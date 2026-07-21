"""
Step 6: RAG Layer - ChromaDB + MITRE ATT&CK

Downloads the public MITRE ATT&CK Enterprise dataset (STIX bundle from the
official mitre/cti GitHub repo), extracts each technique's name, ID,
description, tactics and platforms, embeds the text with a
sentence-transformers model, and stores everything in a persistent
ChromaDB collection so it can be queried later by your local LLM
reasoning step (step 7).

Usage:
    python rag_ingest.py                 # build the DB (first run / refresh)
    python rag_ingest.py --query "..."   # quick test query after building
"""

import argparse
import json
import os
import urllib.request

import chromadb
from sentence_transformers import SentenceTransformer

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# This script lives in scripts/, but the ChromaDB store it builds must
# match the path backend/app/rag/retriever.py expects, so we point at
# backend/app/rag/chroma_db regardless of where this script is run from.
CHROMA_DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "backend", "app", "rag", "chroma_db"
)
COLLECTION_NAME = "mitre_attack"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # small, fast, 384-dim, good default


def fetch_mitre_attack_bundle(url: str = MITRE_ATTACK_URL) -> dict:
    """Download the raw STIX 2.1 bundle for MITRE ATT&CK Enterprise."""
    print(f"Downloading MITRE ATT&CK data from {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        bundle = json.loads(resp.read())
    print(f"Downloaded {len(bundle.get('objects', []))} STIX objects.")
    return bundle


def extract_techniques(bundle: dict) -> list[dict]:
    """
    Pull out only the 'attack-pattern' objects (these are the actual
    techniques/sub-techniques), skipping revoked/deprecated entries.
    Returns a clean list of dicts ready for embedding.
    """
    techniques = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # The human-readable technique ID (e.g. T1055.011) lives inside
        # external_references, tagged with source_name == "mitre-attack"
        technique_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break

        if not technique_id:
            continue  # skip anything without an official ATT&CK ID

        name = obj.get("name", "")
        description = obj.get("description", "")

        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        platforms = obj.get("x_mitre_platforms", [])

        techniques.append(
            {
                "id": technique_id,
                "name": name,
                "description": description,
                "tactics": tactics,
                "platforms": platforms,
                "url": url or "",
            }
        )

    print(f"Extracted {len(techniques)} usable techniques.")
    return techniques


def build_document_text(t: dict) -> str:
    """
    Combine the fields into one text blob for embedding. This is the
    string the model actually turns into a vector, so keep it
    information-dense but readable.
    """
    tactics_str = ", ".join(t["tactics"]) if t["tactics"] else "unknown"
    platforms_str = ", ".join(t["platforms"]) if t["platforms"] else "unknown"
    return (
        f"Technique {t['id']}: {t['name']}. "
        f"Tactics: {tactics_str}. Platforms: {platforms_str}. "
        f"{t['description']}"
    )


def build_chroma_collection(
    techniques: list[dict],
    db_path: str = CHROMA_DB_PATH,
    collection_name: str = COLLECTION_NAME,
    model_name: str = EMBEDDING_MODEL,
    batch_size: int = 64,
):
    """
    Embed every technique and upsert it into a persistent ChromaDB
    collection. Safe to re-run: existing IDs get overwritten (upsert),
    so refreshing the MITRE data won't create duplicates.
    """
    print(f"Loading embedding model '{model_name}' ...")
    model = SentenceTransformer(model_name)

    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_or_create_collection(
        name=collection_name,
        metadata={"hnsw:space": "cosine"},
    )

    ids, documents, metadatas = [], [], []
    for t in techniques:
        ids.append(t["id"])
        documents.append(build_document_text(t))
        metadatas.append(
            {
                "name": t["name"],
                "tactics": ", ".join(t["tactics"]),
                "platforms": ", ".join(t["platforms"]),
                "url": t["url"],
            }
        )

    print(f"Embedding and upserting {len(ids)} techniques "
          f"in batches of {batch_size} ...")
    for start in range(0, len(ids), batch_size):
        end = start + batch_size
        batch_docs = documents[start:end]
        batch_embeddings = model.encode(
            batch_docs, show_progress_bar=False
        ).tolist()

        collection.upsert(
            ids=ids[start:end],
            documents=batch_docs,
            embeddings=batch_embeddings,
            metadatas=metadatas[start:end],
        )
        print(f"  upserted {end if end < len(ids) else len(ids)}/{len(ids)}")

    print(f"Done. Collection '{collection_name}' now has "
          f"{collection.count()} entries at '{db_path}'.")
    return collection


def query_collection(
    query_text: str,
    n_results: int = 5,
    db_path: str = CHROMA_DB_PATH,
    collection_name: str = COLLECTION_NAME,
    model_name: str = EMBEDDING_MODEL,
):
    """
    Example of how step 7 (Local AI reasoning) will pull similar RAG
    cases: embed the incoming evidence/event text and ask ChromaDB for
    the closest MITRE ATT&CK techniques.
    """
    model = SentenceTransformer(model_name)
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_collection(collection_name)

    query_embedding = model.encode([query_text]).tolist()
    results = collection.query(
        query_embeddings=query_embedding,
        n_results=n_results,
    )

    for i, (doc_id, doc, meta, dist) in enumerate(
        zip(
            results["ids"][0],
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        )
    ):
        print(f"\n#{i + 1} [{doc_id}] {meta['name']}  (distance={dist:.4f})")
        print(f"    tactics: {meta['tactics']}")
        print(f"    {doc[:200]}...")

    return results


def main():
    parser = argparse.ArgumentParser(description="MITRE ATT&CK RAG ingestion")
    parser.add_argument(
        "--query",
        type=str,
        default=None,
        help="Skip ingestion and just run a test similarity query.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Re-download MITRE data and rebuild the collection.",
    )
    args = parser.parse_args()

    if args.query:
        query_collection(args.query)
        return

    bundle = fetch_mitre_attack_bundle()
    techniques = extract_techniques(bundle)
    build_chroma_collection(techniques)

    # quick sanity check right after building
    print("\n--- sanity check query ---")
    query_collection("suspicious PowerShell script downloading a payload")


if __name__ == "__main__":
    main()