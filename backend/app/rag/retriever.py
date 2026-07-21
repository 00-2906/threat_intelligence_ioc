"""
backend/app/rag/retriever.py

Thin retrieval wrapper around the ChromaDB collection built by
scripts/rag_ingest.py. Import this from your app / step-7 reasoning
module instead of touching ChromaDB or the embedding model directly.

Example:
    from app.rag.retriever import MitreAttackRetriever

    retriever = MitreAttackRetriever()
    matches = retriever.find_similar_techniques(
        "suspicious PowerShell script downloading a payload"
    )
"""

import os

import chromadb
from sentence_transformers import SentenceTransformer

# Same values used by scripts/rag_ingest.py - keep these in sync.
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "chroma_db")
COLLECTION_NAME = "mitre_attack"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


class MitreAttackRetriever:
    """
    Loads the embedding model and ChromaDB collection once, then lets
    the app query it repeatedly without re-loading either.
    """

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        collection_name: str = COLLECTION_NAME,
        model_name: str = EMBEDDING_MODEL,
    ):
        self.db_path = db_path
        self.collection_name = collection_name
        self.model = SentenceTransformer(model_name)

        client = chromadb.PersistentClient(path=db_path)
        try:
            self.collection = client.get_collection(collection_name)
        except Exception as e:
            raise RuntimeError(
                f"Could not find ChromaDB collection '{collection_name}' at "
                f"'{db_path}'. Run scripts/rag_ingest.py first to build it."
            ) from e

    def find_similar_techniques(
        self,
        evidence_text: str,
        n_results: int = 5,
    ) -> list[dict]:
        """
        Given a piece of evidence/event text (e.g. a flagged proctoring
        event, a suspicious log line, an IOC description), return the
        closest matching MITRE ATT&CK techniques.

        Returns a list of dicts:
            {
                "id": "T1055.011",
                "name": "...",
                "tactics": "...",
                "platforms": "...",
                "url": "...",
                "document": "...",   # the full embedded text
                "distance": 0.1234,  # lower = more similar (cosine)
            }
        """
        query_embedding = self.model.encode([evidence_text]).tolist()
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=n_results,
        )

        matches = []
        for doc_id, doc, meta, dist in zip(
            results["ids"][0],
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            matches.append(
                {
                    "id": doc_id,
                    "name": meta.get("name", ""),
                    "tactics": meta.get("tactics", ""),
                    "platforms": meta.get("platforms", ""),
                    "url": meta.get("url", ""),
                    "document": doc,
                    "distance": dist,
                }
            )

        return matches

    def collection_size(self) -> int:
        """Number of techniques currently stored - handy for a health check."""
        return self.collection.count()


# Lazy singleton so the app can just do:
#   from app.rag.retriever import get_retriever
#   retriever = get_retriever()
# without every module re-loading the embedding model.
_retriever_instance: MitreAttackRetriever | None = None


def get_retriever() -> MitreAttackRetriever:
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = MitreAttackRetriever()
    return _retriever_instance