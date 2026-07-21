"""
Reference embedding store for malicious/benign IOC contexts, with kNN
cosine-similarity scoring.

Workflow:
1. Curate a labeled CSV of IOC context strings (see build_seed_reference_csv()
   for a starter set — replace/expand with real threat intel data, e.g. from
   MalwareBazaar, AbuseIPDB, URLhaus, or your own labeled samples).
2. build_reference_set() embeds every row once and caches the resulting
   matrix + labels + source texts to disk (.npz), so you don't re-embed on
   every run.
3. score_against_reference() embeds a new IOC context and returns a
   malicious probability plus its top-k nearest labeled neighbors, which
   doubles as the evidence your LLM explanation layer can cite.
"""

import csv
import logging
import os
from dataclasses import dataclass
from typing import List, Tuple

import numpy as np

from .embedder import IOCEmbedder

logger = logging.getLogger(__name__)


@dataclass
class Neighbor:
    text: str
    label: str  # "malicious" | "benign"
    similarity: float


@dataclass
class ScoreResult:
    malicious_score: float       # 0.0-1.0, weighted fraction of malicious neighbors
    verdict: str                  # "malicious" | "benign" | "suspicious"
    neighbors: List[Neighbor]     # top-k, for explainability


def build_seed_reference_csv(path: str) -> None:
    """
    Write a small starter labeled reference set to `path`.

    This is intentionally small and illustrative — for real use, replace
    with a curated set of a few hundred+ real malicious/benign IOC contexts
    pulled from threat intel feeds and your own historical logs.
    """
    rows = [
        # value, ioc_type, context_text, label
        ("185.220.101.4", "ip", "IP address 185.220.101.4 identified as Tor exit node used in C2 traffic", "malicious"),
        ("45.155.205.233", "ip", "IP address 45.155.205.233 flagged as active Cobalt Strike C2 server", "malicious"),
        ("evil-phish-login.com", "domain", "domain evil-phish-login.com registered 2 days ago, used in phishing campaign targeting bank logins", "malicious"),
        ("secure-paypa1-verify.net", "domain", "domain secure-paypa1-verify.net typosquatting PayPal, hosting credential harvesting page", "malicious"),
        ("http://185.220.101.4/payload.exe", "url", "URL http://185.220.101.4/payload.exe hosting ransomware dropper payload", "malicious"),
        ("44d88612fea8a8f36de82e1278abb02f", "md5", "MD5 hash 44d88612fea8a8f36de82e1278abb02f matches known EICAR/malware test signature", "malicious"),
        ("e99a18c428cb38d5f260853678922e03", "md5", "MD5 hash e99a18c428cb38d5f260853678922e03 associated with trojan dropper sample", "malicious"),
        ("8.8.8.8", "ip", "IP address 8.8.8.8 is Google public DNS resolver, benign well-known infrastructure", "benign"),
        ("1.1.1.1", "ip", "IP address 1.1.1.1 is Cloudflare public DNS resolver, benign infrastructure", "benign"),
        ("google.com", "domain", "domain google.com long-standing legitimate domain, benign", "benign"),
        ("github.com", "domain", "domain github.com legitimate code hosting platform, benign", "benign"),
        ("https://github.com/anthropics/claude", "url", "URL https://github.com/anthropics/claude legitimate public repository, benign", "benign"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5", "MD5 hash d41d8cd98f00b204e9800998ecf8427e is the hash of an empty file, benign", "benign"),
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["value", "ioc_type", "context_text", "label"])
        writer.writerows(rows)
    logger.info(f"Wrote seed reference CSV ({len(rows)} rows) to {path}")


def build_reference_set(
    embedder: IOCEmbedder,
    csv_path: str,
    output_path: str = "./reference_embeddings.npz",
) -> None:
    """
    Embed every row in `csv_path` (columns: value, ioc_type, context_text, label)
    and save the resulting embedding matrix + labels + texts to `output_path`.
    """
    contexts, labels = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            contexts.append(row["context_text"])
            labels.append(row["label"].strip().lower())

    if not contexts:
        raise ValueError(f"No rows found in {csv_path}")

    result = embedder.embed_batch(contexts)
    np.savez_compressed(
        output_path,
        embeddings=result.embeddings,
        labels=np.array(labels),
        texts=np.array(contexts, dtype=object),
    )
    logger.info(f"Saved reference set ({len(contexts)} entries) to {output_path}")


def load_reference_set(path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Reference embedding set not found at {path}. "
            f"Run build_reference_set() first."
        )
    data = np.load(path, allow_pickle=True)
    return data["embeddings"], data["labels"], data["texts"]


def score_against_reference(
    query_embedding: np.ndarray,
    ref_embeddings: np.ndarray,
    ref_labels: np.ndarray,
    ref_texts: np.ndarray,
    k: int = 5,
    malicious_threshold: float = 0.6,
    suspicious_threshold: float = 0.35,
) -> ScoreResult:
    """
    Score a single query embedding against the reference set using cosine
    similarity kNN.

    malicious_score is the similarity-weighted fraction of the top-k
    neighbors labeled "malicious" (not a plain majority vote — closer
    neighbors count more).
    """
    # Reference embeddings are assumed L2-normalized (normalize=True at embed time),
    # so cosine similarity reduces to a dot product.
    query_norm = query_embedding / (np.linalg.norm(query_embedding) + 1e-12)
    sims = ref_embeddings @ query_norm  # shape (N,)

    top_k_idx = np.argsort(-sims)[:k]
    neighbors = [
        Neighbor(text=str(ref_texts[i]), label=str(ref_labels[i]), similarity=float(sims[i]))
        for i in top_k_idx
    ]

    weight_sum = sum(n.similarity for n in neighbors) or 1e-12
    malicious_weight = sum(n.similarity for n in neighbors if n.label == "malicious")
    malicious_score = malicious_weight / weight_sum

    if malicious_score >= malicious_threshold:
        verdict = "malicious"
    elif malicious_score >= suspicious_threshold:
        verdict = "suspicious"
    else:
        verdict = "benign"

    return ScoreResult(malicious_score=malicious_score, verdict=verdict, neighbors=neighbors)