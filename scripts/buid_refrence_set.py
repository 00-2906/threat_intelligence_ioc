"""
One-time setup script: builds the labeled reference embedding set used by
the kNN scorer. Run this once (and again whenever you update the labeled
reference CSV) before the log scanner or API endpoint will work.

Run from the repository root:
    python scripts/buid_refrence_set.py
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))  # make `embedding` importable from repository root

from embedding.embedder import IOCEmbedder
from embedding.reference_embeddings import build_seed_reference_csv, build_reference_set

CSV_PATH = REPO_ROOT / "reference_iocs.csv"
OUTPUT_PATH = REPO_ROOT / "reference_embeddings.npz"

if __name__ == "__main__":
    if not os.path.exists(CSV_PATH):
        print(f"No {CSV_PATH} found — writing a starter seed set. Replace/expand this with real labeled data.")
        build_seed_reference_csv(CSV_PATH)

    embedder = IOCEmbedder(cache_dir=os.path.join(REPO_ROOT, "embedding_cache"), use_cache=True)
    embedder.initialize()

    build_reference_set(embedder, CSV_PATH, OUTPUT_PATH)
    print(f"Done. Reference set saved to {OUTPUT_PATH}")