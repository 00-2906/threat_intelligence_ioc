"""
Regenerate reference_embeddings.npz using the CURRENT embedding model.

Run this any time you change the embedding model (e.g. switching from
BAAI/bge-large-en-v1.5 to all-MiniLM-L6-v2) — old cached reference
embeddings will have the wrong dimensionality otherwise and every
scan will crash with a matmul dimension mismatch.

Usage (run from the REPO ROOT, not from inside embedding/):
    python -m embedding.regenerate_reference
"""

import os
import logging
from pathlib import Path

from embedding.embedder import IOCEmbedder
from embedding.reference_embeddings import build_seed_reference_csv, build_reference_set

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# This script lives in the embedding/ folder, one level below the repo
# root (the same "ioc-scanner" folder that contains backend/ and
# embedding/). log_scanner.py computes REPO_ROOT as 3 levels up from
# backend/app/services/log_scanner.py, which resolves to that same
# repo root -- so we match it here from the other direction.
REPO_ROOT = Path(__file__).resolve().parent.parent

CSV_PATH = str(REPO_ROOT / "embedding" / "reference_iocs.csv")
OUTPUT_PATH = str(REPO_ROOT / "reference_embeddings.npz")

if __name__ == "__main__":
    # If you already have a real labeled CSV, skip seeding and just
    # make sure CSV_PATH points to it instead.
    if not os.path.exists(CSV_PATH):
        logger.info(f"No CSV found at {CSV_PATH}, writing seed starter set...")
        build_seed_reference_csv(CSV_PATH)
    else:
        logger.info(f"Using existing CSV at {CSV_PATH}")

    logger.info("Loading embedding model (this may take a moment)...")
    embedder = IOCEmbedder()
    embedder.initialize()

    logger.info("Building reference embedding set with current model...")
    build_reference_set(embedder, CSV_PATH, OUTPUT_PATH)

    logger.info(f"Done. New reference embeddings saved to {OUTPUT_PATH}")
    logger.info("Restart your FastAPI server so it picks up the new file.")