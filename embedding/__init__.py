"""
Threat Intelligence IOC Scanner - Embeddings Layer

This module provides pretrained embedding generation for IOC (Indicator of Compromise)
context data using sentence-transformers and BAAI/bge-large-en-v1.5 model.

Core components:
- EmbeddingModel: Main class for loading and managing the pretrained embedding model
- IOCEmbedder: High-level interface for single and batch embedding operations
- EmbeddingCache: Disk-based caching to avoid regenerating embeddings
"""

from .model import EmbeddingModel
from .embedder import IOCEmbedder
from .cache import EmbeddingCache

__all__ = [
    "EmbeddingModel",
    "IOCEmbedder",
    "EmbeddingCache",
]