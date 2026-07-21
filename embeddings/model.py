"""
Pretrained Embedding Model wrapper using sentence-transformers.

Handles loading, initialization, and management of BAAI/bge-large-en-v1.5 model
with automatic GPU detection and graceful CPU fallback.
"""

import torch
import logging
from typing import Optional
from sentence_transformers import SentenceTransformer

from .utils import detect_device, get_model_info

logger = logging.getLogger(__name__)


class EmbeddingModel:
    """
    Wrapper for pretrained sentence embedding model (BAAI/bge-large-en-v1.5).
    
    Features:
    - Automatic GPU detection with CPU fallback
    - Lazy loading (model loaded on first use)
    - Memory-efficient batch processing
    - Model caching via sentence-transformers
    
    Attributes:
        model_name (str): Hugging Face model identifier
        model (SentenceTransformer): Loaded model instance (None until initialized)
        device (str): Compute device ('cuda' or 'cpu')
        is_gpu (bool): Whether GPU is being used
        embedding_dimension (int): Dimensionality of generated embeddings (1024)
    
    Example:
        >>> model = EmbeddingModel()
        >>> model.initialize()  # Load model to device
        >>> embedding = model.encode("suspicious file hash from malware report")
        >>> print(embedding.shape)  # (1024,)
    """
    
    # Model constants
    MODEL_NAME = "BAAI/bge-large-en-v1.5"
    EMBEDDING_DIMENSION = 1024
    
    def __init__(self, model_name: Optional[str] = None):
        """
        Initialize EmbeddingModel.
        
        Args:
            model_name: Optional custom model name. Defaults to BAAI/bge-large-en-v1.5
        """
        self.model_name = model_name or self.MODEL_NAME
        self.model: Optional[SentenceTransformer] = None
        self.device, self.is_gpu = detect_device()
        self.embedding_dimension = self.EMBEDDING_DIMENSION
        
        logger.info(f"EmbeddingModel initialized (not loaded yet)")
        logger.info(f"Model: {self.model_name}")
        logger.info(f"Target device: {self.device}")
    
    def initialize(self) -> None:
        """
        Load the pretrained model to the target device.
        
        Loads model from Hugging Face (cached locally if already downloaded).
        Should be called once before encoding operations.
        
        Raises:
            RuntimeError: If model loading fails
        """
        if self.model is not None:
            logger.warning("Model already initialized, skipping re-load")
            return
        
        try:
            logger.info(f"Loading model {self.model_name} to {self.device}...")
            self.model = SentenceTransformer(self.model_name, device=self.device)
            logger.info(f"Model loaded successfully. Embedding dimension: {self.embedding_dimension}")
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            raise RuntimeError(f"Model initialization failed: {str(e)}")
    
    def encode(self, texts, batch_size: int = 32, normalize_embeddings: bool = True):
        """
        Encode text(s) into embeddings.
        
        Args:
            texts: Single string or list of strings
            batch_size: Number of texts to process at once (memory-speed tradeoff)
            normalize_embeddings: Whether to L2-normalize embeddings (recommended for similarity)
        
        Returns:
            numpy.ndarray: Single embedding (shape: (1024,)) or batch (shape: (N, 1024))
        
        Raises:
            RuntimeError: If model not initialized
            ValueError: If texts are empty or invalid
        """
        if self.model is None:
            raise RuntimeError("Model not initialized. Call initialize() first.")
        
        # Handle single string input
        is_single = isinstance(texts, str)
        if is_single:
            texts = [texts]
        
        if not texts or len(texts) == 0:
            raise ValueError("Input texts cannot be empty")
        
        # Encode with batch processing
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            normalize_embeddings=normalize_embeddings,
            show_progress_bar=False,
        )
        
        # Return single embedding if input was single string
        if is_single:
            return embeddings[0]
        
        return embeddings
    
    def get_info(self) -> dict:
        """
        Get model and system configuration info.
        
        Returns:
            dict: Model metadata and system information
        """
        return get_model_info()
    
    def is_initialized(self) -> bool:
        """
        Check if model has been loaded.
        
        Returns:
            bool: True if model is loaded and ready
        """
        return self.model is not None
    
    def __repr__(self) -> str:
        status = "initialized" if self.is_initialized() else "not initialized"
        return f"EmbeddingModel(model={self.model_name}, device={self.device}, status={status})"
