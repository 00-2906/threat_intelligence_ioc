"""
Pretrained Embedding Model wrapper using sentence-transformers.

Handles loading, initialization, and management of the
sentence-transformers/all-MiniLM-L6-v2 model with automatic GPU detection
and graceful CPU fallback.
"""

import importlib
import torch
import logging
from typing import Optional, TYPE_CHECKING

# Use TYPE_CHECKING to help linters/static analyzers while avoiding import
# errors at runtime in environments where sentence-transformers is not
# installed. At runtime, if sentence-transformers is missing and the class
# is actually needed, a clear error will be raised when attempting to
# initialize the model.
if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer  # pragma: no cover - type checking only
else:
    try:
        SentenceTransformer = importlib.import_module("sentence_transformers").SentenceTransformer
    except Exception:  # pragma: no cover - import may not be available in some dev environments
        class SentenceTransformer:  # type: ignore
            def __init__(self, *args, **kwargs):
                raise RuntimeError(
                    "sentence-transformers is required. Install via: pip install sentence-transformers"
                )

from .utils import detect_device, get_model_info

logger = logging.getLogger(__name__)


class EmbeddingModel:
    """
    Wrapper for pretrained sentence embedding model (all-MiniLM-L6-v2).

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
        embedding_dimension (int): Dimensionality of generated embeddings (384)

    Example:
        >>> model = EmbeddingModel()
        >>> model.initialize()  # Load model to device
        >>> embedding = model.encode("suspicious file hash from malware report")
        >>> print(embedding.shape)  # (384,)
    """

    # Model constants
    # Primary model - faster, small, and reliable to download
    MODEL_NAME = "all-MiniLM-L6-v2"
    EMBEDDING_DIMENSION = 384
    # Fallback model if primary fails (same model, fully-qualified HF repo id)
    FALLBACK_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
    FALLBACK_DIMENSION = 384

    def __init__(self, model_name: Optional[str] = None):
        """
        Initialize EmbeddingModel.

        Args:
            model_name: Optional custom model name. Defaults to all-MiniLM-L6-v2
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
        Load the pretrained model to the target device with retry logic and fallback.

        Loads model from Hugging Face (cached locally if already downloaded).
        Should be called once before encoding operations.

        Raises:
            RuntimeError: If model loading fails
        """
        if self.model is not None:
            logger.warning("Model already initialized, skipping re-load")
            return

        models_to_try = [
            (self.model_name, self.EMBEDDING_DIMENSION),
            (self.FALLBACK_MODEL, self.FALLBACK_DIMENSION),
        ]

        for model_name, embedding_dim in models_to_try:
            try:
                logger.info(f"Loading model {model_name} to {self.device}...")
                self.model = SentenceTransformer(
                    model_name,
                    device=self.device,
                    trust_remote_code=True
                )
                self.embedding_dimension = embedding_dim
                logger.info(f"Model {model_name} loaded successfully. Embedding dimension: {embedding_dim}")
                return
            except Exception as e:
                logger.warning(f"Failed to load model {model_name}: {str(e)}")
                self.model = None
                continue

        # If we get here, all models failed
        raise RuntimeError(
            f"Failed to load any embedding model. Tried: {[m[0] for m in models_to_try]}. "
            f"Check your internet connection or Hugging Face availability."
        )

    def encode(self, texts, batch_size: int = 32, normalize_embeddings: bool = True):
        """
        Encode text(s) into embeddings.

        Args:
            texts: Single string or list of strings
            batch_size: Number of texts to process at once (memory-speed tradeoff)
            normalize_embeddings: Whether to L2-normalize embeddings (recommended for similarity)

        Returns:
            numpy.ndarray: Single embedding (shape: (384,)) or batch (shape: (N, 384))

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