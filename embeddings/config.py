"""
Configuration settings for embeddings layer.

Centralized configuration for model, cache, and inference parameters.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class EmbeddingConfig:
    """
    Configuration dataclass for embedding generation.
    
    Attributes:
        model_name: Hugging Face model identifier
        embedding_dimension: Expected embedding vector dimension
        batch_size: Default batch size for inference
        max_text_length: Maximum allowed input text length
        max_batch_size: Maximum allowed batch size
        use_cache: Whether to enable disk caching
        cache_dir: Directory for embedding cache storage
        device: Compute device ('cuda', 'cpu', or 'auto')
        normalize_embeddings: Whether to L2-normalize embeddings
    """
    
    # Model configuration
    model_name: str = "BAAI/bge-large-en-v1.5"
    embedding_dimension: int = 1024
    
    # Inference configuration
    batch_size: int = 32
    max_text_length: int = 512
    max_batch_size: int = 256
    normalize_embeddings: bool = True
    
    # Caching configuration
    use_cache: bool = True
    cache_dir: str = "./embedding_cache"
    
    # Device configuration
    device: str = "auto"  # 'auto', 'cuda', 'cpu'


# Default configuration instance
DEFAULT_CONFIG = EmbeddingConfig()


def get_default_config() -> EmbeddingConfig:
    """
    Get default configuration.
    
    Returns:
        EmbeddingConfig: Default configuration instance
    """
    return DEFAULT_CONFIG


def create_config(
    model_name: Optional[str] = None,
    batch_size: Optional[int] = None,
    use_cache: bool = True,
    cache_dir: Optional[str] = None,
    **kwargs
) -> EmbeddingConfig:
    """
    Create custom configuration.
    
    Args:
        model_name: Optional model identifier
        batch_size: Optional batch size override
        use_cache: Whether to enable caching
        cache_dir: Optional cache directory
        **kwargs: Additional config overrides
    
    Returns:
        EmbeddingConfig: Custom configuration instance
    
    Example:
        >>> config = create_config(batch_size=64, use_cache=False)
    """
    config_dict = {
        "model_name": model_name or DEFAULT_CONFIG.model_name,
        "batch_size": batch_size or DEFAULT_CONFIG.batch_size,
        "use_cache": use_cache,
        "cache_dir": cache_dir or DEFAULT_CONFIG.cache_dir,
    }
    config_dict.update(kwargs)
    return EmbeddingConfig(**config_dict)
