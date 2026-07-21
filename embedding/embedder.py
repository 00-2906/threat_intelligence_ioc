"""
High-level IOC embedder interface combining model and cache.

Provides user-friendly API for single and batch embedding operations
with automatic caching and cache-aware generation.
"""

import logging
import numpy as np
from typing import List, Optional, Union, Tuple
from dataclasses import dataclass

from .model import EmbeddingModel
from .cache import EmbeddingCache
from .utils import validate_text_input, validate_batch_input, normalize_text

logger = logging.getLogger(__name__)


@dataclass
class EmbeddingResult:
    """
    Result of embedding operation.
    
    Attributes:
        embedding (np.ndarray): Generated embedding vector
        text (str): Original input text
        from_cache (bool): Whether embedding was retrieved from cache
    """
    embedding: np.ndarray
    text: str
    from_cache: bool


@dataclass
class BatchEmbeddingResult:
    """
    Result of batch embedding operation.
    
    Attributes:
        embeddings (np.ndarray): Array of embedding vectors (shape: N x 1024)
        texts (List[str]): Original input texts
        from_cache (List[bool]): Cache status for each embedding
        cache_hits (int): Number of embeddings retrieved from cache
        cache_misses (int): Number of embeddings generated fresh
    """
    embeddings: np.ndarray
    texts: List[str]
    from_cache: List[bool]
    cache_hits: int
    cache_misses: int


class IOCEmbedder:
    """
    High-level interface for IOC embedding generation and caching.
    
    Combines EmbeddingModel (generation) and EmbeddingCache (storage) to provide
    an efficient, cache-aware embedding API optimized for IOC threat intelligence data.
    
    Features:
    - Single and batch embedding
    - Automatic cache-aware generation (avoid regenerating)
    - Caching of generated embeddings
    - Detailed operation results with cache status
    - Memory-efficient batch processing
    
    Attributes:
        model (EmbeddingModel): Pretrained embedding model
        cache (EmbeddingCache): Embedding cache storage
        
    Example:
        >>> embedder = IOCEmbedder()
        >>> embedder.initialize()
        >>> 
        >>> # Single embedding with caching
        >>> result = embedder.embed("malicious IP 192.168.1.1 from APT report")
        >>> print(result.embedding.shape)  # (1024,)
        >>> print(result.from_cache)       # False (first time)
        >>> 
        >>> # Batch embedding (mixed cache hits/misses)
        >>> results = embedder.embed_batch([
        ...     "file hash md5 abc123 high reputation",
        ...     "domain example.com blacklisted",
        ...     "suspicious URL with phishing indicators"
        ... ])
        >>> print(f"Cache hits: {results.cache_hits}/{len(results.texts)}")
    """
    
    def __init__(
        self,
        model_name: Optional[str] = None,
        cache_dir: str = "./embedding_cache",
        use_cache: bool = True,
    ):
        """
        Initialize IOCEmbedder.
        
        Args:
            model_name: Optional custom embedding model name
            cache_dir: Directory for embedding cache storage
            use_cache: Whether to enable caching (default: True)
        """
        self.model = EmbeddingModel(model_name)
        self.cache = EmbeddingCache(cache_dir) if use_cache else None
        self.use_cache = use_cache
        
        logger.info(f"IOCEmbedder initialized (model not loaded yet)")
        logger.info(f"Caching: {'enabled' if use_cache else 'disabled'}")
    
    def initialize(self) -> None:
        """
        Load embedding model to device.
        
        Must be called before embed operations.
        """
        self.model.initialize()
        logger.info("IOCEmbedder ready for embedding operations")
    
    def embed(self, text: str, normalize: bool = True) -> EmbeddingResult:
        """
        Generate embedding for single IOC context text.
        
        Args:
            text: IOC context description (e.g., "MD5 hash abc123 from malware sample")
            normalize: Whether to L2-normalize embedding
        
        Returns:
            EmbeddingResult: Embedding vector, original text, and cache status
        
        Raises:
            ValueError: If text validation fails
            RuntimeError: If model not initialized or embedding fails
        
        Example:
            >>> result = embedder.embed("suspicious file hash from OSINT")
            >>> print(f"From cache: {result.from_cache}")
            >>> print(f"Embedding shape: {result.embedding.shape}")
        """
        # Validate input
        validate_text_input(text)
        normalized_text = normalize_text(text)
        
        # Try cache first
        if self.use_cache and self.cache is not None:
            cached_embedding = self.cache.get(normalized_text)
            if cached_embedding is not None:
                logger.debug(f"Cache hit: {text[:60]}...")
                return EmbeddingResult(
                    embedding=cached_embedding,
                    text=text,
                    from_cache=True,
                )
        
        # Generate embedding
        embedding = self.model.encode(text, normalize_embeddings=normalize)
        
        # Save to cache
        if self.use_cache and self.cache is not None:
            self.cache.save(normalized_text, embedding)
        
        return EmbeddingResult(
            embedding=embedding,
            text=text,
            from_cache=False,
        )
    
    def embed_batch(
        self,
        texts: List[str],
        batch_size: int = 32,
        normalize: bool = True,
    ) -> BatchEmbeddingResult:
        """
        Generate embeddings for multiple IOC context texts efficiently.
        
        Uses cache for previously computed embeddings and generates only missing ones.
        This significantly speeds up operations on repeated or similar IOC data.
        
        Args:
            texts: List of IOC context descriptions
            batch_size: Number of texts to encode at once (memory-speed tradeoff)
            normalize: Whether to L2-normalize embeddings
        
        Returns:
            BatchEmbeddingResult: Embeddings array, cache status, and statistics
        
        Raises:
            ValueError: If batch validation fails
            RuntimeError: If embedding fails
        
        Example:
            >>> iocs = [
            ...     "MD5 hash xyz789 from ransomware",
            ...     "IP 192.168.1.100 C2 server",
            ...     "domain evil.com phishing campaign"
            ... ]
            >>> result = embedder.embed_batch(iocs)
            >>> print(f"Shape: {result.embeddings.shape}")  # (3, 1024)
            >>> print(f"Cache hits: {result.cache_hits}")
        """
        # Validate batch
        validate_batch_input(texts)
        
        embeddings_list = []
        cache_status = []
        texts_to_encode = []
        encode_indices = []  # Track which positions need encoding
        
        # Check cache and identify what needs encoding
        cache_hits = 0
        for i, text in enumerate(texts):
            normalized_text = normalize_text(text)
            
            if self.use_cache and self.cache is not None:
                cached_embedding = self.cache.get(normalized_text)
                if cached_embedding is not None:
                    embeddings_list.append(cached_embedding)
                    cache_status.append(True)
                    cache_hits += 1
                    continue
            
            # Cache miss - need to encode this text
            embeddings_list.append(None)  # Placeholder
            cache_status.append(False)
            texts_to_encode.append(text)
            encode_indices.append(i)
        
        cache_misses = len(texts_to_encode)
        
        # Encode cache misses in batches
        if texts_to_encode:
            logger.info(f"Encoding {cache_misses}/{len(texts)} texts (cache hits: {cache_hits})")
            batch_embeddings = self.model.encode(
                texts_to_encode,
                batch_size=batch_size,
                normalize_embeddings=normalize,
            )
            
            # Fill in placeholders with generated embeddings
            for i, idx in enumerate(encode_indices):
                embeddings_list[idx] = batch_embeddings[i]
                
                # Save to cache
                if self.use_cache and self.cache is not None:
                    normalized_text = normalize_text(texts[idx])
                    self.cache.save(normalized_text, batch_embeddings[i])
        
        # Stack embeddings into single array
        embeddings_array = np.vstack(embeddings_list)
        
        logger.info(f"Batch embedding complete: {cache_hits} cache hits, {cache_misses} generated")
        
        return BatchEmbeddingResult(
            embeddings=embeddings_array,
            texts=texts,
            from_cache=cache_status,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
        )
    
    def get_cache_stats(self) -> dict:
        """
        Get embedding cache statistics.
        
        Returns:
            dict: Cache hit/miss rates and size info, or None if caching disabled
        """
        if self.cache is None:
            return None
        return self.cache.get_stats()
    
    def get_cache_size(self) -> dict:
        """
        Get cache directory size information.
        
        Returns:
            dict: Number of cached files and total size
        """
        if self.cache is None:
            return None
        return self.cache.get_cache_size()
    
    def clear_cache(self) -> int:
        """
        Clear all cached embeddings.
        
        Returns:
            int: Number of files deleted, or 0 if caching disabled
        """
        if self.cache is None:
            return 0
        return self.cache.clear()
    
    def get_info(self) -> dict:
        """
        Get embedder configuration and system info.
        
        Returns:
            dict: Model info, caching status, and device info
        """
        info = {
            "model_info": self.model.get_info(),
            "caching_enabled": self.use_cache,
        }
        if self.use_cache and self.cache is not None:
            info["cache_stats"] = self.get_cache_stats()
            info["cache_size"] = self.get_cache_size()
        return info
    
    def __repr__(self) -> str:
        cache_str = f" (cache: {self.cache})" if self.use_cache else " (no cache)"
        return f"IOCEmbedder({self.model}{cache_str})"