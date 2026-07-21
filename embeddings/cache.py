"""
Disk-based embedding cache to avoid regenerating embeddings.

Provides simple file-based storage and retrieval of numpy embeddings using
a hash-based key system for efficient lookup.
"""

import os
import hashlib
import numpy as np
import logging
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)


class EmbeddingCache:
    """
    Simple file-based cache for storing and retrieving embeddings.
    
    Features:
    - Hash-based key generation from text content
    - Automatic directory creation
    - Numpy binary storage (.npy format)
    - Batch operations support
    - Cache statistics
    
    Attributes:
        cache_dir (Path): Directory to store cached embeddings
        stats (dict): Cache hit/miss statistics
    
    Example:
        >>> cache = EmbeddingCache("./cache")
        >>> cache.save("suspicious hash md5", embedding_vector)
        >>> retrieved = cache.get("suspicious hash md5")
    """
    
    def __init__(self, cache_dir: str = "./embedding_cache"):
        """
        Initialize EmbeddingCache.
        
        Args:
            cache_dir: Directory path for storing embeddings (created if doesn't exist)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.stats = {
            "hits": 0,
            "misses": 0,
            "saves": 0,
            "deletes": 0,
        }
        logger.info(f"EmbeddingCache initialized at {self.cache_dir}")
    
    def _get_hash_key(self, text: str) -> str:
        """
        Generate unique hash key from text content.
        
        Args:
            text: Input text to hash
        
        Returns:
            str: SHA256 hash (hex format)
        """
        return hashlib.sha256(text.encode()).hexdigest()
    
    def _get_cache_path(self, hash_key: str) -> Path:
        """
        Get file path for cached embedding.
        
        Args:
            hash_key: Hash key from _get_hash_key()
        
        Returns:
            Path: Full path to .npy file
        """
        return self.cache_dir / f"{hash_key}.npy"
    
    def has(self, text: str) -> bool:
        """
        Check if embedding for given text exists in cache.
        
        Args:
            text: Input text to check
        
        Returns:
            bool: True if cached embedding exists
        """
        hash_key = self._get_hash_key(text)
        cache_path = self._get_cache_path(hash_key)
        return cache_path.exists()
    
    def get(self, text: str) -> Optional[np.ndarray]:
        """
        Retrieve embedding from cache.
        
        Args:
            text: Input text to retrieve embedding for
        
        Returns:
            np.ndarray: Cached embedding vector, or None if not found
        """
        hash_key = self._get_hash_key(text)
        cache_path = self._get_cache_path(hash_key)
        
        if not cache_path.exists():
            self.stats["misses"] += 1
            return None
        
        try:
            embedding = np.load(cache_path)
            self.stats["hits"] += 1
            logger.debug(f"Cache hit for text: {text[:50]}...")
            return embedding
        except Exception as e:
            logger.warning(f"Failed to load cached embedding: {str(e)}")
            self.stats["misses"] += 1
            return None
    
    def save(self, text: str, embedding: np.ndarray) -> bool:
        """
        Save embedding to cache.
        
        Args:
            text: Original input text
            embedding: Numpy array of embedding vector
        
        Returns:
            bool: True if save successful
        """
        if not isinstance(embedding, np.ndarray):
            logger.warning(f"Embedding must be numpy array, got {type(embedding)}")
            return False
        
        hash_key = self._get_hash_key(text)
        cache_path = self._get_cache_path(hash_key)
        
        try:
            np.save(cache_path, embedding)
            self.stats["saves"] += 1
            logger.debug(f"Cached embedding for: {text[:50]}...")
            return True
        except Exception as e:
            logger.error(f"Failed to save embedding to cache: {str(e)}")
            return False
    
    def batch_get(self, texts: List[str]) -> tuple:
        """
        Retrieve multiple embeddings from cache.
        
        Args:
            texts: List of text strings to retrieve
        
        Returns:
            tuple: (list of embeddings or None for cache misses, list of cache hit status)
        
        Example:
            >>> embeddings, hit_mask = cache.batch_get(["text1", "text2", "text3"])
            >>> # embeddings[0] is None if cache miss, otherwise numpy array
            >>> # hit_mask[0] is False if cache miss, True if hit
        """
        embeddings = []
        hit_mask = []
        
        for text in texts:
            embedding = self.get(text)
            embeddings.append(embedding)
            hit_mask.append(embedding is not None)
        
        return embeddings, hit_mask
    
    def batch_save(self, texts: List[str], embeddings: List[np.ndarray]) -> int:
        """
        Save multiple embeddings to cache.
        
        Args:
            texts: List of original text strings
            embeddings: List of corresponding embedding vectors
        
        Returns:
            int: Number of successful saves
        """
        if len(texts) != len(embeddings):
            logger.warning(f"Text count ({len(texts)}) != embedding count ({len(embeddings)})")
            return 0
        
        success_count = 0
        for text, embedding in zip(texts, embeddings):
            if self.save(text, embedding):
                success_count += 1
        
        return success_count
    
    def delete(self, text: str) -> bool:
        """
        Delete cached embedding.
        
        Args:
            text: Text whose cached embedding should be deleted
        
        Returns:
            bool: True if deletion successful
        """
        hash_key = self._get_hash_key(text)
        cache_path = self._get_cache_path(hash_key)
        
        if not cache_path.exists():
            return False
        
        try:
            cache_path.unlink()
            self.stats["deletes"] += 1
            logger.debug(f"Deleted cached embedding for: {text[:50]}...")
            return True
        except Exception as e:
            logger.error(f"Failed to delete cached embedding: {str(e)}")
            return False
    
    def clear(self) -> int:
        """
        Clear all cached embeddings.
        
        Returns:
            int: Number of files deleted
        """
        if not self.cache_dir.exists():
            return 0
        
        count = 0
        for cache_file in self.cache_dir.glob("*.npy"):
            try:
                cache_file.unlink()
                count += 1
            except Exception as e:
                logger.warning(f"Failed to delete {cache_file}: {str(e)}")
        
        logger.info(f"Cleared {count} cached embeddings")
        return count
    
    def get_stats(self) -> dict:
        """
        Get cache statistics.
        
        Returns:
            dict: Cache hit/miss/save statistics
        """
        total = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total * 100) if total > 0 else 0
        
        return {
            **self.stats,
            "total_queries": total,
            "hit_rate_percent": hit_rate,
        }
    
    def get_cache_size(self) -> dict:
        """
        Get cache directory size information.
        
        Returns:
            dict: Number of cached files and total size in MB
        """
        if not self.cache_dir.exists():
            return {"num_files": 0, "total_size_mb": 0}
        
        num_files = len(list(self.cache_dir.glob("*.npy")))
        total_size_bytes = sum(f.stat().st_size for f in self.cache_dir.glob("*.npy"))
        total_size_mb = total_size_bytes / (1024 * 1024)
        
        return {
            "num_files": num_files,
            "total_size_bytes": total_size_bytes,
            "total_size_mb": round(total_size_mb, 2),
        }
    
    def __repr__(self) -> str:
        cache_info = self.get_cache_size()
        return (f"EmbeddingCache(dir={self.cache_dir}, "
                f"files={cache_info['num_files']}, "
                f"size_mb={cache_info['total_size_mb']})")
