"""
Utility functions for embeddings layer.

Includes GPU detection, device management, and common validation checks.
"""

import torch
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


def detect_device() -> Tuple[str, bool]:
    """
    Detect available compute device (GPU or CPU) with automatic fallback.
    
    Returns:
        Tuple of (device_name, is_gpu_available)
        - device_name: 'cuda' if GPU available, 'cpu' otherwise
        - is_gpu_available: Boolean indicating GPU availability
    
    Example:
        >>> device, has_gpu = detect_device()
        >>> print(f"Using {device}, GPU available: {has_gpu}")
    """
    if torch.cuda.is_available():
        device = "cuda"
        gpu_name = torch.cuda.get_device_name(0)
        logger.info(f"GPU detected: {gpu_name}")
        logger.info(f"CUDA version: {torch.version.cuda}")
        return device, True
    else:
        logger.info("GPU not available. Falling back to CPU.")
        return "cpu", False


def get_device() -> str:
    """
    Get the current device for PyTorch operations.
    
    Returns:
        str: 'cuda' or 'cpu'
    """
    device, _ = detect_device()
    return device


def validate_text_input(text: str, min_length: int = 1, max_length: int = 512) -> bool:
    """
    Validate IOC context text input.
    
    Args:
        text: Input text to validate
        min_length: Minimum required text length
        max_length: Maximum allowed text length
    
    Returns:
        bool: True if valid, False otherwise
    
    Raises:
        ValueError: If validation fails
    """
    if not isinstance(text, str):
        raise ValueError(f"Input must be string, got {type(text)}")
    
    text = text.strip()
    
    if len(text) < min_length:
        raise ValueError(f"Text too short. Minimum {min_length} characters required, got {len(text)}")
    
    if len(text) > max_length:
        raise ValueError(f"Text too long. Maximum {max_length} characters allowed, got {len(text)}")
    
    return True


def validate_batch_input(texts: list, max_batch_size: int = 256) -> bool:
    """
    Validate batch input of IOC context texts.
    
    Args:
        texts: List of text strings
        max_batch_size: Maximum allowed batch size
    
    Returns:
        bool: True if valid, False otherwise
    
    Raises:
        ValueError: If validation fails
    """
    if not isinstance(texts, list):
        raise ValueError(f"Batch must be list, got {type(texts)}")
    
    if len(texts) == 0:
        raise ValueError("Batch cannot be empty")
    
    if len(texts) > max_batch_size:
        raise ValueError(f"Batch too large. Maximum {max_batch_size} items, got {len(texts)}")
    
    # Validate each item
    for i, text in enumerate(texts):
        try:
            validate_text_input(text)
        except ValueError as e:
            raise ValueError(f"Item {i} validation failed: {str(e)}")
    
    return True


def normalize_text(text: str) -> str:
    """
    Normalize input text for consistent embedding generation.
    
    Args:
        text: Raw input text
    
    Returns:
        str: Normalized text (lowercase, stripped whitespace)
    """
    return text.strip().lower()


def get_model_info() -> dict:
    """
    Get information about the embedding model and system configuration.
    
    Returns:
        dict: Configuration and system info
    """
    device, has_gpu = detect_device()
    
    info = {
        "model_name": "BAAI/bge-large-en-v1.5",
        "model_dimension": 1024,
        "device": device,
        "gpu_available": has_gpu,
        "torch_version": torch.__version__,
        "cuda_available": torch.cuda.is_available(),
    }
    
    if has_gpu:
        info["cuda_version"] = torch.version.cuda
        info["gpu_name"] = torch.cuda.get_device_name(0)
        info["gpu_memory_mb"] = torch.cuda.get_device_properties(0).total_memory / 1024 / 1024
    
    return info