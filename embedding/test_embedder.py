"""
Test suite for EmbeddingModel and IOCEmbedder.

Covers:
- Model loading (GPU/CPU fallback)
- Single + batch encoding shape/dtype/normalization
- Cache hit/miss correctness
- Batch embedding with mixed cache hits/misses
- Edge cases (empty input, duplicate IOCs, near-duplicate text)
- Semantic sanity check (similar IOC contexts should be closer than unrelated ones)

Run with:
    pytest tests/test_embedder.py -v

Or standalone:
    python tests/test_embedder.py
"""

import shutil
import tempfile
import time
import numpy as np
import pytest

# Adjust this import to match your package layout, e.g.:
#   from ioc_scanner.embeddings.embedder import IOCEmbedder
#   from ioc_scanner.embeddings.model import EmbeddingModel
from embedder import IOCEmbedder
from model import EmbeddingModel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tmp_cache_dir():
    d = tempfile.mkdtemp(prefix="ioc_embed_cache_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def embedder(tmp_cache_dir):
    """One shared, initialized embedder for the whole module (model load is expensive)."""
    e = IOCEmbedder(cache_dir=tmp_cache_dir, use_cache=True)
    e.initialize()
    return e


SAMPLE_IOCS = [
    "MD5 hash 44d88612fea8a8f36de82e1278abb02f associated with EICAR test file",
    "IP address 185.220.101.4 identified as known Tor exit node used in C2 traffic",
    "domain evil-phish-login.com registered 2 days ago, flagged for phishing campaign",
    "URL hxxp://malicious-site[.]com/payload.exe hosting ransomware dropper",
    "IP address 8.8.8.8 is Google public DNS, benign infrastructure",
]


# ---------------------------------------------------------------------------
# Model-level tests
# ---------------------------------------------------------------------------

class TestEmbeddingModel:

    def test_model_not_initialized_raises(self):
        m = EmbeddingModel()
        assert not m.is_initialized()
        with pytest.raises(RuntimeError):
            m.encode("test")

    def test_model_initializes(self):
        m = EmbeddingModel()
        m.initialize()
        assert m.is_initialized()
        assert m.device in ("cuda", "cpu")

    def test_double_initialize_is_safe(self):
        m = EmbeddingModel()
        m.initialize()
        m.initialize()  # should log a warning, not raise
        assert m.is_initialized()

    def test_single_encode_shape_and_dtype(self):
        m = EmbeddingModel()
        m.initialize()
        vec = m.encode("suspicious file hash from malware report")
        assert vec.shape == (1024,)
        assert vec.dtype in (np.float32, np.float64)

    def test_batch_encode_shape(self):
        m = EmbeddingModel()
        m.initialize()
        vecs = m.encode(SAMPLE_IOCS, batch_size=4)
        assert vecs.shape == (len(SAMPLE_IOCS), 1024)

    def test_normalized_embeddings_have_unit_norm(self):
        m = EmbeddingModel()
        m.initialize()
        vec = m.encode("test IOC", normalize_embeddings=True)
        norm = np.linalg.norm(vec)
        assert abs(norm - 1.0) < 1e-3

    def test_empty_input_raises(self):
        m = EmbeddingModel()
        m.initialize()
        with pytest.raises(ValueError):
            m.encode([])


# ---------------------------------------------------------------------------
# Embedder-level tests (caching + batch logic)
# ---------------------------------------------------------------------------

class TestIOCEmbedder:

    def test_single_embed_first_call_is_cache_miss(self, embedder):
        text = f"unique test IOC {time.time()}"  # ensure no cache collision
        result = embedder.embed(text)
        assert result.from_cache is False
        assert result.embedding.shape == (1024,)

    def test_single_embed_second_call_is_cache_hit(self, embedder):
        text = f"repeat test IOC {time.time()}"
        first = embedder.embed(text)
        second = embedder.embed(text)
        assert first.from_cache is False
        assert second.from_cache is True
        np.testing.assert_allclose(first.embedding, second.embedding, atol=1e-6)

    def test_batch_embed_mixed_cache_hits_and_misses(self, embedder):
        unique_texts = [f"batch IOC {i} {time.time()}" for i in range(3)]
        # Prime the cache with the first one
        embedder.embed(unique_texts[0])

        result = embedder.embed_batch(unique_texts)
        assert result.embeddings.shape == (3, 1024)
        assert result.cache_hits == 1
        assert result.cache_misses == 2
        assert result.from_cache[0] is True
        assert result.from_cache[1] is False
        assert result.from_cache[2] is False

    def test_batch_embed_all_fresh(self, embedder):
        texts = [f"fresh batch {i} {time.time()}" for i in range(5)]
        result = embedder.embed_batch(texts)
        assert result.cache_misses == 5
        assert result.cache_hits == 0
        assert result.embeddings.shape == (5, 1024)

    def test_cache_disabled_never_hits(self, tmp_cache_dir):
        e = IOCEmbedder(cache_dir=tmp_cache_dir, use_cache=False)
        e.initialize()
        text = "no cache test IOC"
        first = e.embed(text)
        second = e.embed(text)
        assert first.from_cache is False
        assert second.from_cache is False

    def test_empty_batch_raises(self, embedder):
        with pytest.raises(ValueError):
            embedder.embed_batch([])

    def test_cache_stats_and_size(self, embedder):
        stats = embedder.get_cache_stats()
        size = embedder.get_cache_size()
        assert stats is not None
        assert size is not None

    def test_clear_cache(self, tmp_cache_dir):
        e = IOCEmbedder(cache_dir=tmp_cache_dir, use_cache=True)
        e.initialize()
        e.embed("cache clear test IOC")
        deleted = e.clear_cache()
        assert deleted >= 1
        # after clearing, same text should be a fresh miss
        result = e.embed("cache clear test IOC")
        assert result.from_cache is False


# ---------------------------------------------------------------------------
# Semantic sanity checks — the tests that actually matter for a threat-intel
# embedding pipeline: do "similar" IOC contexts land closer together than
# unrelated ones? This is what your downstream malicious/benign scoring
# will depend on.
# ---------------------------------------------------------------------------

def cosine_sim(a, b):
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


class TestSemanticQuality:

    def test_similar_malicious_contexts_are_closer_than_unrelated(self, embedder):
        malicious_a = embedder.embed("IP 185.220.101.4 used as Tor C2 exit node in APT campaign").embedding
        malicious_b = embedder.embed("IP 185.220.101.9 known Tor node linked to APT C2 infrastructure").embedding
        benign = embedder.embed("IP 8.8.8.8 is Google public DNS resolver, benign").embedding

        sim_malicious_pair = cosine_sim(malicious_a, malicious_b)
        sim_cross = cosine_sim(malicious_a, benign)

        assert sim_malicious_pair > sim_cross, (
            f"Expected malicious-malicious similarity ({sim_malicious_pair:.3f}) "
            f"to exceed malicious-benign similarity ({sim_cross:.3f})"
        )

    def test_identical_text_has_similarity_near_one(self, embedder):
        vec = embedder.embed("identical IOC text for self-similarity check").embedding
        assert cosine_sim(vec, vec) > 0.999


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))