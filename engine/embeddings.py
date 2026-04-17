"""Semantic embedding engine for DataComponent similarity matching.

Uses sentence-transformers to encode DC descriptions/channels and log
messages into dense vectors, then computes cosine similarity to identify
which DataComponents are semantically relevant to an incoming log event.

The model is loaded lazily on first use and DC embeddings are pre-computed
at startup to avoid redundant inference.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Sequence

import numpy as np

LOG = logging.getLogger("ics-detector.embeddings")

try:
    from sentence_transformers import SentenceTransformer
    _HAS_ST = True
except ImportError:
    SentenceTransformer = None  # type: ignore[assignment, misc]
    _HAS_ST = False


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two 1-D vectors."""
    dot = float(np.dot(a, b))
    norm_a = float(np.linalg.norm(a))
    norm_b = float(np.linalg.norm(b))
    if norm_a < 1e-9 or norm_b < 1e-9:
        return 0.0
    return dot / (norm_a * norm_b)


class EmbeddingEngine:
    """Manages a sentence-transformer model and DC embedding cache."""

    def __init__(
        self,
        model_name: str = "BAAI/bge-small-en-v1.5",
        device: str = "cpu",
        *,
        enabled: bool = True,
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._enabled = enabled and _HAS_ST
        self._model: Optional[SentenceTransformer] = None
        self._dc_embeddings: Dict[str, np.ndarray] = {}
        self._dc_texts: Dict[str, str] = {}

        if enabled and not _HAS_ST:
            LOG.warning(
                "sentence-transformers not installed. "
                "Semantic matching disabled. Install with: "
                "pip install sentence-transformers"
            )

    @property
    def available(self) -> bool:
        return self._enabled

    def _load_model(self) -> None:
        if self._model is not None:
            return
        if not self._enabled:
            return
        try:
            LOG.info("Loading embedding model %s on %s ...", self._model_name, self._device)
            self._model = SentenceTransformer(self._model_name, device=self._device)
            dim_fn = getattr(self._model, "get_embedding_dimension",
                            getattr(self._model, "get_sentence_embedding_dimension", None))
            dim = dim_fn() if dim_fn else "?"
            LOG.info("Embedding model loaded (dim=%s).", dim)
        except Exception:
            LOG.exception("Failed to load embedding model %s. Semantic matching disabled.", self._model_name)
            self._enabled = False

    def precompute_dc_embeddings(
        self,
        dc_texts: Dict[str, str],
    ) -> None:
        """Pre-compute and cache embeddings for all DataComponent profiles.

        Args:
            dc_texts: mapping of DC ID to the concatenated embedding text
                      (description + channel strings).
        """
        if not self._enabled:
            return
        self._load_model()
        if self._model is None:
            return

        self._dc_texts = dict(dc_texts)
        ids = list(dc_texts.keys())
        texts = [dc_texts[dc_id] for dc_id in ids]

        LOG.info("Pre-computing embeddings for %d DataComponents ...", len(ids))
        vectors = self._model.encode(
            texts,
            batch_size=32,
            show_progress_bar=False,
            normalize_embeddings=True,
        )
        for idx, dc_id in enumerate(ids):
            self._dc_embeddings[dc_id] = vectors[idx]
        LOG.info("DC embedding cache ready (%d vectors).", len(self._dc_embeddings))

    def embed_text(self, text: str) -> Optional[np.ndarray]:
        """Encode a single text string into a normalised embedding vector."""
        if not self._enabled:
            return None
        self._load_model()
        if self._model is None:
            return None
        vec = self._model.encode(
            text,
            show_progress_bar=False,
            normalize_embeddings=True,
        )
        return np.asarray(vec)

    def semantic_similarity(
        self,
        log_embedding: Optional[np.ndarray],
        dc_id: str,
    ) -> float:
        """Cosine similarity between a log embedding and a cached DC embedding."""
        if log_embedding is None:
            return 0.0
        dc_vec = self._dc_embeddings.get(dc_id)
        if dc_vec is None:
            return 0.0
        return _cosine_similarity(log_embedding, dc_vec)

    def bulk_semantic_similarity(
        self,
        log_embedding: Optional[np.ndarray],
        dc_ids: Optional[Sequence[str]] = None,
    ) -> Dict[str, float]:
        """Compute cosine similarity against all (or selected) DC embeddings.

        Returns a dict of {dc_id: similarity_score}.
        """
        if log_embedding is None:
            return {}
        ids = dc_ids if dc_ids is not None else list(self._dc_embeddings.keys())
        results: Dict[str, float] = {}
        for dc_id in ids:
            dc_vec = self._dc_embeddings.get(dc_id)
            if dc_vec is not None:
                results[dc_id] = _cosine_similarity(log_embedding, dc_vec)
        return results

    @property
    def dc_ids(self) -> List[str]:
        return list(self._dc_embeddings.keys())
