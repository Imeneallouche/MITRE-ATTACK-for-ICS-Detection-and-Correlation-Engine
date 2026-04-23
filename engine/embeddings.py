"""Semantic embedding engine for DataComponent similarity matching.

Uses sentence-transformers to encode DC descriptions/channels and log
messages into dense vectors, then computes cosine similarity to identify
which DataComponents are semantically relevant to an incoming log event.

Each MITRE ``log_sources`` row (Name + Channel) is embedded once (deduped
across DCs) so the matcher can score *affinity* between a concrete site
log and the specific DC log-source lines, not only the aggregate DC text.
This differentiates DataComponents that share the same pipeline mapping.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from .models import DataComponentProfile

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


def _embedding_device_candidates_for_auto() -> List[str]:
    """Ordered devices to try when ``device: auto`` (CUDA, Intel XPU, then CPU)."""
    order: List[str] = []
    try:
        import torch

        if torch.cuda.is_available():
            order.append("cuda")
        xpu = getattr(torch, "xpu", None)
        if xpu is not None and getattr(xpu, "is_available", lambda: False)():
            order.append("xpu")
    except Exception:
        pass
    order.append("cpu")
    seen: set = set()
    out: List[str] = []
    for d in order:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


class EmbeddingEngine:
    """Manages a sentence-transformer model and DC embedding cache."""

    def __init__(
        self,
        model_name: str = "BAAI/bge-small-en-v1.5",
        device: str = "cpu",
        *,
        enabled: bool = True,
        encode_batch_size: int = 64,
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._encode_batch_size = max(1, int(encode_batch_size))
        self._enabled = enabled and _HAS_ST
        self._model: Optional[SentenceTransformer] = None
        self._resolved_device: Optional[str] = None
        self._dc_embeddings: Dict[str, np.ndarray] = {}
        self._dc_texts: Dict[str, str] = {}
        # Stacked unit vectors (float32) for vectorized cosine similarity vs. all DCs.
        self._dc_matrix: Optional[np.ndarray] = None
        self._dc_id_order: List[str] = []
        self._dc_id_to_row: Dict[str, int] = {}
        # Deduped (Name, Channel) line texts -> row index; per-DC list of row indices
        self._line_texts: List[str] = []
        self._line_matrix: Optional[np.ndarray] = None
        self._dc_line_row_indices: Dict[str, List[int]] = {}

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
        if self._device.strip().lower() == "auto":
            candidates = _embedding_device_candidates_for_auto()
        else:
            candidates = [self._device]

        last_exc: Optional[Exception] = None
        for dev in candidates:
            try:
                LOG.info("Loading embedding model %s on %s ...", self._model_name, dev)
                self._model = SentenceTransformer(self._model_name, device=dev)
                self._resolved_device = dev
                dim_fn = getattr(
                    self._model,
                    "get_embedding_dimension",
                    getattr(self._model, "get_sentence_embedding_dimension", None),
                )
                dim = dim_fn() if dim_fn else "?"
                LOG.info("Embedding model loaded (dim=%s, device=%s).", dim, dev)
                return
            except Exception as exc:
                last_exc = exc
                LOG.warning(
                    "Could not load embedding model on %s (%s); trying next option.",
                    dev,
                    exc,
                )
                self._model = None

        LOG.error(
            "Failed to load embedding model %s on any device. Semantic matching disabled. Last error: %r",
            self._model_name,
            last_exc,
        )
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
        bs = self._encode_batch_size
        vectors = self._model.encode(
            texts,
            batch_size=min(bs, max(1, len(texts))),
            show_progress_bar=False,
            normalize_embeddings=True,
        )
        for idx, dc_id in enumerate(ids):
            self._dc_embeddings[dc_id] = np.asarray(vectors[idx], dtype=np.float32).reshape(-1)

        self._dc_id_order = list(ids)
        self._dc_id_to_row = {dc_id: i for i, dc_id in enumerate(self._dc_id_order)}
        if self._dc_id_order:
            stacked = np.stack([self._dc_embeddings[i] for i in self._dc_id_order])
            self._dc_matrix = stacked.astype(np.float32, copy=False)
        else:
            self._dc_matrix = None
        LOG.info(
            "DC embedding cache ready (%d vectors, matrix=%s).",
            len(self._dc_embeddings),
            getattr(self._dc_matrix, "shape", None),
        )

    def precompute_log_source_line_embeddings(
        self,
        profiles: Sequence[DataComponentProfile],
    ) -> None:
        """Embed every unique ``log_sources`` (Name + Channel) row for affinity scoring."""
        if not self._enabled:
            return
        self._load_model()
        if self._model is None:
            return

        text_to_row: Dict[str, int] = {}
        texts: List[str] = []
        self._dc_line_row_indices = {}

        for profile in profiles:
            row_ids: List[int] = []
            for ls in profile.log_sources:
                name = ls.name.strip()
                channel = ls.channel.strip()
                combined = f"{name}\n{channel}"
                if combined not in text_to_row:
                    text_to_row[combined] = len(texts)
                    texts.append(combined)
                row_ids.append(text_to_row[combined])
            self._dc_line_row_indices[profile.id] = row_ids

        self._line_texts = texts
        if not texts:
            LOG.info("No log_source lines to embed.")
            return

        LOG.info("Pre-computing embeddings for %d unique log_source lines ...", len(texts))
        bs = self._encode_batch_size
        mat = self._model.encode(
            texts,
            batch_size=min(bs, max(1, len(texts))),
            show_progress_bar=False,
            normalize_embeddings=True,
        )
        self._line_matrix = np.asarray(mat, dtype=np.float32)
        LOG.info("Log-source line embedding matrix ready (shape=%s).", self._line_matrix.shape)

    def log_source_line_affinity(
        self,
        log_embedding: Optional[np.ndarray],
        profile_id: str,
        event_log_source: str,
        profile: DataComponentProfile,
    ) -> Tuple[float, str, str]:
        """Max cosine similarity between the log and name-aligned ``log_sources`` rows.

        Returns:
            (best_similarity, best_Name, best_Channel) — best_Channel may be truncated
            in callers for storage. When embeddings are unavailable, returns (0.0, "", "").
        """
        if (
            log_embedding is None
            or self._line_matrix is None
            or profile_id not in self._dc_line_row_indices
        ):
            return -1.0, "", ""

        indices = self._dc_line_row_indices[profile_id]
        if not indices or not profile.log_sources:
            return -1.0, "", ""

        best_sim = -1.0
        best_name = ""
        best_ch = ""
        ev_src = event_log_source.strip().lower()

        for i, row_idx in enumerate(indices):
            if i >= len(profile.log_sources):
                break
            ls = profile.log_sources[i]
            if not log_source_name_matches_observed(ev_src, ls.name):
                continue
            vec = self._line_matrix[row_idx]
            sim = _cosine_similarity(log_embedding, vec)
            if sim > best_sim:
                best_sim = sim
                best_name = ls.name
                best_ch = ls.channel

        if best_sim < 0.0:
            return -1.0, "", ""
        return float(best_sim), best_name, best_ch

    def embed_text(self, text: str) -> Optional[np.ndarray]:
        """Encode a single text string into a normalised embedding vector."""
        out = self.embed_texts([text])
        return out[0] if out else None

    def embed_texts(self, texts: List[str]) -> List[Optional[np.ndarray]]:
        """Batch-encode log lines (major latency win vs. one ``encode`` per event)."""
        if not self._enabled or not texts:
            return [None] * len(texts)
        self._load_model()
        if self._model is None:
            return [None] * len(texts)

        bs = self._encode_batch_size
        out: List[Optional[np.ndarray]] = []
        for start in range(0, len(texts), bs):
            chunk = texts[start : start + bs]
            vecs = self._model.encode(
                chunk,
                batch_size=min(bs, len(chunk)),
                show_progress_bar=False,
                normalize_embeddings=True,
            )
            for row in vecs:
                out.append(np.asarray(row, dtype=np.float32).reshape(-1))
        return out

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

        Vectors are L2-normalized; cosine similarity equals the dot product.
        Uses one matrix-vector multiply for the full-catalog case.
        """
        if log_embedding is None:
            return {}
        log = np.asarray(log_embedding, dtype=np.float32).reshape(-1)

        if self._dc_matrix is not None and self._dc_id_order and self._dc_id_to_row:
            if dc_ids is None:
                sims = self._dc_matrix @ log
                return {self._dc_id_order[i]: float(sims[i]) for i in range(len(self._dc_id_order))}
            id_list = [d for d in dc_ids if d in self._dc_id_to_row]
            if id_list:
                idx = [self._dc_id_to_row[d] for d in id_list]
                sub = self._dc_matrix[idx]
                sims = sub @ log
                return {id_list[i]: float(sims[i]) for i in range(len(id_list))}

        ids = list(dc_ids) if dc_ids is not None else list(self._dc_embeddings.keys())
        results: Dict[str, float] = {}
        for dc_id in ids:
            dc_vec = self._dc_embeddings.get(dc_id)
            if dc_vec is not None:
                results[dc_id] = _cosine_similarity(log, dc_vec)
        return results

    @property
    def dc_ids(self) -> List[str]:
        return list(self._dc_embeddings.keys())


def log_source_name_matches_observed(event_src: str, line_name: str) -> bool:
    """True if the observed normalized log source type matches the DC row Name.

    Uses case-insensitive equality so ``NSM:Flow`` matches the MITRE catalog row
    ``NSM:Flow``; different tools (e.g. ``NSM:Flow`` vs ``NSM:Content``) do not match.
    """
    a = event_src.strip().lower()
    b = line_name.strip().lower()
    if not a or not b:
        return False
    return a == b
