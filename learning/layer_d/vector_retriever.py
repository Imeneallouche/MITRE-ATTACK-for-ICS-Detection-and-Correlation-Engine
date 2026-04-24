"""Lightweight in-memory dense-passage retriever.

Used by the multi-agent LLM as a soft fallback when a technique has no
direct mitigation entries in the KG (e.g. very recent technique IDs).
The corpus is loaded from ``data/datacomponents/<DC>/.../*.json`` files
that the engine already ships, so this class adds zero heavyweight
indexing infrastructure.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

LOG = logging.getLogger("learning.layer_d.vector")

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
except Exception:  # pragma: no cover
    SentenceTransformer = None  # type: ignore


@dataclass
class _Doc:
    doc_id: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class VectorRetriever:
    def __init__(
        self,
        *,
        model_name: str = "BAAI/bge-small-en-v1.5",
        device: str = "cpu",
        embedder: Optional[Any] = None,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self._embedder = embedder
        self._docs: List[_Doc] = []
        self._matrix: Optional[np.ndarray] = None

    def _ensure_embedder(self) -> Any:
        if self._embedder is not None:
            return self._embedder
        if SentenceTransformer is None:
            raise RuntimeError(
                "sentence-transformers not installed; install it or pass an embedder.",
            )
        self._embedder = SentenceTransformer(self.model_name, device=self.device)
        return self._embedder

    # ── Corpus management ─────────────────────────────────────────────
    def add_documents(self, docs: Iterable[Dict[str, Any]]) -> None:
        new_docs = []
        for d in docs:
            text = str(d.get("text") or d.get("description") or "").strip()
            if not text:
                continue
            new_docs.append(_Doc(
                doc_id=str(d.get("id") or d.get("doc_id") or f"doc-{len(self._docs)}"),
                text=text,
                metadata={k: v for k, v in d.items() if k not in {"text", "description", "id", "doc_id"}},
            ))
        if not new_docs:
            return
        embedder = self._ensure_embedder()
        embs = embedder.encode([d.text for d in new_docs], normalize_embeddings=True)
        embs = np.asarray(embs, dtype=np.float32)
        if self._matrix is None:
            self._matrix = embs
        else:
            self._matrix = np.vstack([self._matrix, embs])
        self._docs.extend(new_docs)

    def add_from_directory(self, root: Path) -> int:
        root = Path(root)
        added = 0
        for path in root.rglob("*.json"):
            try:
                with path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            text_blocks: List[str] = []
            if isinstance(data, dict):
                for k in ("description", "summary", "rationale", "long_description"):
                    v = data.get(k)
                    if isinstance(v, str) and v.strip():
                        text_blocks.append(v)
                kws = data.get("keywords") or []
                if isinstance(kws, list) and kws:
                    text_blocks.append(", ".join(str(x) for x in kws if x))
            text = "\n".join(text_blocks).strip()
            if not text:
                continue
            self.add_documents([{
                "id": str(path.stem),
                "text": text,
                "path": str(path),
            }])
            added += 1
        return added

    # ── Query ─────────────────────────────────────────────────────────
    def query(self, text: str, *, top_k: int = 6) -> List[Dict[str, Any]]:
        if self._matrix is None or not self._docs:
            return []
        embedder = self._ensure_embedder()
        q = embedder.encode([text], normalize_embeddings=True)
        q = np.asarray(q, dtype=np.float32)[0]
        scores = self._matrix @ q
        order = np.argsort(scores)[::-1][:top_k]
        out: List[Dict[str, Any]] = []
        for idx in order:
            d = self._docs[int(idx)]
            out.append({
                "doc_id": d.doc_id, "score": float(scores[int(idx)]),
                "text": d.text, "metadata": d.metadata,
            })
        return out

    def __len__(self) -> int:
        return len(self._docs)
