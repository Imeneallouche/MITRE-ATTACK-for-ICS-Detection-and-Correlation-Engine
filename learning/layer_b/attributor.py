"""High-level wrapper around :class:`CausalWindowTransformer`.

The :class:`ChainAttributor` is the public interface used by the
orchestrator.  It handles vocabulary mapping, batching, training,
inference, and persistence, hiding the PyTorch boilerplate.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from ..data.dataset import LabelledExample
from ..data.feature_builder import AlertFeatures
from .sequence_model import CausalWindowTransformer, SequenceModelConfig
from .vocab import PAD, UNK, Vocabulary

LOG = logging.getLogger("learning.layer_b")

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import DataLoader, Dataset
except Exception:  # pragma: no cover
    torch = None  # type: ignore


@dataclass
class ChainPrediction:
    chain_id: str
    chain_confidence: float
    techniques: List[Tuple[str, float]] = field(default_factory=list)
    tactics: List[Tuple[str, float]] = field(default_factory=list)
    sequence_len: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "chain_confidence": float(self.chain_confidence),
            "techniques": [
                {"id": t, "confidence": float(p)} for t, p in self.techniques
            ],
            "tactics": [
                {"id": t, "confidence": float(p)} for t, p in self.tactics
            ],
            "sequence_len": int(self.sequence_len),
        }


# ── Dataset wrapper ───────────────────────────────────────────────────
class _SeqDataset(Dataset if torch is not None else object):  # type: ignore[misc]
    def __init__(
        self,
        groups: List[List[LabelledExample]],
        vocab: Vocabulary,
        cfg: SequenceModelConfig,
    ) -> None:
        if torch is None:
            raise RuntimeError("Layer B training requires PyTorch.")
        self.groups = groups
        self.vocab = vocab
        self.cfg = cfg

    def __len__(self) -> int:
        return len(self.groups)

    def __getitem__(self, idx: int):
        seq = self.groups[idx][: self.cfg.max_seq_len]
        n = len(seq)
        dc = torch.zeros(self.cfg.max_seq_len, dtype=torch.long)
        asset = torch.zeros(self.cfg.max_seq_len, dtype=torch.long)
        scalar = torch.zeros(self.cfg.max_seq_len, self.cfg.scalar_dim, dtype=torch.float32)
        time_delta = torch.zeros(self.cfg.max_seq_len, dtype=torch.float32)
        pad = torch.ones(self.cfg.max_seq_len, dtype=torch.bool)

        if n > 0:
            base_ts = seq[0].features.timestamp.timestamp()
        for i, ex in enumerate(seq):
            f = ex.features
            dc[i] = self.vocab.encode_dc(f.datacomponent)
            asset[i] = self.vocab.encode_asset(f.asset_id)
            slen = min(f.scalar.shape[0], self.cfg.scalar_dim)
            scalar[i, :slen] = torch.from_numpy(f.scalar[:slen].astype(np.float32))
            time_delta[i] = float(f.timestamp.timestamp() - base_ts) / 60.0
            pad[i] = False

        # Targets
        chain_label_str = seq[0].chain_id or self.vocab.chain_at(self.vocab.chain[UNK])
        chain_target = torch.tensor(
            self.vocab.chain.get(chain_label_str, self.vocab.chain[UNK]),
            dtype=torch.long,
        )

        # Multi-label tech/tactic targets — union across the window.
        tech_target = torch.zeros(max(len(self.vocab.technique), 2), dtype=torch.float32)
        for ex in seq:
            for t in ex.technique_list:
                idx = self.vocab.technique.get(t.upper())
                if idx is not None:
                    tech_target[idx] = 1.0

        # We have no tactic ground truth at the window level here; downstream
        # ``ChainAttributor`` inflates tactic targets from a fallback map.
        tactic_target = torch.zeros(max(len(self.vocab.tactic), 2), dtype=torch.float32)

        return dc, asset, scalar, time_delta, pad, chain_target, tech_target, tactic_target


class ChainAttributor:
    """Train and run the Layer-B sequence model."""

    def __init__(
        self,
        *,
        cfg: SequenceModelConfig,
        vocab: Vocabulary,
        device: str = "auto",
        technique_threshold: float = 0.45,
        tactic_threshold: float = 0.35,
        unknown_chain_label: str = "__UNKNOWN__",
        technique_to_tactics: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        if torch is None:
            raise RuntimeError("Layer B requires PyTorch.")
        self.cfg = cfg
        self.vocab = vocab
        self.device = self._select_device(device)
        self.technique_threshold = float(technique_threshold)
        self.tactic_threshold = float(tactic_threshold)
        self.unknown_chain_label = unknown_chain_label
        self.technique_to_tactics = {
            k.upper(): [t.lower() for t in (v or [])]
            for k, v in (technique_to_tactics or {}).items()
        }
        self.model = CausalWindowTransformer(cfg).to(self.device)

    # ── Device ─────────────────────────────────────────────────────────
    @staticmethod
    def _select_device(device: str) -> str:
        if torch is None:
            return "cpu"
        if device == "auto":
            return "cuda" if torch.cuda.is_available() else "cpu"
        return device

    # ── Vocabulary builder ─────────────────────────────────────────────
    @classmethod
    def fit_vocabulary(
        cls,
        examples: Sequence[LabelledExample],
        *,
        technique_to_tactics: Optional[Dict[str, List[str]]] = None,
    ) -> Vocabulary:
        v = Vocabulary.empty()
        dcs, assets, techs, chains = set(), set(), set(), set()
        tactics = set()
        for ex in examples:
            dcs.add(ex.features.datacomponent)
            assets.add(ex.features.asset_id)
            techs.update(ex.technique_list)
            if ex.chain_id:
                chains.add(ex.chain_id)
        for t in techs:
            for tac in (technique_to_tactics or {}).get(t.upper(), []):
                tactics.add(tac.lower())
        return v.fit(dcs=dcs, assets=assets, techniques=techs,
                     tactics=tactics, chains=chains)

    # ── Train ──────────────────────────────────────────────────────────
    def fit(
        self,
        train_groups: List[List[LabelledExample]],
        *,
        epochs: int = 20,
        batch_size: int = 16,
        lr: float = 0.0005,
        weight_decay: float = 1e-4,
        grad_clip: float = 1.0,
        val_split: float = 0.2,
        seed: int = 42,
    ) -> Dict[str, Any]:
        if torch is None:
            raise RuntimeError("Layer B requires PyTorch.")
        if not train_groups:
            raise ValueError("ChainAttributor.fit: no training groups.")

        torch.manual_seed(seed)
        rng = np.random.default_rng(seed)
        idx = np.arange(len(train_groups))
        rng.shuffle(idx)
        n_val = max(1, int(len(idx) * val_split))
        val_idx, tr_idx = idx[:n_val], idx[n_val:]
        tr_ds = _SeqDataset([train_groups[i] for i in tr_idx], self.vocab, self.cfg)
        val_ds = _SeqDataset([train_groups[i] for i in val_idx], self.vocab, self.cfg)

        tr_loader = DataLoader(tr_ds, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

        opt = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=weight_decay)
        chain_loss_fn = nn.CrossEntropyLoss()
        ml_loss_fn = nn.BCEWithLogitsLoss()

        best_val = float("inf")
        history: List[Dict[str, float]] = []

        for ep in range(epochs):
            self.model.train()
            running = 0.0
            n = 0
            for batch in tr_loader:
                dc, asset, scalar, td, pad, chain_t, tech_t, tactic_t = (b.to(self.device) for b in batch)
                out = self.model(dc, asset, scalar, td, pad)
                loss_chain = chain_loss_fn(out["chain_logits"], chain_t)
                loss_tech = ml_loss_fn(out["technique_logits"], tech_t)
                loss_tactic = ml_loss_fn(out["tactic_logits"], tactic_t) if tactic_t.sum() > 0 else torch.tensor(0.0, device=self.device)
                loss = loss_chain + loss_tech + 0.5 * loss_tactic
                opt.zero_grad()
                loss.backward()
                if grad_clip:
                    nn.utils.clip_grad_norm_(self.model.parameters(), grad_clip)
                opt.step()
                running += loss.item() * dc.size(0)
                n += dc.size(0)
            train_loss = running / max(n, 1)

            val_loss = self._evaluate_loss(val_loader, chain_loss_fn, ml_loss_fn)
            history.append({"epoch": ep, "train_loss": train_loss, "val_loss": val_loss})
            LOG.info("Layer B epoch %d/%d train=%.4f val=%.4f", ep + 1, epochs, train_loss, val_loss)
            if val_loss < best_val:
                best_val = val_loss
        return {"history": history, "best_val": best_val}

    def _evaluate_loss(self, loader, chain_loss_fn, ml_loss_fn) -> float:
        self.model.eval()
        total = 0.0
        n = 0
        with torch.no_grad():
            for batch in loader:
                dc, asset, scalar, td, pad, chain_t, tech_t, tactic_t = (b.to(self.device) for b in batch)
                out = self.model(dc, asset, scalar, td, pad)
                loss = (
                    chain_loss_fn(out["chain_logits"], chain_t)
                    + ml_loss_fn(out["technique_logits"], tech_t)
                )
                total += float(loss.item()) * dc.size(0)
                n += dc.size(0)
        return total / max(n, 1)

    # ── Inference ──────────────────────────────────────────────────────
    @torch.no_grad() if torch is not None else lambda f: f
    def predict(self, sequence: Sequence[AlertFeatures]) -> ChainPrediction:
        if torch is None:
            raise RuntimeError("Layer B requires PyTorch.")
        if not sequence:
            return ChainPrediction(self.unknown_chain_label, 0.0, [], [], 0)
        seq = list(sequence)[: self.cfg.max_seq_len]
        n = len(seq)

        dc = torch.zeros(1, self.cfg.max_seq_len, dtype=torch.long, device=self.device)
        asset = torch.zeros(1, self.cfg.max_seq_len, dtype=torch.long, device=self.device)
        scalar = torch.zeros(1, self.cfg.max_seq_len, self.cfg.scalar_dim,
                             dtype=torch.float32, device=self.device)
        td = torch.zeros(1, self.cfg.max_seq_len, dtype=torch.float32, device=self.device)
        pad = torch.ones(1, self.cfg.max_seq_len, dtype=torch.bool, device=self.device)
        base_ts = seq[0].timestamp.timestamp()
        for i, f in enumerate(seq):
            dc[0, i] = self.vocab.encode_dc(f.datacomponent)
            asset[0, i] = self.vocab.encode_asset(f.asset_id)
            slen = min(f.scalar.shape[0], self.cfg.scalar_dim)
            scalar[0, i, :slen] = torch.from_numpy(f.scalar[:slen].astype(np.float32)).to(self.device)
            td[0, i] = float(f.timestamp.timestamp() - base_ts) / 60.0
            pad[0, i] = False

        self.model.eval()
        out = self.model(dc, asset, scalar, td, pad)
        chain_probs = F.softmax(out["chain_logits"][0], dim=-1).cpu().numpy()
        tech_probs = torch.sigmoid(out["technique_logits"][0]).cpu().numpy()
        tactic_probs = torch.sigmoid(out["tactic_logits"][0]).cpu().numpy()

        chain_idx = int(np.argmax(chain_probs))
        chain_id = self.vocab.chain_at(chain_idx)
        chain_conf = float(chain_probs[chain_idx])

        techs = [
            (self.vocab.technique_at(i), float(p))
            for i, p in enumerate(tech_probs)
            if self.vocab.technique_at(i) not in {PAD, UNK}
            and p >= self.technique_threshold
        ]
        techs.sort(key=lambda t: t[1], reverse=True)

        # Hierarchical mask: keep techniques whose tactic was also predicted.
        active_tactics = {
            self.vocab.tactic_at(i)
            for i, p in enumerate(tactic_probs)
            if p >= self.tactic_threshold
        } - {PAD, UNK}
        if self.technique_to_tactics and active_tactics:
            techs = [
                (t, p) for t, p in techs
                if not self.technique_to_tactics.get(t.upper())
                or set(self.technique_to_tactics[t.upper()]) & active_tactics
            ]

        tactics = [
            (self.vocab.tactic_at(i), float(p))
            for i, p in enumerate(tactic_probs)
            if self.vocab.tactic_at(i) not in {PAD, UNK}
            and p >= self.tactic_threshold
        ]
        tactics.sort(key=lambda t: t[1], reverse=True)

        return ChainPrediction(
            chain_id=chain_id,
            chain_confidence=chain_conf,
            techniques=techs,
            tactics=tactics,
            sequence_len=n,
        )

    # ── Persistence ────────────────────────────────────────────────────
    def save(self, model_path: Path, vocab_path: Path) -> None:
        if torch is None:
            raise RuntimeError("Layer B requires PyTorch.")
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "state_dict": self.model.state_dict(),
            "cfg": self.cfg.__dict__,
            "technique_threshold": self.technique_threshold,
            "tactic_threshold": self.tactic_threshold,
            "unknown_chain_label": self.unknown_chain_label,
            "technique_to_tactics": self.technique_to_tactics,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }, model_path)
        self.vocab.save(vocab_path)

    @classmethod
    def load(cls, model_path: Path, vocab_path: Path, *, device: str = "auto") -> "ChainAttributor":
        if torch is None:
            raise RuntimeError("Layer B requires PyTorch.")
        vocab = Vocabulary.load(vocab_path)
        payload = torch.load(model_path, map_location="cpu")
        cfg_kwargs = payload.get("cfg", {})
        cfg = SequenceModelConfig(**cfg_kwargs) if cfg_kwargs else SequenceModelConfig()
        att = cls(
            cfg=cfg, vocab=vocab, device=device,
            technique_threshold=payload.get("technique_threshold", 0.45),
            tactic_threshold=payload.get("tactic_threshold", 0.35),
            unknown_chain_label=payload.get("unknown_chain_label", "__UNKNOWN__"),
            technique_to_tactics=payload.get("technique_to_tactics") or {},
        )
        att.model.load_state_dict(payload["state_dict"])
        att.model.to(att.device)
        att.model.eval()
        return att
