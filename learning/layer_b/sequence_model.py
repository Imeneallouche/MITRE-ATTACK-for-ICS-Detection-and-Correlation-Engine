"""Causal-window Transformer for attack-chain recognition.

The model consumes a sequence of alert-token tuples
``(dc_id, asset_id, scalar_features, time_delta)`` and outputs:

* ``chain_logits`` — logits over chain ids (multi-class).
* ``technique_logits`` — multi-label technique probabilities.
* ``tactic_logits`` — multi-label tactic probabilities (used as a
  hierarchical mask on the technique head).

The attention mask is causal *with* a sliding-window cap (``causal_window``)
to keep memory linear in sequence length while preserving the
causality-preserving behaviour required for streaming inference.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
except Exception:  # pragma: no cover
    torch = None  # type: ignore
    nn = None  # type: ignore


@dataclass
class SequenceModelConfig:
    n_dc: int = 64
    n_asset: int = 32
    n_technique: int = 64
    n_tactic: int = 16
    n_chain: int = 16
    scalar_dim: int = 20
    d_model: int = 128
    n_heads: int = 4
    n_layers: int = 3
    ff_dim: int = 256
    dropout: float = 0.1
    causal_window: int = 8
    max_seq_len: int = 64


def _require_torch() -> None:
    if torch is None:
        raise RuntimeError(
            "Layer B requires PyTorch. Install via `pip install torch` (or use the"
            " GPU wheel from pytorch.org).",
        )


def causal_window_mask(seq_len: int, window: int) -> "torch.Tensor":
    _require_torch()
    i = torch.arange(seq_len).unsqueeze(1)
    j = torch.arange(seq_len).unsqueeze(0)
    keep = (j <= i) & ((i - j) < window)
    mask = torch.zeros(seq_len, seq_len)
    mask.masked_fill_(~keep, float("-inf"))
    return mask


class _CausalEncoderBlock(nn.Module if nn is not None else object):
    """A single Transformer block configured for causal attention."""

    def __init__(self, cfg: SequenceModelConfig) -> None:
        _require_torch()
        super().__init__()
        self.self_attn = nn.MultiheadAttention(
            cfg.d_model, cfg.n_heads, dropout=cfg.dropout, batch_first=True,
        )
        self.norm1 = nn.LayerNorm(cfg.d_model)
        self.norm2 = nn.LayerNorm(cfg.d_model)
        self.ffn = nn.Sequential(
            nn.Linear(cfg.d_model, cfg.ff_dim),
            nn.GELU(),
            nn.Dropout(cfg.dropout),
            nn.Linear(cfg.ff_dim, cfg.d_model),
        )
        self.dropout = nn.Dropout(cfg.dropout)

    def forward(self, x: "torch.Tensor", attn_mask: "torch.Tensor") -> "torch.Tensor":
        h = self.norm1(x)
        attn_out, _ = self.self_attn(h, h, h, attn_mask=attn_mask, need_weights=False)
        x = x + self.dropout(attn_out)
        h = self.norm2(x)
        x = x + self.ffn(h)
        return x


class CausalWindowTransformer(nn.Module if nn is not None else object):
    """End-to-end model for chain + technique + tactic attribution."""

    def __init__(self, cfg: SequenceModelConfig) -> None:
        _require_torch()
        super().__init__()
        self.cfg = cfg
        self.dc_embed = nn.Embedding(cfg.n_dc, cfg.d_model // 2, padding_idx=0)
        self.asset_embed = nn.Embedding(cfg.n_asset, cfg.d_model // 4, padding_idx=0)
        self.scalar_proj = nn.Linear(cfg.scalar_dim + 1, cfg.d_model // 4)
        self.position = nn.Embedding(cfg.max_seq_len, cfg.d_model)

        self.input_norm = nn.LayerNorm(cfg.d_model)
        self.encoder = nn.ModuleList([_CausalEncoderBlock(cfg) for _ in range(cfg.n_layers)])

        self.chain_head = nn.Linear(cfg.d_model, max(cfg.n_chain, 2))
        self.technique_head = nn.Linear(cfg.d_model, max(cfg.n_technique, 2))
        self.tactic_head = nn.Linear(cfg.d_model, max(cfg.n_tactic, 2))

    def forward(
        self,
        dc_ids: "torch.Tensor",
        asset_ids: "torch.Tensor",
        scalar: "torch.Tensor",
        time_delta: "torch.Tensor",
        pad_mask: Optional["torch.Tensor"] = None,
    ):
        b, t = dc_ids.shape
        device = dc_ids.device
        pos_idx = torch.arange(t, device=device).unsqueeze(0).expand(b, -1)

        scalar_in = torch.cat([scalar, time_delta.unsqueeze(-1)], dim=-1)

        x = torch.cat([
            self.dc_embed(dc_ids),
            self.asset_embed(asset_ids),
            self.scalar_proj(scalar_in),
        ], dim=-1)

        # Pad to d_model in case the sub-projections don't perfectly sum.
        if x.shape[-1] != self.cfg.d_model:
            pad = self.cfg.d_model - x.shape[-1]
            if pad > 0:
                x = F.pad(x, (0, pad))
            else:
                x = x[..., : self.cfg.d_model]

        x = x + self.position(pos_idx.clamp(max=self.cfg.max_seq_len - 1))
        x = self.input_norm(x)

        attn_mask = causal_window_mask(t, self.cfg.causal_window).to(device)

        # Apply pad mask by converting to attention mask.  We rely on
        # MultiheadAttention's broadcast of the pad mask via the
        # ``key_padding_mask`` argument; pass through every block.
        if pad_mask is not None:
            kp_mask = pad_mask.bool()
        else:
            kp_mask = None

        for block in self.encoder:
            if kp_mask is not None:
                # MultiheadAttention does not let us pass key_padding_mask via
                # the block helper above; re-implement the call here.
                h = block.norm1(x)
                attn_out, _ = block.self_attn(
                    h, h, h, attn_mask=attn_mask,
                    key_padding_mask=kp_mask, need_weights=False,
                )
                x = x + block.dropout(attn_out)
                h2 = block.norm2(x)
                x = x + block.ffn(h2)
            else:
                x = block(x, attn_mask)

        if pad_mask is not None:
            mask = (~pad_mask.bool()).float().unsqueeze(-1)
            pooled = (x * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
        else:
            pooled = x.mean(dim=1)

        return {
            "chain_logits": self.chain_head(pooled),
            "technique_logits": self.technique_head(pooled),
            "tactic_logits": self.tactic_head(pooled),
            "token_logits_technique": self.technique_head(x),
        }
