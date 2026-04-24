# Learning-Enhanced ICS Detection and Mitigation Recommendation

*A feasibility study and implementation blueprint for integrating adaptive
learning and large-language-model–assisted mitigation recommendation into
a MITRE ATT&CK for ICS detection and correlation engine.*

---

## 1. Executive summary

This report assesses whether the existing **MITRE ATT&CK for ICS Detection
and Correlation Engine** — operating on a GRFICSv3 industrial simulation,
fed by Caldera-driven attack chains, and backed by a Neo4j knowledge graph
of techniques, mitigations, groups, software and data components — can be
meaningfully enhanced by a **reinforcement-learning (RL) component** and a
**large language model (LLM)** that contextualizes mitigations.

The core finding is that the *learning objective* the user describes is
**not natively an RL problem**. What is described is a weakly-supervised
**classification and sequence-labeling** problem (given a stream of logs
with time-window labels indicating “benign” vs “under attack with Caldera
chain X”, learn to attribute alerts to MITRE ATT&CK for ICS DataComponents
and techniques, and reduce false positives). Framing it as pure RL would
introduce non-trivial issues of sparse rewards, credit assignment, and
off-policy evaluation that recent surveys (Kurochkin & Volkov, 2025; Wang
et al., 2024; Kalpani et al., 2025) identify as the main bottlenecks of
DRL-based intrusion detection.

The report recommends a **hybrid architecture** that splits the problem
into three cooperating layers, each using the paradigm best suited to it:

1. **Weak / semi-supervised classification** of alerts to DataComponents
   and techniques, using time-window labels as weak supervision and
   Positive–Unlabeled (PU) learning for the benign stream.
2. **Sequence / graph modelling** of the alert stream to recognise attack
   chains and attribute MITRE ATT&CK for ICS techniques (LSTM or causal
   transformer over alert sequences, optionally coupled with a GNN over
   the provenance / asset graph — the DeepOP, StageFinder and hybrid
   GNN+LSTM families).
3. **Retrieval-Augmented Generation (RAG) with an LLM** over the Neo4j
   MITRE ATT&CK for ICS knowledge graph to produce **contextualised,
   prioritised, environment-aware mitigation recommendations**, ideally
   with a multi-agent / IRCopilot-style decomposition to suppress
   hallucinations.

Reinforcement learning does have a **well-defined, narrow, and scientifically
supported role** in this system: **alert triage, deferral and prioritisation
under analyst (or label) feedback**, following the L2DHF /
Deep-Reinforcement-Learning-from-Human-Feedback (DRLHF) pattern (Hoang & Le,
2025) and the HARE human-guided reward-shaping template (Sai & Dhaker,
2025). This is the only layer where “actions with delayed consequences”
genuinely exist (defer vs. accept, tune a threshold, ask for human
feedback). For this sub-problem, RL is appropriate and the literature
reports consistent 37–98 % reductions in mis-prioritised or false-positive
alerts compared with static baselines.

**Overall recommendation.** Keep the engine’s deterministic detection
core (which is already interpretable and explainable); add a **supervised
/ weakly-supervised learning loop** that updates classifiers and scoring
weights from labelled attack/benign windows; add a **sequence / graph
model** on top of the correlation layer to refine technique attribution;
add an **RL-based alert triage agent** only when there is a continuous
stream of labelled feedback; and use a **RAG + LLM** pipeline against the
MITRE ATT&CK for ICS knowledge graph for mitigation generation, with a
strict human-in-the-loop gate for any recommendation that would be
actioned in the ICS environment.

---

## 2. Feasibility analysis

### 2.1 Problem framing

The user’s system produces, at every timestamp *t*, a (potentially empty)
set of alerts *A_t = {a_t^{(1)}, …, a_t^{(k)}}* derived from log events,
each tagged by the deterministic engine with a candidate MITRE
DataComponent, a similarity score, and correlation metadata. The operator
additionally supplies a **window-level label** *L_t ∈ {benign, under-attack:
chain_id}*. When `under-attack`, the Caldera report contains the ordered
technique list *T = (τ_1, …, τ_n)* that was executed during the window.

The learning objectives are therefore:

* **(O1)** Given *a_t* and its context, predict whether it is a *true
  positive* (i.e. causally linked to the labelled attack) or a *false
  positive*.
* **(O2)** Given a stream *A_{[t−Δ, t]}*, predict the **MITRE ATT&CK for
  ICS technique** that is currently being executed, and ideally the
  position in the chain.
* **(O3)** Given the attributed techniques, the matched DataComponents
  and the environmental context (asset inventory, protocols, zones),
  **retrieve and contextualise mitigations** from the knowledge graph.

These objectives are **supervised or weakly-supervised prediction tasks**
with known ground truth at the time-window granularity. None of them
natively involves a sequence of actions with delayed, stochastic rewards
from an environment — the defining signature of RL. In contrast, three
classical paradigms directly apply:

* Supervised / weakly-supervised classification (O1, O2);
* Sequence or structured-prediction models (O2);
* Retrieval-based question answering / generation (O3).

### 2.2 Where RL is and is not appropriate

RL-for-intrusion-detection has a mature literature, well summarised by
the 2024–2025 surveys (Kurochkin & Volkov, 2025; Kalpani et al., 2025;
Wang et al., 2024). The *common pattern* these surveys identify is to
frame each classification decision as an action and give the agent a
reward of +1 for correctness and −1 for error on a benchmark dataset
(NSL-KDD, CIC-IDS, UNSW-NB15, etc.). On these tabular datasets, DRL
classifiers are *competitive with* but not systematically *better than*
supervised deep classifiers; their reported advantages (ability to
handle class imbalance, online adaptation) are, in practice, also
achievable with well-designed supervised models, cost-sensitive losses,
and continual-learning techniques such as memory replay (Kalpani et al.,
2025; Wang et al., 2024). In the ICS/SCADA-specific literature (Liyanage
et al., 2024; *IEEE TII* 2024) the use of DRL is justified primarily as
a way to cope with class imbalance and to support online updating —
again, both are achievable without RL.

**The genuinely RL-shaped sub-problem** in this system is not “detect the
attack” but “**decide what to do with each alert given a bounded analyst
budget and evolving feedback**”. Hoang & Le (2025) formalise this as
*Learning to Defer with Human Feedback* (L2DHF): a DRL agent trained via
*Deep Reinforcement Learning from Human Feedback* (DRLHF) decides whether
to accept, reject, or defer each alert to a human. On CIC-IDS2017 this
approach reduces false positives by ~52 % and mis-prioritisation of
high-severity alerts by ~98 % compared with a static predictive AI.
Similar results are reported for the HARE framework in adaptive phishing
detection (~97 % F1 at 2.5 % FPR) and by SOC vendors in deployed
continuous-feedback systems. These studies align with the system we are
designing: the attack/benign labels and the Caldera chain metadata *act
as teacher signals* for the agent.

### 2.3 Where the LLM is appropriate

LLMs are appropriate and state-of-the-art for **mitigation/remediation
recommendation** if (and only if) they are constrained by **retrieval
over a trusted structured source**, because they otherwise hallucinate
controls that do not exist or do not apply. The relevant literature
strands:

* **TechniqueRAG** (Lekssays et al., 2025) and **H-TechniqueRAG**
  (2026) demonstrate that RAG with a re-ranker is currently the
  state-of-the-art for mapping CTI text to ATT&CK technique IDs, with
  H-TechniqueRAG exploiting the tactic→technique hierarchy for a
  77.5 % reduction in candidate search space and a ~4 % F1 gain.
* **AttacKG+** (Zhang et al., 2024) shows that LLMs can extract
  ATT&CK-aligned attack knowledge graphs with a four-stage pipeline
  (rewriter, parser, identifier, summariser), providing templates for
  decomposed LLM reasoning.
* **IRCopilot** (Li et al., 2025) shows that a multi-agent LLM system
  (Planner, Generator, Reflector, Analyst) substantially outperforms
  single-LLM baselines on incident-response sub-tasks (+114 % to
  +150 %), and specifically attributes the improvement to the reduction
  of context loss and hallucination via responsibility segmentation.
* **ICSSPulse** (Karacan & Ghafir, 2026) is the first ICS-specific PT
  platform to integrate an LLM-assisted reporting module that maps
  findings to ICS MITRE ATT&CK mitigations — a direct templating
  precedent for the OT recommendation layer proposed here.
* Raptis et al. (2025) provide a systematic evaluation of multiple LLMs
  for IR tasks and explicitly recommend human-in-the-loop control,
  calibrated outputs, provenance-bound retrieval, and staged rollout —
  the operational doctrine this report adopts.

### 2.4 Feasibility verdict

The idea, as a whole, is **feasible** — but with two precise caveats
that shape the architecture:

1. **RL should not be the primary learning paradigm.** It should be a
   *narrow component* (alert triage / analyst deferral / threshold
   adaptation) plugged into a system whose main learning work is done
   by supervised / weakly-supervised and sequence models.
2. **The LLM must be a constrained, retrieval-grounded, multi-agent
   system with human-in-the-loop approval for any actionable output.**
   Raw LLM prompting on OT environments is not acceptable due to
   hallucination, privacy, and the catastrophic-action risk inherent to
   ICS (plant safety).

---

## 3. Literature-based comparison of approaches

### 3.1 Taxonomy of candidate paradigms

| # | Paradigm | Typical task it solves well | Representative works | Fit to (O1) FP reduction | Fit to (O2) technique attribution | Fit to (O3) mitigation reco |
|---|---|---|---|---|---|---|
| 1 | Supervised / weakly-supervised classification | Per-alert true-/false-positive labelling | Kalpani et al. (2025); Feng (2017) | **Strong** | Medium | Weak |
| 2 | Positive–Unlabeled (PU) learning | Training with scarce attack labels + large unlabeled benign stream | Arif et al. (2024); Hu et al. (2024); Zhao et al. (2022) — *AdaPU* | **Strong** | Medium | — |
| 3 | Online / continual / concept-drift learning | Adapting IDS to evolving benign and adversarial behaviour | Ade & Desphande (2021); METANOIA (2025); CITADEL (2025); DDM-ORF (Laoudias et al., 2023) | Strong (adaptation) | Medium | — |
| 4 | Sequence models (LSTM, Transformer, causal-window attention) | Predicting the next technique; recognising attack chains | DeepOP (Wu et al., 2025); hybrid GNN+LSTM (Awotunde et al., 2025); Markov+LSTM chain prediction (Lukade, 2024) | — | **Strong** | — |
| 5 | Graph neural networks on provenance / asset graphs | Host/network context encoding, stage estimation | StageFinder (2026); unsupervised APT reconstruction (2026) | Medium | **Strong** | — |
| 6 | Deep Reinforcement Learning (DRL) classifier | Direct intrusion classification | Kurochkin & Volkov (2025); Wang et al. (2024); Liyanage et al. (2024) | Medium (no clear gain vs. supervised) | Weak | — |
| 7 | Deep RL from Human Feedback (DRLHF / RLHF) | Alert triage, deferral, prioritisation under feedback | Christiano et al. (2017); Ouyang et al. (2022); L2DHF (Hoang & Le, 2025); HARE (Sai & Dhaker, 2025) | **Strong** (in triage) | — | — |
| 8 | Retrieval-Augmented Generation with LLM | Mapping CTI text → techniques; generating recommendations | Lewis et al. (2020); TechniqueRAG (2025); H-TechniqueRAG (2026); AttacKG+ (2024) | Weak | Medium | **Strong** |
| 9 | Multi-agent LLM orchestration | Structured IR, report generation, mitigation synthesis | IRCopilot (Li et al., 2025); ICSSPulse (2026); Raptis et al. (2025) | — | Weak | **Strong** |

### 3.2 Why pure DRL is a weak fit for the primary detection objective

Wang et al. (2024) report that on NSL-KDD, DRL classifiers score
82–98 % accuracy, but the best supervised / ensemble baselines achieve
comparable numbers with substantially simpler training. The surveys
consistently identify four limitations that are highly relevant to the
GRFICS / Caldera setup:

* **Sparse rewards.** The user’s proposed reward signal
  (“attack-window + technique list”) is coarse. Many benign time-steps
  carry no informative reward; in RL this leads to slow convergence and
  reward-hacking (Wang et al., 2024, §5; Kurochkin & Volkov, 2025).
* **Credit assignment.** If only the entire window is labelled
  `under-attack`, the agent cannot easily attribute credit to individual
  log events, especially for non-obvious preparatory techniques (e.g.
  discovery → credential access → program upload). Supervised sequence
  models solve exactly this via categorical cross-entropy on each
  step (Lukade, 2024; Wu et al., 2025).
* **Off-policy evaluation in production.** ICS environments cannot
  tolerate exploration (an agent that “tries” to block legitimate
  traffic to see the reward may harm the plant). In RL vocabulary,
  exploration in this setting is unsafe. This is precisely why SOC
  literature moves toward *offline RL with human labels* (L2DHF) rather
  than classical on-policy DRL.
* **Concept drift and catastrophic forgetting.** METANOIA (2025) and
  CITADEL (2025) show that lifelong incremental learning with memory
  replay is a more principled response to drift than DRL with
  experience replay, which was *not* designed to protect previously
  learned concepts.

### 3.3 Why sequence / graph models are the right core

DeepOP (Wu et al., 2025) predicts multi-step ATT&CK sequences using a
transformer with a *causal window self-attention* — a pattern that fits
the chronological sequence of alerts fed by the correlation engine.
Lukade (2024) and the hybrid GNN+LSTM family (Awotunde et al., 2025)
show that combining local transition statistics (Markov), long-range
temporal memory (LSTM) and relational context (GNN over the MITRE graph
or the asset graph) yields AUC up to 0.99 on CIC-IDS2017 for chain
reconstruction. StageFinder (2026) operationalises the same recipe on
provenance graphs of alerts and observes that GNN-encoded graphs plus an
LSTM *stage estimator* map cleanly onto the ATT&CK kill-chain tactics.

The 2026 meta-alert reconstruction paper (“From logs to tactics …”)
closes the loop: it demonstrates that a *fully unsupervised* pipeline
using GNNs + LLM summarisation + transformer-embedding clustering +
a hybrid symbolic/BERT classifier mapped 87 % F1 of ATT&CK techniques
on the NATO Crossed Swords dataset, reducing analyst triage volume by
approximately 98 %. This is the closest published analogue to the
sequence/graph stage we propose.

### 3.4 Why RL still has a place — but only as the triage layer

Hoang & Le’s L2DHF (2025) gives the strongest published evidence that
DRLHF delivers real value when:

* The upstream predictor is already reasonably calibrated;
* A human (or a label proxy) provides verdict corrections;
* The action space is bounded and *safe* (accept / defer / adjust
  priority), not “block traffic”.

The HARE framework (Sai & Dhaker, 2025) adds a useful finding: feedback
is *most* effective in mid-to-late training, after initial policy
stabilisation. This supports our architecture, where RL is layered on
top of a supervised predictor.

### 3.5 Why the mitigation layer should be RAG + multi-agent LLM

Single-LLM prompting on mitigation questions *routinely* hallucinates
controls that are technically valid in IT but harmful in OT
(e.g. “reboot the PLC”, “drop all Modbus traffic”). RAG over the Neo4j
ATT&CK-for-ICS graph constrains the generator to the canonical
mitigations associated with the attributed techniques (Lewis et al.,
2020; TechniqueRAG, 2025). H-TechniqueRAG (2026) shows that the
tactic→technique hierarchy is a strong inductive bias for retrieval
efficiency. Finally, IRCopilot (Li et al., 2025) and ICSSPulse (2026)
show that decomposing the LLM’s work into roles — planning, generation,
analysis, reflection — materially reduces hallucinations, especially
when the downstream consumer is a human incident-response team.

---

## 4. Proposed implementation plan

### 4.1 Target architecture

```
          ┌──────────────────────────────────────────────────────────┐
          │  GRFICSv3 ICS simulation  +  Caldera attack executor     │
          └───────────────┬───────────────────────────┬──────────────┘
                          │ logs                      │ attack metadata
                          ▼                           ▼
               ┌─────────────────────┐     ┌─────────────────────┐
               │ Filebeat → Logstash │     │ Attack window label │
               │ → Elasticsearch     │     │  (benign / chain_id │
               └──────────┬──────────┘     │   + technique list) │
                          │                 └──────────┬──────────┘
                          ▼                            │
               ┌─────────────────────┐                 │
               │  Detection &        │                 │
               │  Correlation Engine │                 │
               │  (deterministic)    │                 │
               └──────────┬──────────┘                 │
                          │ candidate matches          │
                          ▼                            │
  ┌─────────────────────────────────────────────────────┐
  │  Layer A — Alert classifier (supervised / PU / CL)  │
  │  Input:  match features, event embeddings           │
  │  Output: P(true_positive | alert)                   │
  └──────────┬──────────────────────────────────────────┘
             ▼
  ┌─────────────────────────────────────────────────────┐
  │  Layer B — Chain / technique attributor             │
  │  Input:  sequence of alerts over window Δ          │
  │  Model:  Markov + causal-window Transformer + GNN   │
  │  Output: P(technique_k | alert_sequence, asset_ctx) │
  └──────────┬──────────────────────────────────────────┘
             ▼
  ┌─────────────────────────────────────────────────────┐
  │  Layer C — Triage RL (optional, DRLHF)              │
  │  State:   {alert, classifier.P, chain.P, context}   │
  │  Actions: {accept, defer to analyst, lower, raise}  │
  │  Reward:  label-based (benign/under-attack) &       │
  │           analyst feedback (AVAR-style)             │
  └──────────┬──────────────────────────────────────────┘
             ▼
  ┌─────────────────────────────────────────────────────┐
  │  Layer D — Mitigation RAG + multi-agent LLM         │
  │  Retrieval: Neo4j ATT&CK-for-ICS KG                 │
  │  Generation: Planner → Generator → Analyst →        │
  │              Reflector (IRCopilot pattern)          │
  │  Output:  contextualised mitigation plan            │
  └──────────┬──────────────────────────────────────────┘
             ▼
      Human-in-the-loop analyst review / SOC dashboard
```

The critical design principle: **the deterministic engine’s output is the
input to Layer A, not its replacement.** Layer A re-scores each candidate
match; Layer B converts the re-scored stream into chain-level
predictions; Layer C is a *policy* over the scored stream; Layer D only
produces natural-language recommendations.

### 4.2 Data labelling strategy

The label inputs are heterogeneous and must be reconciled carefully:

* **Window labels (L_t).** Coarse, always present. Encoded as a
  timestamp interval with fields `{label: benign | under_attack,
  chain_id, technique_list, attacker_assets, defender_assets}`.
* **Alert-level positives.** An alert *a_t* is treated as a *weak positive*
  for technique *τ* iff
  * *t* is within an `under-attack` window for a chain containing *τ*, **and**
  * the alert’s `asset_id` is in `attacker_assets ∪ defender_assets`, **and**
  * the alert’s matched DataComponent is in the set of DCs mapped (in
    MITRE ATT&CK for ICS) to *τ*.
* **Alert-level negatives.** Any alert inside a `benign` window is a
  *certain negative*.
* **Unlabelled alerts.** Alerts inside `under-attack` windows that do
  not satisfy the positive criteria are **unlabelled**, not negative —
  they may be pre/post-noise or weak side-effects.

This yields a **PU-learning** setup (Arif et al., 2024; Zhao et al., 2022)
that aligns well with the cybersecurity scarcity reported by Feng (2017)
for SIEM event prioritisation (AUC 0.96 with supervised PU). For
benign-only long runs, SELID (Kim et al., 2023) can cluster and select
a small, diverse label budget for periodic operator review (~2 % of
events re-labelled manually preserves F1 on intrusion datasets).

To avoid label contamination we impose:

* **Time-alignment skew.** Shift the window label ±15 s to absorb
  Caldera scheduling jitter and pipeline ingestion lag; events in the
  skew boundary are marked *ambiguous* and excluded from training but
  kept for evaluation.
* **Chain-ID provenance.** Every labelled positive keeps a pointer to
  the Caldera ability ID and adversary profile — this lets us do
  per-chain ablations and fault analysis.
* **Dataset schema (versioned, append-only).** One row per alert: alert
  fields, candidate DC, scoring evidence, window label, weak technique
  label(s), chain_id, label_source ∈ {window, analyst, agreement}.

### 4.3 Layer A — supervised / weakly-supervised alert classifier

**Task.** Binary classification `true_positive ∈ {0, 1}` with an
auxiliary multi-label head predicting the set of techniques.

**Features.** The deterministic engine already emits a structured
evidence object per match — reuse it directly: semantic score, keyword
score, log-source affinity, field match, category match, candidate
gate reason, weak-evidence flag, correlation group depth, asset
`is_ics_asset`, etc. Add contextualised text embeddings of the log
body using the same `BAAI/bge-small-en-v1.5` model the engine already
uses for semantic gating, so no new model pipeline is needed.

**Model.** Gradient-boosted trees (XGBoost or LightGBM) on the
structured features, with a shallow MLP over the concatenation of the
text embedding and a learned projection of the structured features.
This mirrors the PU-learning precedent in Arif et al. (2024), who
observed that ensembles dominate neural baselines for DDoS-in-cloud PU
classification. Use nnPU loss (Kiryo et al., 2017) or AdaPU (Zhao et
al., 2022) for the attack-positive / unlabelled-rest formulation.

**Calibration.** Calibrate probabilities via isotonic regression on a
held-out benign+attack split. Calibration is required for Layer C,
since the RL reward uses classifier confidence as part of the state.

**Online updating.** After the initial offline batch, move to an
**online / continual** regime with:

* a sliding-window replay buffer (FIFO by timestamp) per class,
* a concept-drift detector (ADWIN or DDM) on running classifier loss;
  this mirrors DDM-ORF (Laoudias et al., 2023) and the closed-loop CPS
  framework of Ade & Deshpande (2021),
* a CITADEL-style hierarchical memory to protect previously-learned
  benign classes against catastrophic forgetting (Dhanmeher et al.,
  2025).

### 4.4 Layer B — attack-chain recognition and technique attribution

**Input.** A sequence of (classifier-scored) alerts over a sliding
window of length *W* (e.g. 10 minutes or the last *N* alerts per asset
group — the existing correlation engine already maintains such groups).

**Representation.**

1. **Local graph snapshot** *G_t*: nodes = assets + alerts in the
   window; edges = {asset→alert (emitted by), alert→technique
   (candidate), alert→alert (correlated in engine group)}; node and
   edge features carry engine evidence and asset metadata. This is a
   minimalistic analogue of the provenance graph used by StageFinder
   (2026).
2. **GNN encoder** on *G_t* to produce per-alert embeddings
   *h_t^{(i)}*, using a GraphSAGE or a Heterogeneous GAT — the hybrid
   GNN+LSTM paper (Awotunde et al., 2025) and StageFinder both
   validate this choice.
3. **Sequence model** on the time-ordered *h_t*: either a
   bidirectional LSTM (Lukade, 2024) or a **causal window
   self-attention Transformer** à la DeepOP (Wu et al., 2025). The
   latter is preferred for the final version because it handles
   variable-length context and parallel paths natively.
4. **Heads.** (a) multi-label technique head with sigmoid cross-entropy
   (active techniques in the window), (b) chain-identification head
   (softmax over known Caldera chain IDs + an "unknown" class), (c)
   kill-chain-stage head (softmax over the seven ATT&CK for ICS
   tactics), following StageFinder.

**Auxiliary symbolic prior.** Inject MITRE’s tactic → technique
hierarchy and the asset-type ↔ DataComponent applicability map as a
masking prior on the output logits. The hierarchical retrieval
structure of H-TechniqueRAG (2026) can be reused here: restrict the
technique head to techniques known to be applicable for the matched
tactic + asset role.

**Training.** Use the weak labels derived in §4.2 and the Caldera
chain metadata. Loss combines per-step technique loss and a
sequence-level chain-identification loss, following Wu et al. (2025).

### 4.5 Layer C — RL alert triage (optional, DRLHF)

This layer is **optional**. It is only worth the engineering cost when
the stream of labels + analyst feedback is continuous. The formulation:

* **State** *s_t* = concatenation of:
  * Layer A calibrated probability,
  * Layer B top-k technique distribution,
  * alert evidence vector (kept short, ≤ 64 dims),
  * AVAR memory hit (has this alert-type been validated before?
    Hoang & Le, 2025),
  * system load indicator (open alerts, analyst queue length).
* **Action space** *A* = {*accept*, *defer_to_analyst*, *downgrade*,
  *upgrade*}. No environment-altering actions; crucially **no
  blocking / packet-drop actions** are in *A*, because such actions
  are unsafe in OT and would turn the agent from advisory into
  actuating, which ICS security guidance (NIST SP 800-82r3) treats as
  a separate, heavily-reviewed category.
* **Reward** *r_t*:
  * +1 if agent accepted a labelled positive alert, 0 otherwise;
  * −α if agent accepted a labelled negative alert
    (α tuned for desired FPR);
  * +β if `defer` and the analyst subsequently validated the
    deferred alert (β < 1 so the agent does not learn to defer
    everything);
  * −γ per `defer` to model analyst workload cost.
* **Algorithm.** Proximal Policy Optimization (PPO) or Deep Q-Network
  (DQN) with prioritised replay. L2DHF uses DRLHF (Christiano et al.,
  2017; Ouyang et al., 2022) — this is the most direct analogue for
  our setting where window labels act as a *reward model*.

**Safety rail.** Any alert that Layer A classifies as positive *with
confidence ≥ θ_high* must be accepted regardless of the RL agent’s
action. This enforces a floor on recall.

### 4.6 Layer D — mitigation RAG + multi-agent LLM

**Trigger.** Whenever Layer B attributes a technique *τ* with
probability ≥ θ_τ, Layer D is invoked.

**Retrieval.** Two-stage retrieval against Neo4j:

1. **Graph query.** For each attributed technique *τ*, retrieve
   `(Technique)-[:MITIGATED_BY]->(Mitigation)` and
   `(Technique)-[:DETECTED_BY]->(DataComponent)`, plus any
   `(Group)-[:USES]->(Technique)` and `(Software)-[:USES]->(Technique)`
   hits — so the generator sees which adversary profiles are
   consistent. (This is the H-TechniqueRAG recipe, adapted to the KG
   instead of a flat vector store.)
2. **Contextual vector retrieval.** Embed the alert triggering-event
   text and use it to pull the *k* most similar asset-role and
   historical-incident records from an internal vector store (for
   example, previous analyst notes linked by chain_id). This is the
   TechniqueRAG (Lekssays et al., 2025) recipe.

**Generation.** Adopt the **IRCopilot four-role decomposition**:

* **Planner.** Breaks the recommendation into sub-tasks: containment,
  eradication, recovery, hardening, monitoring improvements. Uses
  only the retrieved mitigation list and the environment metadata.
* **Generator.** For each sub-task, composes a concrete, ICS-safe
  action plan. Input is restricted to the Planner’s instructions and
  the retrieved context; the prompt forbids recommending actions not
  grounded in the provided mitigation IDs (cf. TechniqueRAG’s
  constraint of generating only from the re-ranked candidate set).
* **Analyst.** Uses a tree-of-thought prompt (Yao et al., 2023) to
  cross-check the plan against the asset inventory (e.g. “never
  suggest a restart on an asset whose role is `simulation` or `plc`
  while `phase=run`”).
* **Reflector.** Reviews the plan, requests clarifications, and
  emits the final report in two modes (executive and technical) —
  ICSSPulse (2026) demonstrated the value of this dual mode.

**Prompt guardrails.** Adopt the governance doctrine of Raptis et al.
(2025): pinned model versions, full audit log of prompts + retrieved
context, abstention when retrieval returns empty or contradictory
evidence, and a hard human-approval gate before any recommendation is
flagged “ready to execute”.

### 4.7 Training and evaluation workflow

**Stage 0 — Baseline freeze.**
Run the deterministic engine for *≥2 weeks* across benign and attack
windows, indexing every alert and its evidence. This becomes the
supervised-learning corpus.

**Stage 1 — Layer A offline training.**
Train the PU classifier. Evaluate TPR / FPR / F1 per DataComponent and
per chain; require FPR not to regress below the current deterministic
engine’s number.

**Stage 2 — Layer B offline training.**
Train sequence/graph model. Evaluate per-technique F1 and chain
identification accuracy. Reuse the DeepOP evaluation protocol (Wu et
al., 2025): top-*k* next-technique accuracy, and window-level
precision/recall per tactic.

**Stage 3 — Shadow deployment of Layers A + B.**
Run in parallel with the deterministic engine; emit a shadow-alert
channel that analysts can compare with the live channel. Correct
shadow alerts feed back into Layer A’s replay buffer.

**Stage 4 — Layer C pilot (optional).**
Deploy the RL triage agent in **advisory mode** (it suggests an action
but the deterministic channel remains authoritative). Collect analyst
feedback; follow HARE’s empirical guideline that feedback matters most
*after* policy stabilisation (Sai & Dhaker, 2025).

**Stage 5 — Layer D pilot.**
Deploy the RAG + multi-agent LLM in **read-only / recommendation-only**
mode. Validate mitigations against a held-out set of Caldera chains
and compare to the mitigations authored by the existing
**Techniques-and-Mitigations Prioritization Engine** (internal
project) as a ground-truth proxy.

**Stage 6 — Full hybrid.**
Layer A replaces the deterministic gating threshold with a learned
decision, Layer B replaces the ad-hoc chain heuristics with a
probabilistic attributor, Layer C runs in advisory, Layer D produces
SOC-visible recommendations. Safety rails (§4.5) remain active.

### 4.8 Evaluation methodology and metrics

**Detection quality (Layer A, Layer B).**

* **Per-alert TPR / FPR / precision / recall / F1**, both overall
  and per DataComponent, per chain, per tactic.
* **Technique-attribution accuracy:** top-1 and top-3 technique F1,
  following Wu et al. (2025) and H-TechniqueRAG (2026).
* **Chain identification accuracy:** exact-match and
  Hamming-distance over the predicted vs. executed technique list.
* **Detection latency:** time between the first in-chain log event
  and the first correctly attributed alert. Latency budgets of
  "<60 s per step" are conventional in SCADA IDS literature (Liyanage
  et al., 2024).

**Triage quality (Layer C).**

* **Mis-prioritisation rate** (proxy: share of high-priority alerts
  downgraded that later correspond to in-chain events), borrowing
  L2DHF’s evaluation (Hoang & Le, 2025).
* **Analyst workload:** defer rate, average time-to-verdict.
* **Policy stability:** policy entropy and KL-divergence drift across
  retraining epochs — this is the RL-specific stability metric.

**Recommendation quality (Layer D).**

* **Coverage:** share of MITRE-recommended mitigations for the
  attributed techniques that appear in the LLM output.
* **Grounding / faithfulness:** ratio of generated sentences whose
  claims are backed by the retrieved context (Lewis et al., 2020 and
  follow-up RAG faithfulness literature).
* **Specificity:** ratio of mitigations tailored to the environment’s
  asset inventory vs. generic ATT&CK text.
* **Hallucination rate:** fraction of recommendations not mappable to
  any retrieved mitigation ID; target zero, enforced by the
  Generator’s constrained-decoding prompt.
* **Safety audit:** reviewer-scored proportion of recommendations
  that are *safe to apply in OT without additional caveats*.

**Overall system KPIs.**

* FPR reduction vs. the deterministic-only baseline (target: ≥50 %
  at equal TPR, comparable to L2DHF);
* Precision@K on chain-level notifications;
* Mean time-to-mitigation-draft (MTTD) from chain detection to an
  analyst-reviewable recommendation.

### 4.9 Risks and mitigations

| Risk | Source | Mitigation |
|---|---|---|
| **Sparse rewards** (many benign windows, few chains) | Layer C RL | Use DRLHF / L2DHF instead of pure online RL; shape reward with analyst feedback; pre-train Layer A to supply dense confidence signal. |
| **Noisy labels** (timestamp skew, side-effect events) | Layer A / B | Skew-window exclusion (§4.2); PU-learning loss (nnPU / AdaPU); disagreement-based re-labelling via SELID. |
| **Concept drift** (OT routine changes, new firmware) | All layers | ADWIN/DDM drift detector + METANOIA-style pseudo-edges to resist catastrophic forgetting; scheduled benign-only recalibration. |
| **Attack realism / synthetic bias** | Caldera only | Supplement with literature attack datasets (e.g. CIC-ICS) and blue-team exercises; report out-of-distribution F1 separately. |
| **LLM hallucination** | Layer D | Retrieval grounding, constrained decoding, IRCopilot role decomposition, abstention on empty retrieval, pinned model versions. |
| **Unsafe automation in OT** | Layer C / D | No actuating actions in Layer C; mandatory human approval before any Layer D recommendation is executed. |
| **Privacy / IP leakage to external LLM** | Layer D | Prefer on-premise inference (e.g. vLLM-hosted open-weight models); redact asset identifiers. |
| **Adversarial drift** (attacker learns the detector) | Layer A / B | Regular red-team runs; ensemble + randomised feature subsets; monitor class-conditional feature drift. |
| **Catastrophic forgetting on online updates** | Layer A | Replay buffer + elastic weight consolidation or CITADEL-style hierarchical memory. |
| **Reward hacking** (RL exploits label jitter) | Layer C | Human approval of aggregated policy changes before deployment; monitor defer-rate and accept-rate sanity bounds (Hoang & Le, 2025). |

---

## 5. Better alternatives and hybrids

Several designs should be considered as **safer**, simpler, or more
evidence-backed alternatives to the full RL-centric design the user
initially proposed.

### 5.1 Alternative 1 — Supervised sequence model + RAG (no RL)

Drop Layer C entirely. The system becomes:

* Layer A (PU classifier),
* Layer B (causal-window Transformer / hybrid GNN+LSTM), and
* Layer D (RAG + multi-agent LLM).

This is the **minimum-viable** learning-enhanced system and maps
directly onto well-published precedents (DeepOP, StageFinder, hybrid
GNN+LSTM, TechniqueRAG, IRCopilot). It preserves >90 % of the expected
benefit with substantially less operational risk. RL can be added
later when the analyst feedback loop is mature.

### 5.2 Alternative 2 — Bandit-based threshold tuning

Replace Layer C with a **contextual multi-armed bandit** that only
tunes the engine’s thresholds (`alert_threshold`,
`correlation_entry_threshold`, `per_asset_dc_rate_max_alerts`, …) per
asset class, given labelled windows as the reward. This is what much
of the SOC-tuning literature actually does, even when called “RL”,
because the decision is a low-dimensional continuous parameter. It
inherits the theoretical regret guarantees of LinUCB / Thompson
sampling and avoids the credit-assignment hazards of DRL.

### 5.3 Alternative 3 — Unsupervised meta-alert pipeline

Follow the 2026 *“From logs to tactics”* blueprint: use a GNN on the
alert provenance graph + transformer embedding clustering + a hybrid
BERT/symbolic mapper to produce ATT&CK-enriched meta-alerts, with no
RL at all. This works especially well in the data-scarce regime (few
labelled chains) and was validated on the NATO Crossed Swords exercise
with 87 % F1 and ~98 % reduction in analyst triage volume.

### 5.4 Alternative 4 — Human-feedback-only supervised loop

A production-oriented alternative that is pragmatic in OT: surface
every alert to the analyst, record verdict corrections, and feed those
corrections into Layer A as additional labelled examples. This is the
Radiant-Security-style “continuous feedback loop” pattern (Radiant
Security, 2024) and, per industry case studies, yields 38–80 % FPR
reduction within 90 days — without any RL formalism. This should be
treated as the *operational backbone*; the other layers sit on top.

### 5.5 Hybrid recommendation

Implement **Alternative 4 as the baseline**, layer **Alternative 1 on
top** once data volume allows, and **add Alternative 2 (bandit
threshold tuning)** as the optional adaptive component. Keep RL/DRLHF
(Layer C) as a later, opt-in upgrade path rather than a day-one
dependency.

---

## 6. Final recommendation

1. **The user’s original framing should be adjusted.** The core
   learning problem is *not* a reinforcement-learning problem; it is a
   weakly-supervised classification and sequence-labelling problem,
   for which supervised, PU, sequence and graph models have direct,
   well-validated precedents.

2. **RL should be scoped to the alert-triage layer.** Use the L2DHF /
   DRLHF pattern (Hoang & Le, 2025; Christiano et al., 2017) with
   analyst / window labels as the reward. Exclude environment-altering
   actions from the action space for OT safety (NIST SP 800-82r3;
   Raptis et al., 2025).

3. **An LLM is the correct tool for mitigation contextualisation.**
   Use **Retrieval-Augmented Generation** against the MITRE ATT&CK for
   ICS knowledge graph, with the **IRCopilot multi-agent decomposition**
   for hallucination control (Li et al., 2025). Hierarchy-aware
   retrieval (H-TechniqueRAG, 2026) is recommended for efficiency and
   precision. The mitigation pipeline must have a human-in-the-loop
   gate.

4. **The architecture should be implemented in stages.** Start with
   the supervised / weakly-supervised classifier (Layer A) and the
   sequence/graph attributor (Layer B). These alone are expected to
   deliver the largest improvements in FP reduction and technique
   attribution. Add the RL triage (Layer C) and full multi-agent LLM
   recommendation (Layer D) only after the earlier layers stabilise.

5. **Safety first.** No autonomous blocking, no autonomous PLC / HMI
   actions. LLM-proposed mitigations must be auditable, version-pinned,
   grounded in retrieved content, and analyst-approved. Raptis et al.
   (2025) provide the most directly applicable governance checklist.

6. **Evaluate rigorously.** Alongside classical IDS metrics, report
   per-technique F1, chain identification accuracy, detection latency,
   analyst defer-rate (if Layer C is deployed), mitigation coverage /
   faithfulness / hallucination (Layer D), and safety-audit ratings.
   Out-of-distribution evaluation (non-Caldera attack traffic, novel
   chains) is mandatory for any claim of generalisation.

A final practical note: the GRFICS + Caldera setup is an excellent
laboratory for this program, because both the logs and the ground truth
are repeatable. The combination of (i) a reproducible environment, (ii)
a structured detection engine emitting rich evidence per alert, (iii) a
canonical MITRE ATT&CK for ICS knowledge graph, and (iv) modern RAG /
multi-agent LLM techniques is, in the current state of the literature,
close to ideal for building and scientifically evaluating a
learning-enhanced ICS detection-and-mitigation-recommendation system.

---

## 7. References

1. Ade, R., & Deshpande, M. (2021). *Continuous detection of concept
   drift in industrial cyber-physical systems using closed-loop
   incremental machine learning.* **Discover Artificial Intelligence**,
   1. DOI 10.1007/s44163-021-00007-z.
2. Alexander, O., Belisle, M., & Steele, J. (2020). *MITRE ATT&CK® for
   Industrial Control Systems: Design and Philosophy.* The MITRE
   Corporation.
3. Arif, A., Javaid, S., & Khan, L. (2024). *Applications of Positive
   Unlabeled (PU) and Negative Unlabeled (NU) Learning in
   Cybersecurity.* arXiv:2412.06203.
4. Awotunde, J. B., Abiodun, O. I., Jimoh, R. G., et al. (2025).
   *A Hybrid Approach Using Graph Neural Networks and LSTM for Attack
   Vector Reconstruction.* **Computers**, 14(8), 301. MDPI.
5. Christiano, P., Leike, J., Brown, T., Martic, M., Legg, S., &
   Amodei, D. (2017). *Deep Reinforcement Learning from Human
   Preferences.* NeurIPS 30.
6. Dhanmeher, M., et al. (2025). *CITADEL: Continual Anomaly Detection
   for Enhanced Learning in IoT Intrusion Detection.*
   arXiv:2508.19450.
7. Feng, Y. (2017). *Supervised PU Learning for Cyber Security Event
   Prioritization.* **DEStech Transactions on Computer Science and
   Engineering**.
8. Formby, D., Rad, A., & Beyah, R. (2018). *Lowering the Barriers to
   Industrial Control System Security with GRFICS.* USENIX ASE’18.
9. Hoang, L., & Le, T. (2025). *Adaptive alert prioritisation in
   security operations centres via learning to defer with human
   feedback.* arXiv:2506.18462.
10. Hu, X., et al. (2024). *Harnessing PU Learning for Enhanced
    Cloud-based DDoS Detection: A Comparative Analysis.*
    arXiv:2410.18380.
11. Karacan, H., & Ghafir, I. (2026). *ICSSPulse: Automated Penetration
    Testing Platform for ICS with LLM-assisted ATT&CK reporting.*
    arXiv:2602.20663.
12. Kalpani, N., Rodrigo, N., Seneviratne, D., et al. (2025).
    *Cutting-edge approaches in intrusion detection systems: a
    systematic review of deep learning, reinforcement learning, and
    ensemble techniques.* **Iran Journal of Computer Science**, 8,
    303–333. DOI 10.1007/s42044-025-00246-8.
13. Kim, J., Park, S., & Cho, Y. (2023). *SELID: Selective Event
    Labeling for Intrusion Detection Datasets.* **Sensors**, 23(13),
    6105. MDPI.
14. Kiryo, R., Niu, G., du Plessis, M. C., & Sugiyama, M. (2017).
    *Positive-Unlabeled Learning with Non-Negative Risk Estimator.*
    NeurIPS 30.
15. Kurochkin, I., & Volkov, S. (2025). *Reinforcement-Learning-Based
    Intrusion Detection in Communication Networks: A Review.* **IEEE
    Communications Surveys & Tutorials**, 27(4).
    DOI 10.1109/COMST.2024.3484491.
16. Laoudias, C., et al. (2023). *Intrusion Detection based on Concept
    Drift Detection & Online Incremental Learning (DDM-ORF).*
    ResearchGate preprint 376256252.
17. Lekssays, A., et al. (2025). *TechniqueRAG: Retrieval-Augmented
    Generation for Adversarial Technique Annotation in Cyber Threat
    Intelligence Text.* arXiv:2505.11988.
18. Lewis, P., et al. (2020). *Retrieval-Augmented Generation for
    Knowledge-Intensive NLP Tasks.* NeurIPS 33.
19. Li, Q., et al. (2025). *IRCopilot: Automated Incident Response
    with Large Language Models.* arXiv:2505.20945.
20. Liyanage, K., et al. (2024). *Leveraging Deep Reinforcement
    Learning Technique for Intrusion Detection in SCADA
    Infrastructure.* **IEEE Access**, 10504835.
21. Lukade, R. R. (2024). *Attack chain contraction and prediction
    using Markov chain and LSTM.* MSc thesis, UMass Dartmouth.
22. MITRE Corporation. (2023). *MITRE ATT&CK for ICS Matrix (v14).*
    attack.mitre.org.
23. NIST. (2023). *Guide to Operational Technology (OT) Security
    (SP 800-82r3).*
24. Ouyang, L., et al. (2022). *Training language models to follow
    instructions with human feedback.* NeurIPS 35.
25. Raptis, C., et al. (2025). *Analysing the role of LLMs in
    cybersecurity incident management.* **International Journal of
    Information Security**. DOI 10.1007/s10207-025-01144-7.
26. Sai, R., & Dhaker, K. (2025). *Human-in-the-Loop Reinforcement
    Learning Framework for Adaptive Phishing Detection (HARE).*
    **Discover Computing**. DOI 10.1007/s10791-025-09849-y.
27. *StageFinder: Temporal-Graph Learning for Multi-Stage Attack
    Progression Inference.* (2026). arXiv:2603.07560.
28. Wang, J., et al. (2024). *A Survey for Deep Reinforcement
    Learning Based Network Intrusion Detection.* arXiv:2410.07612.
29. Wang, Y., et al. (2026). *From logs to tactics: unsupervised
    reconstruction of APT campaigns with MITRE-enriched meta-alerts.*
    **International Journal of Information Security**.
    DOI 10.1007/s10207-026-01254-w.
30. Wu, H., Wang, X., & Liu, Q. (2025). *DeepOP: A Hybrid Framework
    for MITRE ATT&CK Sequence Prediction via Deep Learning and
    Ontology.* **Electronics**, 14(2), 257. MDPI.
31. Yao, S., et al. (2023). *Tree of Thoughts: Deliberate Problem
    Solving with Large Language Models.* NeurIPS 36.
32. Zhang, L., et al. (2024). *AttacKG+: Boosting Attack Knowledge
    Graph Construction with Large Language Models.* arXiv:2405.04753.
33. Zhang, Y., et al. (2026). *H-TechniqueRAG: Hierarchical
    Retrieval-Augmented Generation for Adversarial Technique
    Annotation.* arXiv:2604.14166.
34. Zhao, Y., et al. (2022). *AdaPU: Boosting for Positive-Unlabeled
    Learning.* arXiv:2205.09485.
35. Zheng, R., et al. (2025). *METANOIA: A Lifelong Intrusion Detection
    and Investigation System for Mitigating Concept Drift.*
    arXiv:2501.00438.

---

*Document version 1.0 — prepared for internal review within the
MITRE ATT&CK for ICS Detection & Correlation Engine project.*
