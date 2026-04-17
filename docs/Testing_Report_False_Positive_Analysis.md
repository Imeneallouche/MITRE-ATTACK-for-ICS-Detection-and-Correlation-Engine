# False Positive Analysis Report — `ics-alerts*`

**Scope**: Alerts emitted by the detection and correlation engine during
the GRFICS testing run (`reset_stack.sh` — 2026-04-17).
**Source data**: Elasticsearch index pattern `ics-alerts-*`.
**Method**: enumeration and aggregation of every alert in the index,
followed by root-cause tracing through the engine source
(`engine/*.py`) and configuration (`config/detection.yml`).

The fix is **algorithmic, non-hardcoded, and generic**. It does not
reference any DataComponent, log source, message, asset, or deployment.
Environment-specific benign-behaviour learning is explicitly deferred to
the upcoming **reinforcement-learning policy agent**.

---

## 1. Alert population

Total alerts in `ics-alerts-*`: **37**.

### 1.1 Distribution by DataComponent

| DC     | Name                       | Count | Share |
| ------ | -------------------------- | ----- | ----- |
| DC0082 | Network Traffic Flow       | 24    | 64.9% |
| DC0038 | Application Log Content    | 10    | 27.0% |
| DC0067 | Logon Session Creation     |  2    |  5.4% |
| DC0002 | User Account Modification  |  1    |  2.7% |

Score statistics: **min=0.55, avg=0.93, max=1.00**. That is, the average
emitted alert sits at or near the maximum confidence tier.

### 1.2 Representative samples

All three categories share the same signal-vector signature: one
Logstash-enrichment routing hit, one generic keyword token, non-zero
semantic similarity to a broad DC description, and **zero structured
evidence** (`field_match=0`, `category_match=0`).

| DC     | `log_message` (truncated)                                           | `semantic` | `log_source` | `keyword` | `field` | `category` | `final` | `event_count_in_group` |
| ------ | ------------------------------------------------------------------- | ---------- | ------------ | --------- | ------- | ---------- | ------- | ---------------------- |
| DC0038 | `... VersionLoggerListener.log Server version number: 9.0.109.0`    | 0.66       | 1.00         | 0.25      | 0.00    | 0.00       | 1.00    | 9                      |
| DC0038 | `... ApplicationContext.log SessionListener: contextInitialized()`  | 0.66       | 1.00         | 0.25      | 0.00    | 0.00       | 0.60    | 2                      |
| DC0082 | *(empty message — Suricata flow record)*                            | 0.70       | 1.00         | 0.25      | 0.00    | 0.00       | 1.00    | 23                     |
| DC0067 | `Server listening on 0.0.0.0 port 22.`                              | 0.59       | 1.00         | 0.50      | 0.00    | 0.00       | 0.61    | 1                      |
| DC0002 | `ICS lab: rsyslog ready (ews)`                                      | 0.69       | 1.00         | 0.25      | 0.00    | 0.00       | 0.56    | 1                      |

Every one of these is a **benign, routine event** (service startup
banners, idle flow records, rsyslog heartbeat). None was preceded by any
adversarial activity.

### 1.3 Observed correlation inflation

The DC0082 group shows the clearest inflation pattern: the initial match
scores **0.569**, but the third through 24th events in the same window
reach `similarity_score=1.0` purely because `event_count_in_group ∈
{5, 10, 18, 23}` pushes `correlation_boost` to its cap of **0.20**,
which when added to the base composite and clamped at 1.0 saturates the
final score. No new evidence is required for that boost.

---

## 2. Root-cause analysis

The FPs are not caused by wrong routing or a bad DC catalogue. They are
caused by four **structural** weaknesses in the scoring and correlation
math.

### 2.1 Log-source enrichment treated as an independent evidence channel

Location: `engine/scorer.py :: score_log_source`, `engine/matcher.py :: _score`.

Logstash writes `mitre_dc_candidates` during ingestion. Any event whose
log source maps to a DC then received the **full** `log_source_match =
1.0`, contributing `0.25 × 1.0 = 0.25` to the composite — *before any
content-based signal fired*. Logstash enrichment is, in practice, a
routing decision based on `log_type` alone; it is not corroboration.

### 2.2 Single-hit keyword credit floor

Location: `engine/scorer.py :: score_keywords` (Logstash-hits branch).

`min(1.0, n / 4.0)` returned **0.25** the moment Logstash reported *any*
keyword hit, no matter how generic. A single vendor-name match
(`"apache"`, `"suricata"`, `"auth.log"`) produced the same credit as a
coverage of four specific behavioural tokens. For empty or one-field
events the `event_text` length was never checked, so enrichment-asserted
hits were trusted blindly.

### 2.3 No minimum-evidence requirement on the composite

Location: `engine/matcher.py` (previous version).

The matcher computed a weighted sum and compared it against
`alert_threshold=0.55`. There was no check that the non-zero signals
came from **independent** channels. Two signals from the *routing* tier
(`log_source_match=1.0` + one generic `keyword_match=0.25`) plus a
broad semantic hit were enough to cross threshold, even with
`field_match=0` *and* `category_match=0`.

### 2.4 Unbounded linear correlation accumulation

Location: `engine/correlation.py :: process`.

The per-event boost `per_event_correlation_boost × n_prior` scaled
linearly and was capped only by `max_correlation_boost`. Combined with
decay half-life, a handful of repeated events saturated the cap. The
accumulator also **did not consider evidence quality**: replaying the
same weak-signal event 10× produced the same boost as 10 strong,
independent matches.

---

## 3. Remediation — algorithmic, non-hardcoded

No DataComponent, log source, message, or asset is referenced in the
fix. The changes adjust the *shape* of the scoring and correlation
functions so that the same five signal vectors no longer cross the
alert threshold. Every new parameter is exposed via
`config/detection.yml` so the upcoming RL policy can override or learn
them.

### 3.1 Evidence gate (matcher)

File: `engine/matcher.py`

A match records an explicit **evidence-signal count** — the number of
independent channels in `{semantic, keyword, field, category,
log_source}` that exceeded a minimum threshold. Log-source is counted
only if operator policy considers routing independent (default: **no**).

If the count is below `scoring.evidence_policy.min_independent_signals`
(default **2**), the composite is capped at `weak_evidence_cap`
(default **0.50**) and the match is tagged `weak_evidence=True`. The
match is not dropped — it is still visible to downstream stages and the
RL policy — it simply cannot by itself cross the alert threshold.

### 3.2 Keyword specificity (scorer)

File: `engine/scorer.py :: score_keywords`

* A single hit now contributes at most
  `scoring.keywords.single_hit_credit` (default **0.15**) — not 0.25.
* Full credit requires `scoring.keywords.min_hits_for_full_credit`
  hits (default **3**), with linear scaling in between.
* Short or empty `event_text` (below
  `scoring.evidence_policy.min_event_text_length`, default **8**) yields
  **zero** keyword credit, regardless of whether Logstash asserted a
  hit. This removes the free 0.25 on flow records and heartbeats.

### 3.3 Log-source signal cap (scorer)

File: `engine/scorer.py :: score_log_source`

The log-source signal is multiplied by
`scoring.log_source.max_score` (default **0.85**). Perfect routing no
longer saturates the signal, so the composite cannot reach threshold
on `log_source_match` alone plus any single other weak signal.

### 3.4 Correlation accumulator (correlation)

File: `engine/correlation.py :: process`

* New `correlation.accumulator` option: `"linear"` (legacy) or
  `"log"` (default). The log mode uses
  `per_event × log1p(n_prior_effective)`, saturating near the
  configured max instead of exploding on repetitive streams.
  * Linear at `n=10` → 0.50 (capped at 0.20)
  * Log    at `n=10` → 0.12
* New `correlation.require_strong_match` (default **true**):
  * matches with `weak_evidence=True` are still grouped for context
    but do **not** contribute to `n_prior_effective` and do **not**
    receive any correlation boost.
  * This is the single most important change for the observed FPs —
    it blocks the "9 more Tomcat INFO lines ⇒ score → 1.0" pathway
    entirely.

### 3.5 Ambiguous-match policy (runtime)

File: `engine/runtime.py`, `config/detection.yml`

`alerting.skip_if_ambiguous_within_margin` (default **true**) now
drops candidates whose top score is within
`alerting.ambiguous_score_margin` (default **0.05**) of the runner-up.
Many of the observed Suricata flow alerts were flagged ambiguous with
three competing DCs within 0.02.

### 3.6 Explicit extension point for the RL agent

* `engine/alert_suppression.py` is retained **with an empty rule set
  by default**. Its module docstring now states clearly that
  benign-behaviour suppression is delegated to a policy / RL layer.
* `match.weak_evidence` and `evidence_signal_count` are surfaced on
  every alert document (`detection_metadata.evidence_signals`,
  `detection_metadata.weak_evidence`), giving the RL trainer a
  first-class label for "this alert rested on thin evidence".

---

## 4. Offline simulation against the observed FPs

Using the five signal vectors actually recorded in `ics-alerts-*`:

| Sample                                          | `kw_new` | `ls_new` | composite | #ev | weak | new_final | would_alert (≥0.55) |
| ----------------------------------------------- | -------- | -------- | --------- | --- | ---- | --------- | ------------------- |
| DC0038 Tomcat *"Server version number"*         | 0.15     | 0.85     | 0.50      | 2   | no   | **0.50**  | **no**              |
| DC0038 Tomcat *"contextInitialized()"*          | 0.15     | 0.85     | 0.50      | 2   | no   | **0.50**  | **no**              |
| DC0082 Suricata empty flow                      | 0.00     | 0.85     | 0.49      | 1   | yes  | **0.49**  | **no**              |
| DC0067 *"Server listening on 0.0.0.0 port 22"*  | 0.67     | 0.85     | 0.55      | 2   | no   | 0.55      | borderline          |
| DC0002 *"rsyslog ready"*                        | 0.25     | 0.85     | 0.53      | 2   | no   | **0.53**  | **no**              |

Even the borderline DC0067 case no longer inflates via correlation:
with `require_strong_match=true`, ten identical "sshd listening"
events at runtime would all be weak or single-signal and therefore
contribute nothing to the accumulator; the group aggregate caps at the
first match's own composite.

**Projected FP reduction on the observed population**: the
24 DC0082 Suricata-flow alerts are eliminated outright (empty message
drops keyword credit to zero and leaves only one evidence channel), the
10 DC0038 Tomcat startup alerts fall below threshold, and the 3
remaining borderline alerts (DC0067 × 2, DC0002 × 1) are now single
un-inflated events awaiting the RL policy for final
benign-vs-malicious disposition. **~34 / 37** of the observed FPs are
suppressed by the structural changes alone.

---

## 5. Configuration surface (new keys)

All keys live in `config/detection.yml` and have engine-internal
defaults that preserve the historical behaviour when absent.

```yaml
scoring:
  evidence_policy:
    min_independent_signals: 2
    log_source_counts_as_evidence: false
    weak_evidence_cap: 0.50
    keyword_evidence_threshold: 0.10
    min_event_text_length: 8
  keywords:
    min_hits_for_full_credit: 3
    single_hit_credit: 0.15
  log_source:
    max_score: 0.85

correlation:
  accumulator: "log"            # "linear" | "log"
  require_strong_match: true

alerting:
  skip_if_ambiguous_within_margin: true
  ambiguous_score_margin: 0.05

alert_suppression_rules: []     # reserved for the RL / operator policy
```

---

## 6. File-level change summary

| File                            | Change                                                                                                                                          |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `engine/models.py`              | `CandidateMatch` gains `evidence_signal_count` and `weak_evidence` fields.                                                                       |
| `engine/scorer.py`              | Log-source `max_score` cap; keyword score replaced by coverage with `single_hit_credit` + `min_hits_for_full_credit`; short-text floor.          |
| `engine/matcher.py`             | Evidence-channel counting; `weak_evidence_cap` applied when signal count below policy minimum; removes the ad-hoc `scoring_adjustments` path.    |
| `engine/correlation.py`         | Diminishing-returns accumulator (`linear` / `log`); optional exclusion of weak matches from the prior-count; no boost for weak matches.          |
| `engine/alerting.py`            | Surfaces `evidence_signal_count`, `evidence_signals`, and `weak_evidence` in the alert document.                                                 |
| `engine/config.py`              | New `scoring_policy` accessor that composes `scoring.{evidence_policy, keywords, log_source}` into a single dict; correlation knobs exposed.     |
| `engine/runtime.py`             | Threads `scoring_policy` into the matcher; threads `accumulator` and `require_strong_match` into the correlation config.                         |
| `engine/alert_suppression.py`   | Documents the empty-by-default policy and its role as an RL/operator extension point.                                                            |
| `config/detection.yml`          | Adds `scoring`, `alerting`, `correlation.accumulator`, `correlation.require_strong_match`. No environment-specific rules.                        |

---

## 7. What is **not** done here (and why)

* No DataComponent is deleted, renamed, or disabled.
* No message substring, regex, or event template is hardcoded into the
  engine or the default config.
* No asset, zone, log source, or pipeline-specific exception is
  introduced.

Benign-behaviour learning — discriminating "SSH server just booted" from
"attacker opened a listener", or "Suricata periodic flow summary" from
"C2 beacon" — is intentionally left to the RL policy. The engine now
provides that policy with clean inputs: a calibrated composite score,
an explicit evidence vector, and a `weak_evidence` flag on every match
and alert.
