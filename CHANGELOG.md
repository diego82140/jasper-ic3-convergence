# What's new

## v2.0.0 (2026-10-20)

Installs side by side with the original: `jasper-ic3-convergence-v2` (this) and `jasper-ic3-convergence`
(1.3.0, frozen under `v1/`). Skill: `/jasper-ic3-convergence-v2:jasper-ic3-convergence`.

**Method (design-independent)**
- *Structural analysis first.* Before any telemetry, the agent reads the RTL that produces the
  assertion's antecedent and the RTL that owns its consequent and writes their stage-wise relations
  (phase, single occupancy, held copy, no-early-event, decision consistency) as the first candidate
  family, with base case and step case kept apart.
- *Relevance rule.* A helper is admitted only for a named consumer and with a relevance witness
  (it implies the consumer, or it excludes a counterexample to induction of the consumer). True but
  consumer-free facts are not proved. A helper with no measured benefit is retired from that
  experiment, nothing more is concluded from one run.
- *Witness search before a long proof.* A candidate's negation is covered with a bounded,
  seeded search before time is spent proving it; `covered` refutes the candidate in seconds.
- *Seeded failures are candidate counterexamples* until they are one native trace from reset
  (the two admissible forms are stated).
- *Depth ladder vs. relation family.* The telemetry reading distinguishes a frontier that is only
  bounding the depth of the antecedent from one that recurs on the target's own relation.
- *No run is unlimited.* Every run has a budget derived from evidence: an experiment (≤ 4 h), the
  project's own baseline at its native limit, or a cold replay budgeted from a bounded basis run
  of the same proof graph. "Time makes nothing inductive" is now a rule the tools check.

**Tools and gates**
- `slurm/submit.sh`: `BUDGET=` with class `experiment` | `baseline` | `replay`; every job gets a
  Slurm time limit (budget + margin); the console telemetry sink is refused (not qualifiable).
- `tools/prove_gate.py` (bounded proves in Tcl), `tools/graph_ready.py` (replay receipts tied to
  the basis run's own result lines), `tools/audit.py` (end-of-round audit; also the plugin's Stop
  hook: it refuses to end a turn while an unlabelled or over-budget run is live),
  `tools/jg_results.py` (result, Cache and watchdog lines from a run log).
- Hooks: a poll guard on `Bash` and the Stop audit. Evals: five behaviour cases under `evals/`.
- Run directories stay world-readable on the shared filesystem (`umask 022`).

**Documentation**
- `AGENTS.md` is the contract; `references/inductiveness-method.md` the theory behind it;
  `references/site-profile.md` the site-specific values; `references/validation.json` the
  evidence (reviews, blind trials, qualification receipts, install test).

## v1.3.0

Original published method: M/M4 telemetry, CTI families, sound helper invariants, status-gated
proof graphs, Slurm execution.
