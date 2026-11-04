# What's new

## v3.0.0 (2026-11-03, pending merge)

- Use the distinct `jasper-ic3-convergence-v3` name; retain frozen v1 and pin v2
  to its published revision. The general inductiveness method is unchanged.
- Include the updated Jasper adapters and complete disk/SQLite telemetry.
- Validate actual agent reading of seven 5,233-literal page-walker CTIs and a
  protocol-rich CHI capture. Correct observed format/width/query-scope ambiguities
  and add a focused provenance regression. See [agent validation](references/v3-agent-cti-reading.md).
- Add the `examples/wide-cti` fixture with native wide-CTI evidence on all four
  builds, and clarify question-scoped decoding, provenance and existential
  completions in the agent instructions. See [wide native evidence](references/v3-fresh-wide-native.md).
- Native qualification and direct finite CTI parity remain separately recorded;
  no new target closure or general memory bound is claimed.

## Telemetry compatibility included in v3.0.0

This unpublished v2.0.1 work became part of v3.


- Add exact-build telemetry adapters for production Jasper `2026.09` and
  `2026.09p001`, including native validation/caller attribution, Formula tables
  and report callbacks. Keep the existing June and September prerelease profiles
  unchanged; unknown workers still fail closed.
- Fix a queue-delta bug: reuse of a list-node address for another obligation no
  longer hides removal of its prior membership. A regression rejects the old
  predicate deliberately.
- Qualify all four exact workers: 32 M/M4 native baseline/preload proof/CEX
  checks pass, including June. Reuse matching receipts rather than repeat them.
- Verify direct CTI data on five pinned models/M/M4/three September builds
  against the old Dollar/producer1.5 oracle and fresh producer1.6.13: complete
  raw words, decoded constrained bits, named CTIs, predecessor pairs, query
  semantics and ordered frames (including empty frames). 203 prior automated
  tests, 10 new comparator tests and 12 actual-data negative controls pass.
- Preserve the historical raw allocator-address-history FAIL separately; no
  universal native lifetime or all-design equivalence is claimed. June retains
  its older named-display limitation. Full compressed telemetry remains on disk;
  final direct analysis sampled 37.6 MiB RSS, not a solver memory guarantee.

See [compatibility](references/2026-09-compatibility.md),
[current CTI results](references/2026-09-cti-agent-parity.md) and
[independent review dispositions](references/2026-09-review.md).

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
