# Inductiveness method (design-agnostic)

This note is the theory behind AGENTS.md §3–§7 for a safety target `P` on a transition system
`(I, T)` whose `T` already includes the project's environment assumptions. It names the proof
obligations, how candidate relations are built from RTL structure, what each native result
certifies, and which claims the method does *not* make. It prescribes no signal vocabulary,
helper template or design.

## 1. What a proof needs, and what the engine's objects are

A safety proof of `P` is an inductive strengthening `H` with `I ⇒ H`, `H ∧ T ⇒ H'` and
`H ⇒ P`. Inductive strengthenings are not unique; a proof found by IC3/PDR is one of many.

IC3/PDR keeps frames `F_0 = I`, `F_1`, …, `F_k` with `F_i ⊇ R_i` (the states reachable in at
most `i` steps) and `F_i ⊆ F_{i+1}`; in Bradley's formulation `F_i ⇒ P` for `i < k`, while
other PDR variants let the frontier hold bad states until they are blocked. Its search objects
are *proof obligations*: a cube `s` with `F_i(s) ∧ T(s, s') ∧ ¬P(s')` (or `¬c(s')` for a cube
`c` already being blocked). Such an `s` is a *counterexample to induction* (CTI) of the current
frame. A CTI may be reachable — then the target or the clause being pushed is false — or
unreachable. Blocking `s` at level `i` (`F_{i-1} ∧ ¬s ∧ T ⇒ ¬s'`, with `s ∉ I`) shows only that
`s` is unreachable within `i` steps relative to `F_{i-1}`; the reachability of `s` is settled only
by a trace back to `I` or by a frame that becomes inductive. Blocking adds a generalization of
`¬s` to the frames up to `i`. A frontier clause is therefore an exclusion retained relative to a
frame, never by itself an invariant, and its literal count or frequency is not a cost
measurement (AGENTS.md §3).

Two stalls look alike in a log:

* **Depth ladder.** The antecedent of `P` (or the first bad state) is reachable only after
  many cycles. Successive frames fill with one- or two-literal clauses that advance a valid
  bit, stage or counter by one position per frame, plus whatever environment state the
  generalization kept. Each clause is still the generalized blocking of a CTI, but those CTIs
  constrain only the bounded-depth progress of the antecedent's producer; no clause names a
  relation of the target. Diagnosis: the related activation cover is undetermined or has a long
  witness; frame count ≈ depth reached. This is an observation about where the search is, not a
  diagnosis of a missing relation and not evidence about whether a longer budget converges.
  Remedy: do not mine these literals; prove the structural relations of §2 directly as small
  proves, and use the activation cover's witness as a seed for witness searches (§4).
* **Relation family.** CTIs recur with the same situation over the target's own state (a stage
  holding an identity whose entry is in the wrong phase, two owners of one resource, a copy
  that differs from its source). Diagnosis: decoded cubes concentrate on a few vectors with
  consistent symbolic values. Remedy: the relation those cubes violate, stated over RTL signals,
  admitted under §3a.

## 2. Structural candidates (a heuristic template)

For `A |-> B`, locate the *producer* of `A` (the logic that makes the antecedent true: a
pipeline, queue, counter, handshake) and the *owner* of `B` (the state machine or flag array
whose entry the antecedent names). Typical producers carry an identity through a window of `n`
stages or cycles. For each stage `k` of the window define, over the design's own widths and enum
values:

| relation | form | base case needs | step case needs |
|---|---|---|---|
| phase | `stage_k.valid ⇒ owner[stage_k.id].phase ∈ S_k` | the entry's phase when the identity enters the window (allocation, capture, grant) | every arc leaving `S_k` is impossible while the window is open (the *no-early-event* relations below), for the shifting stage, for a held or stalled stage, and for a flushed or killed stage |
| single occupancy | `¬(stage_j.valid ∧ stage_k.valid ∧ stage_j.id = stage_k.id)` for `j ≠ k`, and across producers that write the same owner | the identity cannot enter the window while another stage holds it (needs the phase relation: an occupied entry is not in the entry phase) | shift, stall, flush, and simultaneous entry and exit in one cycle |
| held copy | `stage_k.valid ⇒ stage_k.copy = f(owner[stage_k.id].state)` with `f` the mapping the consumer itself uses | capture equals source at entry | the source is stable while the window is open (another no-early-event relation), including across a stall |
| no-early-event | `stage_k.valid ⇒ ¬event_e(stage_k.id)` for each arc `e` of the owner's next-state function that leaves `S_k`, read from the RTL *including same-cycle arcs through next-state signals* | the event's enabling condition cannot hold at entry | the condition cannot become true inside the window: either a design counter/flag prevents it (then that flag is itself a phase relation) or an environment assumption does (§4) |
| decision consistency | `recorded_k = f(held_k)` where one side stores only the outcome of a combinational decision `f` (fault, size, match) and the other recomputes `f` later from held copies; `f` is written once as an auxiliary function in the read-only checker | the outcome was computed from the same values that were captured | the held copies are stable while the outcome is held (held-copy relations) |

For two machines that consume the same input at different cycles (a reference model that leads or
lags the design on some path), there is no single phase map: enumerate every alignment the RTL
allows and state the relation per alignment.

Enumerate the arcs from the next-state code, not from a diagram: a `case` branch guarded by a
"data arrived" or "credit returned" flag is an arc whenever that flag can be set by any writer,
including the stage being related. Keep base and step cases separate in the ledger: base cases
are where environment guarantees enter; step cases are where sibling relations are needed. The
template is a default for producer-window/owner designs; it is not a theorem about what any
proof needs, any of its relations may be false, and a different strengthening may avoid them.
Every candidate it produces still needs a relevance witness (§3a) before a proof is spent on it.

## 3. Obligations and what native results certify

Let `K` be the conjunction of a family's relations and `D` the already certified support.

* `prove` of each member (initialized, auto engines) certifies *reachable-state validity* of that
  member under the property's own semantics (clock, reset/disable, enable, sampling). It does
  not certify that `K` is inductive, and a member proved with `-with_proven` used `D` (and
  anything else eligible) as a premise: record the eligible context.
* A `prove` of `K` written as **one assertion** (same clock, reset/disable, non-temporal body)
  is a useful separate diagnostic, not a consecution check. Its CTI is a state the engine's
  frame could not exclude whose successor violates `K`; the decoded cube is a hypothesis
  source for an additional relation, but it may also be reachable (`K` is false; check by a
  cover) or be excluded later by the engine's own clauses. `undetermined` on the conjunction says nothing about
  its inductiveness, and how fast an engine closes an inductive conjunction is an observation
  to record, not a law. Only a validated model of `D ∧ K ∧ T ∧ ¬K'` (AGENTS.md §3) establishes
  that `K` is not inductive relative to `D`.
* A `cover` of a relation's violation, proved `unreachable`, certifies the exclusion and may be
  reused under the proof contract; `covered` supplies a reachable scenario. Neither a budget
  expiry nor a failed search is a label. An unbounded `unreachable` proof of `¬L` is the same
  reachability problem as proving `L`; run one of them, not both.
* `H ⇒ P` is not checked by a native command. Proving `P` with the family eligible certifies
  `P` on reachable states; if `P` is an immediate consequence of `K` (for example one member
  instantiated at the last stage) and still does not close, first inspect whether the eligible
  context actually contains `K` (`-with_proven` eligibility is release- and task-dependent) and
  whether `P`'s semantics (enable, disable, sampling) differ from the member's, before adding
  anything.

## 3a. Relevance: how not to produce inert lemmas

A native proof of `P` with helpers `L_1 … L_n` eligible corresponds to some inductive `H` with
`I ⇒ H`, `H ∧ T ⇒ H'` and `H ⇒ P`; `H` is unknown and generally contains engine-learned clauses
beyond `P ∧ L_1 ∧ … ∧ L_n`. A lemma that is valid and proven but discharges no obligation of
anything in the graph is *inert*: it costs proof time, enlarges the eligible context and misleads
later rounds. Inertness is not directly observable (an eligible fact is not evidence that the
engine consumed it), and the method cannot promise that no inert lemma is ever proved
(strengthenings are not unique, and relevance is judged before the proof exists); what it can do
is refuse to spend proofs on candidates without a consumer, and retire from an experiment a
helper that showed no benefit there. The failure modes that produce inert lemmas are recognizable:

* *Truth-driven selection*: proposing what is easy to prove (domains, encodings, typing of a
  queue payload, environment-model bookkeeping) rather than what an obligation needs.
* *Telemetry name voting*: turning the vectors that merely appear often in frontier clauses into
  lemmas; frequent literals in a depth ladder are the environment's reachable state, not the
  target's relation.
* *Consumer-free lemmas*: helpers written without naming which obligation they discharge.

The relevance rule (AGENTS.md §4) requires, before any proof, a named consumer `C` and one
witness:

* **sufficiency** — `D ∧ L ⇒ C`, established by syntactic instantiation (`C` is a member or
  stage instance of `L`) or by a recorded combinational check over the same monitor state,
  with every conjunct of `L` needed for the implication (dropping any conjunct breaks it). A
  conjunct that is not needed is a separate candidate with its own witness: `C ∧ M` is never
  admitted on `C`'s account. For a temporal `C` the implication is stated over `C`'s monitor
  state, not its bare SVA body.
* **CTI exclusion** — a cube `s` over latches, inputs and `C`'s monitor state such that `s`
  satisfies `D` and `C`, some input makes its successor violate `C`, and `D ∧ s ⇒ ¬L` holds for
  every completion of the cube (not merely at one point). It is *checked* when `s` is a
  qualified decoded CTI of `C` with no unknown bit in the support of `D`, `L` or `C`; a cube
  derived by hand by walking the owner's next-state function backwards from `¬C` is labelled
  "hand-derived, unverified" with the RTL arc, guard and stage used.

Consumers form chains that end at a requested target and never cycle. Relevance is not
necessity. Neither witness shows that every inductive proof of `C` uses `L`, that `L` is the
right strengthening, or that `L` is true; the backward walk is a hypothesis about one path, and
a checked CTI shows only that one obligation of the engine's current frame needs something that
`L` would exclude. After the proof, a matched rerun of the consumer (AGENTS.md §7) measures
benefit in that experiment; a no-benefit result in one run retires the helper from that
experiment's graph, says nothing about its siblings or about the witness, and is never
memoized as impossibility — replicate before generalizing. Removing a helper from a certified
graph goes through an isolated deletion/reproof trial (AGENTS.md §6).

## 4. Environment windows and suspected hazards

A relation whose base case relies on an environment guarantee is only as good as the window
over which the environment state encodes it. Find the environment record that implements the
assumption (a tracker entry, a credit counter, an ownership bit) and compare its lifetime with
the design window the relation needs. Three outcomes:

1. The record outlives the window: state the needed fact on the *design's* copy as a helper and
   prove it from the assumption plus the copy correspondence (AGENTS.md §4).
2. The record retires inside the window (for example a tracker returns to idle on a completion
   handshake while the design still carries the request through later stages): this is a
   *suspected* hazard — the design's own state may still enforce the relation. Write the
   violating scenario as a native cover over design signals, with the candidate's own clock,
   disable and enable (a cover of the bare body can be hit in reset or disabled cycles), and run
   a bounded witness search (AGENTS.md §4): `covered` refutes the candidate and supplies a seed
   for bug hunting on the target; no witness within the bound is no label. A target that then
   fails under `prove -from` is a candidate counterexample until it is established as one native
   trace from reset under the unchanged environment (AGENTS.md §4 names the two admissible forms).
3. The record is not modelled at all: the relation is an environment requirement the task does
   not state; report it as open, never add the assumption.

## 5. Budgeting

No run is unlimited. Every run is budgeted and labelled: an experiment of at most 4 h, the
project's own native baseline at the project's limit, or a cold replay of the proof graph whose
budget is at most `replay_factor` × the proof time of a bounded basis run of the same graph
(AGENTS.md §6); a replay that reaches its budget is an interrupted experiment, not a longer
one. One prove per family with its related covers and the full budget; record engine and time per
property. A prove over many unrelated properties spreads the budget until every member shows
only a bounded engine and measures nothing. Compare each assisted run against the unassisted
baseline under the same orchestration before claiming a benefit (AGENTS.md §7). A family that
stays undetermined as a conjunction is a signal to read its CTI, not to lengthen its budget;
the cost of certifying a family in the cold replay is measured there, not predicted here.
