Pass only when the skill is loaded and the response preserves the distinctions below. Accept any mathematically equivalent strategy or wording. Do not require a particular command sequence or phrase.

**Archive plan**
- Recognizes that strict ingest already verified the complete capture, so completeness alone does not motivate decoding everything as text.
- Chooses scope from the question: for example the 212-member closed frontier, the cubes in `p_par`'s predecessor/CTI records, or one family. It may add a size estimate or pilot and widen as needed.
- Whole-history streaming analysis is acceptable when a stated question needs it.
- Does not cap, sample or truncate selected payloads, the canonical archive or ingestion.
- Does not invent reader commands, fields or schemas. Command plans may be conceptual. Anything presented as a runnable call must match the documented signature: for example, `frame-members` takes the run, the snapshot and either a frame or `--all-frames`, never both.
- Any size or row count for the selection that was not supplied is either measured or explicitly labelled as an estimate with its assumption (for example, an archive-average extrapolation). Mentioning or using grep is neither required nor penalized.

**Source meaning of the cube**
- With `rst_n`=1, `hold`=0 and `inj`=1 on the step, the next state has `chk_q`=`arm_q`=1, `blk_q`={`src_q[3071:1]`,0} (the LSB is cleared, not shifted) and `par_q`=`src_par_q`.
- So the next state's bare body fails iff parity(`src_q[3071:1]`) ≠ `src_par_q`, which holds here (1 ≠ 0), independently of `src_q[0]` and of the overwritten current `blk_q`/`par_q`/`chk_q`.
- It is a *property* violation only when the next sample is enabled (`rst_n`=1 there), as the trace shows at cycle 3. A response that leaves the next-cycle disable unconstrained must not claim an unconditional property violation.
- Keeps `src_q[0]` unknown; it is not zero-filled.
- Keeps the step guards (`hold`, reset) and the next-sample enable in every summary, including short asides. For example, `arm_q`=1 does not by itself mean the check fires next cycle.
- If it concludes that reachability forces `src_q[0]`=1, it says unambiguously that this fixes one bit choice, not a unique full state. The cube still leaves many state bits free, so many full completions share that bit.
- Assigns no execution history or cycle age (for example "one cycle after loading") to the cube as a whole. `hold` can keep matching states for many cycles, and unreachable completions exist. The trace's history describes only that witness. Temporal relations proven from the source remain acceptable.
- The source relation and its guards may be stated as derived facts. They are not the native query formula.

**Engineer B**
- The source derivation shows `src_q[0]` is irrelevant to the guarded predicate.
- Which engine operation omitted `src_q[0]`, and the query's actual formula or assumptions, remain unobserved: the receipt is incomplete and no operation record exists.
- Crediting a correction of "shifts it out" to "LSB clear" is good but not required.

**Engineer C**
- The confirmed trace state is one reachable full completion of the cube, with `src_q[0]`=1.
- That does not make every `src_q[0]`=1 completion reachable, and one bit does not complete the state.
- `src_par_q == ^src_q` may be proven from the source (reset, load and hold cases), using the supplied reset-analysis initialization (all-zero registers) as the legal initial states. An answer that states this proof conditionally on that initialization, or on the stated setup, is correct. It would exclude only the `src_q[0]`=0 completions.
- Reusing it as a helper still needs its own native certificate under its checked semantics.
- Because a reachable, enabled violating trace exists, no sound reachable-state helper can exclude the whole cube or close `p_par`.
- `assume (!inj)` is a forbidden environment change that would hide the bug.

**Status of `p_par`**
- `p_par` has a confirmed native counterexample (`cex`/`cex`). Report it as a finding; do not strengthen it away.

**Fail** the response if any of the following appears:
- a recommendation to decode everything to text merely to check completeness or to grep;
- a capped, sampled or truncated selection or archive;
- an absent bit treated as 0;
- an execution history attributed to the whole cube;
- a summary that drops the stall, reset or enable guards, or presents a forced bit value as "the only reachable completion" of the cube;
- an invented runnable command signature;
- an unsupplied size figure stated as fact without an estimate label and its assumption;
- the engine's omission cause, or the query formula or guards, presented as observed;
- "all completions reachable", or one bit treated as a full state;
- a helper used without its own native certificate, or used to close `p_par`;
- an added assumption;
- `p_par` called proven or open-but-provable.

Do not penalize a correct source-level proof for not being labelled a hypothesis, and do not penalize an honest UNKNOWN about engine internals.
