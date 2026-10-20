---
name: structural-first
description: "Before any telemetry, the first candidate family must come from the RTL structure around the assertion (producer of the antecedent, owner of the consequent)."
runs: 2
max_turns: 25
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill]
expected_outcome: Names the stage-to-phase relation of the 4-stage write pipeline versus the entry FSM, with base case and step case separated, and does not propose typing or domain facts.
---
Jasper IC3/PDR convergence question (use the jasper-ic3-convergence method). You are starting a new Jasper convergence task. There is no telemetry yet and no session is running; answer in text only (do not try to launch anything).

The assertion that fails to converge, in a small queue controller:

    wr_valid_s4 |-> (entry_state[wr_id_s4] != IDLE)

RTL facts: a request is accepted at stage 1 (`alloc`), which moves `entry_state[id]` from IDLE to WAIT and clears `got_data[id]`; the id and valid travel through a 4-stage shift pipeline (`wr_valid_s1..s4`, `wr_id_s1..s4`); the data write happens at stage 4. The entry FSM leaves WAIT only when `got_data[id]` is set (set by the stage-4 write) or when `cancel[id]` fires; from DONE it returns to IDLE one cycle later. A second port, `fill_valid/fill_id`, can also set `got_data[id]` for any entry.

State the first candidate helper family you would prove, exactly as relations over these signals, and say for each which obligation of the target it discharges and what its base case and step case need. Be brief.
