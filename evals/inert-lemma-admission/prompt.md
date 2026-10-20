---
name: inert-lemma-admission
description: "Apply the relevance rule: a lemma needs a named consumer and a relevance witness (sufficiency or CTI exclusion, checked or hand-derived); true-but-consumer-free facts are rejected."
runs: 2
max_turns: 25
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill]
---
Jasper IC3/PDR convergence question (use the jasper-ic3-convergence method). Answer in text only. Target: `wr_valid_s4 |-> entry_state[wr_id_s4] != IDLE` over the queue controller described in its RTL (4-stage write pipeline into a 4-entry FSM array; allocation at stage 1 moves IDLE to WAIT; WAIT leaves only on got_data or cancel). Four candidate lemmas are proposed; decide for each whether it may be admitted for proof now, and why, using the kit's relevance rule:

A. "entry_state[i] is always one of the legal encodings {IDLE, WAIT, DONE}" for all i.
B. "wr_valid_s4 |-> entry_state[wr_id_s4] == WAIT".
C. "The request queue's opcode field is always a legal opcode value".
D. "wr_valid_s3 |-> (entry_state[wr_id_s3] == WAIT && !got_data[wr_id_s3])".

Give a one-line verdict per lemma: admitted or not, the consumer, the obligation, and the kind of witness.
