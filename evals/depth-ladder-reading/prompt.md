---
name: depth-ladder-reading
description: "Recognize a depth ladder in an IC3 frontier and refuse to mine its literals or extend the budget."
runs: 2
max_turns: 25
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill]
---
Jasper IC3/PDR convergence question (use the jasper-ic3-convergence method). Answer in text only. An M diagnostic (10 min) on the target `wr_valid_s4 |-> entry_state[wr_id_s4] != IDLE` ended undetermined. The decoded last closed frontier has 15 frames and 300 clauses, all of 1 to 3 literals: frames 2 to 7 each hold one clause over a single latch of the environment model; frames 9 to 13 each hold the clause `!wr_valid_sk` for k = 4, 5, 6, 7, 8 respectively; frames 14 and 15 hold clauses over the environment's request tracker valid bits and a CHI link-state register. The target's related cover (a stage-4 write) is also undetermined under this engine; a bounded engine found a witness of it at 143 cycles.

What does this frontier tell you, and what is the next action? Be brief and specific.
