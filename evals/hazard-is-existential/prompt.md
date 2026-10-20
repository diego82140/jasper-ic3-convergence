---
name: hazard-is-existential
description: "When a candidate's base case rests on an environment guarantee that expires inside the design window, switch from lemma-proving to a bounded witness search on the candidate's negation, with an explicit bounded engine and seed chaining; a seeded failure is a candidate counterexample until replayed from reset."
runs: 2
max_turns: 25
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill]
---
Jasper IC3/PDR convergence question (use the jasper-ic3-convergence method). Answer in text only. You derived, for the queue controller, the relation PDIST: "two stages of the write pipeline never hold the same entry id". Its step case is a shift. Its base case needs: no second request for the same entry is accepted while a first one is in the 4-stage pipe. The design has no such guard. The environment forbids a second request only to entries its own tracker marks active, and you have read that the tracker clears an entry when the design sends an acknowledgement at stage 2, i.e. two cycles before the stage-4 write. IC3 on PDIST has been undetermined for 30 minutes; a 40-minute unseeded cover search for "two stages hold one id" was also undetermined.

What is the mathematically correct next step, and what exactly would you run? Be brief and specific.
