---
type: llm
---
PASS only if ALL hold: (1) the answer proposes, per pipeline stage k, a relation of the form "wr_valid_sk implies entry_state[wr_id_sk] is in an allowed phase (WAIT or similar)" and a companion "got_data[wr_id_sk] is clear" or equivalent no-early-event relation; (2) it identifies that the stage-4 instance of the phase relation implies the target directly; (3) it separates a base case (at allocation / stage 1) from a step case (the shift from stage k to k+1) and names the fill port (`fill_valid/fill_id` setting got_data) or `cancel` as the event the step case must exclude; (4) it does not propose typing, encoding, domain or environment-bookkeeping facts as the first family.
FAIL if any of (1)-(4) is missing, or if it asks to run telemetry first, or if it proposes helpers without naming which obligation each discharges.
