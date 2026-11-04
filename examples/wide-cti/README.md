# Wide CTI example (deliberate counterexample)

`wide_fold_pipe.sv` and `diag.tcl` are byte-identical to the inputs of the eight native diagnostics in [v3 fresh wide native validation](../../references/v3-fresh-wide-native.md). This is an authored stand-alone validation fixture, not a project design.

**The design.**
- Two stages carrying 6144-bit data and a parity bit.
- Free inputs `stall`, `bug_en`, `in_valid` and `in_data`.
- Clock `clk`; synchronous active-low `rstn`.
- No assumptions.

**The bug and the target.**
- When `bug_en` is set, stage 1 shifts instead of rotating.
- So `ap_fold_s1` (`v1 |-> ^d1 == c1`) has a reachable counterexample.
- Expected native result: `cex`/`cex`.

**What `diag.tcl` does.**
- It analyzes and elaborates the design, sets the clock and reset, and records the assumptions and property inventory.
- It runs one bounded `prove -engine_mode $FIX_ENGINE -time_limit 600s`.
- It then reads the trace through a named `visualize` window (cycles start at 1), saves a VCD and confirms it.

**Environment variables.**

| Variable | Meaning |
|---|---|
| `FIX_DIR` | directory containing these two files |
| `FIX_OUT` | fresh output directory; receives `receipts.txt`, `cex_trace.txt` and `cex.vcd` |
| `FIX_ENGINE` | `M` or `M4` |
| `FIX_LABEL` | free-form run label |

**Running it.**
- Run it as a `diagnostic` through `slurm/submit.sh`, in a fresh run directory, following the runbook in [telemetry-storage.md](../../references/telemetry-storage.md).
- Pass the variables above with `PASS_ENV`, and use an exact qualification for the selected Jasper release.
- Analyze the capture after the workers close: strict `ingest`, then one batch `decode-cubes` of selected complete cube IDs. Do not decode the whole history.
- Tested environments: Python 3.11 on the submit host and Python 3.9 on the compute nodes.

**What was observed, and what is not promised.**
- Each tested cell produced a 6145-literal predecessor cube.
- That size is an observation for these builds and engines. It is not guaranteed by the source.
- Preprocessing, generalization or other releases may give different native cubes.
