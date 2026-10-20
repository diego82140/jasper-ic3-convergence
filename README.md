# jasper-ic3-convergence

Two versions ship from this repository and install side by side (distinct plugin names, skills namespaced per plugin):

```
/plugin marketplace add diego82140/jasper-ic3-convergence     # or the local path of this checkout
/plugin install jasper-ic3-convergence-v2 --marketplace jasper-ic3-convergence   # v2.0.0: current method, evidence-budgeted gates (this root)
/plugin install jasper-ic3-convergence --marketplace jasper-ic3-convergence      # v1.3.0: original published method, frozen under ./v1
```

Invoke the skill as `/jasper-ic3-convergence-v2:jasper-ic3-convergence` (v2) or `/jasper-ic3-convergence:jasper-ic3-convergence` (v1).
v1 is a byte-for-byte snapshot of the original release (commit 98a455d) and is not maintained; everything below describes v2.

Development of the Claude Code convergence plugin and jipstats with complete, lossless disk capture. The current agent candidate is plugin 1.4.42-dev / jipstats 1.6.13-dev, with native components qualified in kit 1.4.41; the primary prebuilt files in this working tree remain the older 1.4.22 / 1.6.4 until final acceptance. The disk sink bypasses Jasper's GUI report callback for captured M/M4 cubes, frames, obligations and queries; exact-build capability limits are below. Streaming gzip stores the canonical evidence; optional verified post-close chain packing reduces permanent storage while reconstructing every original decoded byte. A disposable offline SQLite index supports complete payload exports without loading the history into memory.

Use the qualified immutable candidate identified in [validation.json](references/validation.json) for current validation. The working tree is not yet the promoted deliverable. The public marketplace is updated only after these changes are published. Read [AGENTS.md](AGENTS.md) for the proof contract and [telemetry-storage.md](references/telemetry-storage.md) for architecture, display access, maintenance and limitations. Actual qualifications and measurements are recorded in [validation.json](references/validation.json).

## Requirements and compatibility

Use a shared filesystem, a working `LM_LICENSE_FILE`, and Slurm `Formal` or `Formal_192G`. Emulation partitions are rejected. Every Jasper process runs in an allocation. Exact worker adapters support:

- `/projects/external_ip/cadence/jasper_2026.0920260826065032` (default)
- `/projects/external_ip/cadence/jasper_2026.06p002`

Qualification compares native M/M4 proofs and counterexamples with and without instrumentation. Unknown worker hashes fail closed. The June adapter exports raw complete cubes and native validation boundaries; its old Dollar named display renderer and `getCex` convenience hook are not qualified. Captured mutation-boundary data does not include every hidden SAT formula or a complete RTL transition graph.

## Run and inspect

```bash
K=/formal_shared/diego1/.foo/jasper-ic3-convergence   # or this clone
RUN=/path/on/shared/filesystem/investigation
LAUNCH=/path/to/project

"$K/slurm/submit.sh" check "$RUN/check-original"
JASPER=/projects/external_ip/cadence/jasper_2026.06p002 \
  "$K/slurm/submit.sh" check "$RUN/check-june"
"$K/slurm/submit.sh" diagnostic "$RUN/diag" "$LAUNCH" diagnostic.tcl
# Wait for that job to complete before indexing its archive.
python3 "$K/tools/telemetry_db.py" ingest "$RUN/diag/telemetry" "$RUN/diag/index.db"
python3 "$K/tools/telemetry_db.py" summary "$RUN/diag/index.db"
python3 "$K/tools/telemetry_db.py" frame-members "$RUN/diag/index.db" '<run-key>' 3 --all-frames
python3 "$K/tools/telemetry_db.py" payload "$RUN/diag/index.db" '<run-key>' cube 123
python3 "$K/tools/telemetry_db.py" cube-ids "$RUN/diag/index.db" '<run-key>' --domain jip_formula > "$RUN/diag/cube-ids.txt"
python3 "$K/tools/telemetry_db.py" decode-cubes "$RUN/diag/index.db" '<run-key>' --ids-file "$RUN/diag/cube-ids.txt"

# Optional short warm exploration; rotate and replay proven prerequisites as needed.
"$K/slurm/submit.sh" session "$RUN/explore" "$LAUNCH"
"$K/session/send.sh" "$RUN/explore/io" "$LAUNCH/project.tcl"
echo session_stop | "$K/session/send.sh" "$RUN/explore/io" -

# Every run is budgeted (Slurm --time = BUDGET + margin). Experiments (<= 4h) must bound every prove in their Tcl:
BUDGET=30m BUDGET_NOTE='family F1 with covers' "$K/slurm/submit.sh" batch "$RUN/exp01" "$LAUNCH" exp01.tcl
BUDGET=10m "$K/slurm/submit.sh" batch "$RUN/example" "$K/example" proof_graph.tcl
# The project's own native baseline, unchanged Tcl, its own limit (the §7 control measurement):
BUDGET=48h BUDGET_CLASS=baseline BUDGET_NOTE='project jg_run.tcl, unchanged, native limit 48h' "$K/slurm/submit.sh" batch "$RUN/baseline" "$LAUNCH" jg_run.tcl
# Cold replay of the proof graph: budget <= replay_factor x the basis run's proof time, justified by a receipt
# (tools/graph_ready.py documents the fields; the graph Tcl prints GRAPH_INPUTS/GRAPH_NODES/GRAPH_COVERS/PROOFMASTER/RESULT lines).
BUDGET=2h BUDGET_CLASS=replay GRAPH_READY="$RUN/GRAPH-READY.json" IC3_COLD=1 PASS_ENV='IC3_COLD,<project variables>' "$K/slurm/submit.sh" batch "$RUN/graph" "$LAUNCH" proof_graph.tcl
# End-of-round audit of live native work (also the plugin's Stop hook, which adds --hook):
python3 "$K/tools/audit.py" --workspace "$RUN"
# Result, contract, Cache and watchdog/KILL lines of a run, with file:line:
python3 "$K/tools/jg_results.py" "$RUN/exp01/jg.log"
```

Set `LM_LICENSE_FILE` according to your installation. The Tcl chooses M or M4 and diagnostic budgets. Use `--allow-incomplete` only for time-limited or interrupted diagnostics; it labels the index incomplete and still rejects record/hash corruption. Never use an incomplete capture as a proof certificate. Native Jasper status and validity remain authoritative.

Each fresh run has `job.id`, `job.env`, `jg.log`, `jgproject/` and `rss.csv`. Instrumented modes add `telemetry/`, `capture.log` and `resources.txt`. Keep compressed records and their manifests; the index and selected exports are disposable. Successful ingestion also creates INDEX.db.integrity.json; retain it with the disposable index. Queries verify this checksum and all source decoded SHA-256/byte lengths before output and recheck them at completion, using bounded buffers. Batch selections share those checks; verified byte-preserving recompression remains compatible. Older indexes need fresh ingestion to obtain a trusted receipt. After all workers close, `python3 "$K/tools/archive_pack.py" "$RUN/diag/telemetry" --recompress` can reduce archival space with verified level-9 gzip; it preserves every decoded byte and replaces only when smaller. The index stores integer references and source offsets rather than another full raw log. Do not run whole-history `--details` JSON analysis on multi-gigabyte captures. For legacy analysis, export one small complete run first; `tools/basis.py` accepts that legacy analysis JSON.

## Display

```bash
DIAGNOSTIC_GUI=1 "$K/slurm/submit.sh" diagnostic "$RUN/gui" "$LAUNCH" diagnostic.tcl
```

The wrapper starts a private Xvnc display with Xauthority and a private Unix RFB socket, without a network listener. `display.txt` identifies the allocated node and display. A one-shot GUI Tcl must end with `exit -force`; plain `exit` opens a confirmation dialog and keeps the allocation alive. See the storage reference for tested snapshot/keyboard commands and interactive viewing. GUI mode uses the same disk transport; complete telemetry is queried from the archive rather than rendered as millions of console lines.

## Maintenance

Edit a clone, rebuild atomically from `source/`, and follow the change ledger and requalification procedure in the storage reference. Run transport/archive tests, native checks on both builds, and `claude plugin validate .`. Update the skill, agent contract, validation evidence and plugin version together. Run outputs belong outside the kit. Do not replace a library currently mapped by a worker in place.

A release can be packaged with `python3 tools/package_release.py . /shared/new-release-directory`. The runtime archive contains the launcher, library, skill/agent, tools, profiles, source and tests; the separate rebuild-inputs archive contains large third-party build dependencies. Extract the second archive only when rebuilding offline. RELEASE.json records both archive hashes and the pinned runtime manifest. Neither packaging nor adapter PASS upgrades an open convergence validation to PASS.
