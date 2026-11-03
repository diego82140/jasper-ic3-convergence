# jasper-ic3-convergence

Claude Code plugin for Jasper IC3/PDR convergence work: structural CTI diagnosis, sound helper invariants, proof graphs and complete M/M4 telemetry on Slurm.

## Install (v3)

```
/plugin marketplace add diego82140/jasper-ic3-convergence     # or the local path of this checkout
/plugin install jasper-ic3-convergence-v3 --marketplace jasper-ic3-convergence
```

Invoke the skill as `/jasper-ic3-convergence-v3:jasper-ic3-convergence`. The public marketplace serves v3 once this revision is merged; until then, add the marketplace from a local checkout.

## Versions

| Version | Plugin | Supported Jasper builds |
|---|---|---|
| **v3 3.0.0** (current) | `jasper-ic3-convergence-v3` | 2026.09 prerelease, 2026.06p002, production 2026.09, 2026.09p001 |
| v2 2.0.0 | `jasper-ic3-convergence-v2` | 2026.09 prerelease, 2026.06p002 |
| v1 1.3.0 | `jasper-ic3-convergence` | 2026.09 prerelease |

The 2026.09 prerelease is `jasper_2026.0920260826065032`; full paths are under [Requirements](#requirements-and-compatibility).

Older versions remain installable side by side, with skills `/jasper-ic3-convergence-v2:jasper-ic3-convergence` and `/jasper-ic3-convergence:jasper-ic3-convergence`:

```
/plugin install jasper-ic3-convergence-v2 --marketplace jasper-ic3-convergence
/plugin install jasper-ic3-convergence --marketplace jasper-ic3-convergence
```

v1 is a frozen snapshot of commit `98a455d` under `./v1`; v2 is pinned to its release revision `f358b1a`. Existing installed copies are unchanged. Everything below describes v3; changes are summarised in [CHANGELOG.md](CHANGELOG.md).

v3 uses jipstats `1.6.15-dev`, with exact adapters for all four listed Jasper builds. Its 32 native qualification checks and direct old/new CTI-information tests pass. The disk sink bypasses Jasper's GUI report callback; complete compressed telemetry stays on disk and a disposable SQLite index supports bounded-memory queries. See [current compatibility results](references/2026-09-cti-agent-parity.md) for exact scope and limitations. End-to-end hard-design convergence validation remains separate.

Read [AGENTS.md](AGENTS.md) for the unchanged proof contract and [telemetry-storage.md](references/telemetry-storage.md) for capture, database and display operations. The v3 name distinguishes the telemetry compatibility update; it does not change the inductiveness method. Actual agent tests and observer corrections are in [v3 CTI reading validation](references/v3-agent-cti-reading.md).

## Requirements and compatibility

Use a shared filesystem, a working `LM_LICENSE_FILE`, and Slurm `Formal` or `Formal_192G`. Emulation partitions are rejected. Every Jasper process runs in an allocation. Exact worker adapters support:

- `/projects/external_ip/cadence/jasper_2026.0920260826065032` (default)
- `/projects/external_ip/cadence/jasper_2026.06p002`
- `/projects/external_ip/cadence/jasper_2026.09` (production; worker `b3e7723c…`)
- `/projects/external_ip/cadence/jasper_2026.09p001` (worker `e1b53cf5…`)

Qualification compares native M/M4 proofs and counterexamples with and without instrumentation. Unknown worker hashes fail closed. The June adapter exports raw complete cubes and native validation boundaries; its old Dollar named display renderer and `getCex` convenience hook are not qualified. Captured mutation-boundary data does not include every hidden SAT formula or a complete RTL transition graph.

The production September builds differ from the August prerelease: each has its
own instruction guards, native validation call sites and formula-table addresses.
Existing adapters are retained. See [September compatibility and information
parity](references/2026-09-compatibility.md) for the exact comparison scope and
reproduction commands. A matching installation still needs its own native
qualification; a release label alone never selects offsets.

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
python3 "$K/tools/telemetry_db.py" frame-members "$RUN/diag/index.db" '<run-key>' 3 --all-frames > "$RUN/diag/frontier.jsonl"
python3 "$K/tools/telemetry_db.py" payload "$RUN/diag/index.db" '<run-key>' cube 123
# Decode a deliberately selected ID file (for example the closed frontier above), not every cube;
# build selected-ids.txt with the fail-closed selection recipe in references/telemetry-storage.md.
python3 "$K/tools/telemetry_db.py" decode-cubes "$RUN/diag/index.db" '<run-key>' --ids-file "$RUN/diag/selected-ids.txt"

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

Edit a clone, rebuild atomically from `source/`, and follow the change ledger and requalification procedure in the storage reference. Run transport/archive tests, native checks on the selected builds, and `claude plugin validate .`. Update the skill, agent contract, validation evidence and plugin version together. Run outputs belong outside the kit. Do not replace a library currently mapped by a worker in place.

A release can be packaged with `python3 tools/package_release.py . /shared/new-release-directory`. The runtime archive contains the launcher, library, skill/agent, tools, profiles, source and tests; the separate rebuild-inputs archive contains large third-party build dependencies, which live *beside* the kit in `../jasper-ic3-convergence-build/third_party` (as does the `rebuilt/` output) so that a local-path plugin install copies only the runtime (`--inputs` overrides the location). Extract the second archive only when rebuilding offline. RELEASE.json records both archive hashes and the pinned runtime manifest. Neither packaging nor adapter PASS upgrades an open convergence validation to PASS.
