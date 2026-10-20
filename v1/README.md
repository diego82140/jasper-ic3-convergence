# jasper-ic3-convergence

A Claude Code skill that makes stalled Jasper assertions converge: M/M4 telemetry (jipstats) → CTI families → sound helper invariants → a status-gated proof graph, with every Jasper process on Slurm. Method and rules: `AGENTS.md`.

Contents: `jipstats` (with `_internal/`, `libjipstats.so`), `slurm/submit.sh`, `session/` (`server.tcl`, `send.sh`), `tools/basis.py`, `example/`, `skills/`, `AGENTS.md`.

## Install

```bash
claude plugin marketplace add diego82140/jasper-ic3-convergence
claude plugin install jasper-ic3-convergence@jasper-ic3-convergence     # restart Claude Code
```

Update: `claude plugin marketplace update jasper-ic3-convergence && claude plugin update jasper-ic3-convergence@jasper-ic3-convergence`.
Without installing: `git clone https://github.com/diego82140/jasper-ic3-convergence.git <dir>` (a filesystem the nodes see), then `claude --plugin-dir <dir>`.

Needs: Slurm `Formal` access (`/netbatch/bin`), `LM_LICENSE_FILE` set, a home and run directory the nodes can see (not `/tmp`).

## Start the conversation

```bash
cd <your project> && claude
```

Then, for example:

> Use jasper-ic3-convergence on `<path>/jg_run.tcl`. Targets: all safety assertions. Run directory: `<a directory the nodes can see>`. Deliver the checker, the proof graph, the ledger and the replay.

The skill is also picked up from a plain description of the problem, or by `/jasper-ic3-convergence:jasper-ic3-convergence <task>`.

## Run by hand (what the skill does)

```bash
K=~/.claude/plugins/cache/jasper-ic3-convergence/jasper-ic3-convergence/<version>   # or your clone
RUN=<run directory the nodes can see>  # one per job
LAUNCH=<directory the project Tcl starts in>

$K/jipstats --version                                          # local
$K/slurm/submit.sh check   "$RUN/check"                        # jipstats --check self-test, on a node
$K/slurm/submit.sh session "$RUN/s" "$LAUNCH"                  # persistent jipstats + Jasper session, on a node
$K/session/send.sh "$RUN/s/io" "$LAUNCH/<project.tcl>"         # build once (a file on this host, run in $LAUNCH)
wc -c < "$RUN/s/capture.log" > "$RUN/s/offset"                 # before each diagnostic
$K/session/send.sh "$RUN/s/io" - <<'EOF'                       # any Jasper command is a request
prove -property <task>::<path>.<assertion> -engine_mode M -verbosity 20 -time_limit <budget>
EOF
tail -c +$(( $(cat "$RUN/s/offset") + 1 )) "$RUN/s/capture.log" | awk 'f || /phase=run_contract/ {f=1} f' > "$RUN/s/slice.log"
$K/jipstats --analyse "$RUN/s/slice.log" --details --output "$RUN/s/a.json" --llm-brief "$RUN/s/brief.json"
python3 $K/tools/basis.py "$RUN/s/a.json" 0 polarity           # also: vectors | table VEC... | eval 'EXPR'
echo session_stop | $K/session/send.sh "$RUN/s/io" -           # end of the investigation
PASS_ENV="<VAR> ..." $K/slurm/submit.sh batch "$RUN/graph" "$LAUNCH" proof_graph.tcl   # counted proofs, replay
/netbatch/bin/squeue -u "$USER"; /netbatch/bin/scancel <jobid>
```

Each run directory gets `jg.log`, `job.id`, `jgproject/`, and for a session `io/` and `capture.log`. `PASS_ENV` lists the variables the project Tcl reads. Counted proofs never get `-time_limit`; diagnostic budgets are yours. Delete captures, slices and analysis JSON once used: they reach gigabytes per minute.

Self-test: `$K/slurm/submit.sh batch "$RUN/example" $K/example proof_graph.tcl` → `ALL ACCEPTED` in `$RUN/example/jg.log`.

## Maintain

Edit in a clone, bump `version` in `.claude-plugin/plugin.json` (installed copies keep old files otherwise), run `claude plugin validate .`, then commit and push. Never write run output into the kit.
