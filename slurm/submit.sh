#!/usr/bin/env bash
#=============================================================================
# submit.sh -- run Jasper on a Slurm node (never on the agent host).
#
#   submit.sh batch   <run_dir> <launch_dir> <tcl> [jasper args...]   (<tcl> may be relative to <launch_dir>)
#       Plain Jasper: <jasper>/bin/jaspergold -batch -proj <run_dir>/jgproject
#       -tcl <tcl> [jasper args...], started in <launch_dir>. Use it for proof
#       graphs, cold-start replays and every closure proof.
#
#   submit.sh session <run_dir> <launch_dir> [jasper args...]
#       Persistent jipstats session: jipstats <jasper> -batch
#       -proj <run_dir>/jgproject -tcl session/server.tcl, started in
#       <launch_dir>. Requests: session/send.sh <run_dir>/io <tcl | ->.
#       Telemetry: <run_dir>/telemetry; ordinary messages: capture.log.
#
#   submit.sh diagnostic <run_dir> <launch_dir> <tcl> [jasper args...]
#       One-shot instrumented batch run; DIAGNOSTIC_GUI=1 uses a private Xvnc.
#       Instrumented modes write full gzip telemetry in <run_dir>/telemetry.
#
#   submit.sh check   <run_dir>
#       jipstats --check <jasper> (native M/M4 self-test) on a node.
#
# <run_dir> must be on a filesystem the nodes see (not the agent host's /tmp);
# it receives jg.log (job output), job.env, job.id and jgproject/. <launch_dir>
# is where the project Tcl expects to start (its relative paths resolve there).
# Prints the Slurm job id. Every run gets --time=BUDGET+margin; no agent prove
# limit is added inside Jasper for baseline or replay runs.
#
# Environment (optional):
#   JASPER        Jasper installation (default below)
#   PASS_ENV      names of further variables the project Tcl reads (space or comma separated)
#                 (HOME, USER and LM_LICENSE_FILE are always passed)
#   PARTITION     Slurm partition (default Formal)
#                 Site routing may move small Formal_192G requests to Formal;
#                 inspect the actual partition with scontrol after submission.
#   XDG_CACHE_HOME Optional qualification cache; pass its name via PASS_ENV
#                 for diagnostic/session reuse. Fresh check defaults to RUN/cache.
#   CPUS, MEM     job resources (default 4, 32G); the coordinator, plus any engine
#                 the project does not dispatch as its own Slurm jobs, runs in them
#   ALLOW_UNSUPPORTED_OS  1 (default) = Jasper -allow_unsupported_OS; the Formal
#                 nodes run an OS the installed Jasper does not list
#   SLURM_BIN     directory of sbatch/squeue/scancel (default /netbatch/bin)
#   JOB_NAME      Slurm job name (default jasper-<mode>)
#   BUDGET        run budget, e.g. 30m, 2h (required for batch; default 4h for
#                 diagnostic and session); BUDGET_CLASS experiment|baseline|replay,
#                 BUDGET_NOTE free text (required for baseline), BUDGET_MARGIN
#                 (default 60m, at most 120m) added to the Slurm --time backstop
#   GRAPH_READY   replay class: the receipt (tools/graph_ready.py) that justifies BUDGET
#=============================================================================
set -euo pipefail
AGENT=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)
JASPER=${JASPER:-/projects/external_ip/cadence/jasper_2026.0920260826065032}
SLURM_BIN=${SLURM_BIN:-/netbatch/bin}
if [ "${1:-}" = licenses ]; then
    exec python3 "$AGENT/tools/license_status.py" "$JASPER"
fi

usage() { sed -n '4,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 2 ] || usage
MODE=$1; RUN=$2; shift 2
case $MODE in
    batch|diagnostic)   [ $# -ge 2 ] || usage; LAUNCH=$1; TCL=$2; shift 2 ;;
    session) [ $# -ge 1 ] || usage; LAUNCH=$1; TCL=$AGENT/session/server.tcl; shift ;;
    check)   LAUNCH=$RUN; TCL= ;;
    *) usage ;;
esac

case ${TELEMETRY_SINK:-disk} in disk|console) ;; *) echo "invalid TELEMETRY_SINK" >&2; exit 2 ;; esac
case ${FRAME_ENCODING:-tuple_chunks_v2} in members_v1|tuple_chunks_v1|tuple_chunks_v2) ;; *) echo "invalid FRAME_ENCODING" >&2; exit 2 ;; esac
case ${PARTITION:-Formal} in
    Formal|Formal_192G) ;;
    *) echo "submit.sh: use Formal or Formal_192G, never an emulation partition" >&2; exit 2 ;;
esac
[ ! -e "$RUN/job.env" ] || { echo "submit.sh: use a fresh run directory" >&2; exit 2; }
# Budget gate (checks labels and limits, not truth): no run is unlimited. Every
# job gets --time=BUDGET+BUDGET_MARGIN (margin at most 120m). BUDGET=<n>[smh] in
# one of three classes (BUDGET_CLASS):
#   experiment (default): at most 4h; the Tcl must bound every prove
#                         (tools/prove_gate.py, textual, this file only)
#   baseline:   the unchanged project Tcl under its own native limit; BUDGET_NOTE
#               must name that limit; no textual check (project files are not edited)
#   replay:     cold proof-graph replay; GRAPH_READY=<receipt.json> must validate
#               (tools/graph_ready.py), the Tcl must be the one the receipt hashes,
#               and BUDGET <= replay_factor x the basis run's proof time
# A diagnostic run takes the same rule (default BUDGET=4h, experiment); a session's
# BUDGET is its lifetime (default 4h, at most 4h) and send.sh bounds each request.
to_min() { case $1 in *h) echo $(( ${1%h} * 60 ));; *m) echo ${1%m};; *s) echo $(( (${1%s} + 59) / 60 ));; *) echo "${1}";; esac; }
SLURM_TIME=
BUDGET_CLASS=${BUDGET_CLASS:-experiment}
case $BUDGET_CLASS in experiment|baseline|replay) ;; *) echo "submit.sh: BUDGET_CLASS must be experiment, baseline or replay" >&2; exit 2 ;; esac
MARGIN=${BUDGET_MARGIN:-60m}
echo "$MARGIN" | grep -Eq '^[0-9]+[smh]$' || { echo "submit.sh: BUDGET_MARGIN must look like 30m, 1h" >&2; exit 2; }
[ "$(to_min "$MARGIN")" -le 120 ] || { echo "submit.sh: BUDGET_MARGIN $MARGIN exceeds the 120m cap" >&2; exit 2; }
if [ "$MODE" = check ]; then
    : "${BUDGET:=2h}"   # qualification self-test: labelled and backstopped like every run
    echo "$BUDGET" | grep -Eq '^[0-9]+[smh]$' || { echo "submit.sh: BUDGET must look like 30m, 2h" >&2; exit 2; }
    SLURM_TIME=$(( $(to_min "$BUDGET") + $(to_min "$MARGIN") ))
fi
if [ "$MODE" = batch ] || [ "$MODE" = diagnostic ] || [ "$MODE" = session ]; then
    [ "$MODE" = batch ] || : "${BUDGET:=4h}"
    [ -n "${BUDGET:-}" ] || { echo "submit.sh: batch needs BUDGET=<duration> (BUDGET_CLASS experiment|baseline|replay; see the header)" >&2; exit 2; }
    echo "$BUDGET" | grep -Eq '^[0-9]+[smh]$' || { echo "submit.sh: BUDGET must look like 30m, 2h" >&2; exit 2; }
    bmin=$(to_min "$BUDGET")
    case $MODE:$BUDGET_CLASS in
        session:*)
            [ "$bmin" -le 240 ] || { echo "submit.sh: a session lifetime BUDGET is at most 4h (rotate the session)" >&2; exit 2; } ;;
        *:experiment)
            [ "$bmin" -le 240 ] || { echo "submit.sh: BUDGET $BUDGET exceeds the 4h experiment cap (baseline or replay need their own class and evidence)" >&2; exit 2; }
            TCL_ABS=$(cd "$LAUNCH" && readlink -f "$TCL")
            python3 "$AGENT/tools/prove_gate.py" "$TCL_ABS" --max "$BUDGET" || { echo "submit.sh: BUDGET=$BUDGET given but $TCL has a prove not bounded by it" >&2; exit 2; } ;;
        batch:baseline)
            [ -n "${BUDGET_NOTE:-}" ] || { echo "submit.sh: BUDGET_CLASS=baseline needs BUDGET_NOTE naming the project's native limit and purpose" >&2; exit 2; } ;;
        batch:replay)
            [ -n "${GRAPH_READY:-}" ] || { echo "submit.sh: BUDGET_CLASS=replay needs GRAPH_READY=<receipt.json>" >&2; exit 2; }
            GR_OUT=$(python3 "$AGENT/tools/graph_ready.py" validate "$GRAPH_READY") || { echo "$GR_OUT" >&2; echo "submit.sh: GRAPH_READY receipt not admissible; fix the graph, not the receipt" >&2; exit 2; }
            TCL_ABS=$(cd "$LAUNCH" && readlink -f "$TCL")
            RSHA=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["graph_tcl_sha256"])' "$GRAPH_READY")
            [ "$(sha256sum "$TCL_ABS" | cut -d' ' -f1)" = "$RSHA" ] || { echo "submit.sh: $TCL is not the graph Tcl the receipt hashes" >&2; exit 2; }
            MAXS=$(echo "$GR_OUT" | sed -n 's/.*max_budget_s=\([0-9]*\).*/\1/p')
            [ $(( bmin * 60 )) -le "${MAXS:-0}" ] || { echo "submit.sh: BUDGET $BUDGET exceeds the receipt's replay budget (${MAXS:-0} s = replay_factor x basis time)" >&2; exit 2; } ;;
        *)
            echo "submit.sh: BUDGET_CLASS=$BUDGET_CLASS is only for batch runs" >&2; exit 2 ;;
    esac
    SLURM_TIME=$(( bmin + $(to_min "$MARGIN") ))
fi
: "${LM_LICENSE_FILE:?LM_LICENSE_FILE must be set (the license server of the installed Jasper)}"
JASPER_LAUNCHER=
for candidate in "$JASPER/bin/jaspergold" "$JASPER/jg" "$JASPER/bin/jg"; do
    if [ -x "$candidate" ]; then JASPER_LAUNCHER=$candidate; break; fi
done
[ -n "$JASPER_LAUNCHER" ] || { echo "submit.sh: no Jasper launcher at $JASPER" >&2; exit 2; }
mkdir -p "$RUN"
RUN=$(cd "$RUN" && pwd); LAUNCH=$(cd "$LAUNCH" && pwd)
[ -z "$TCL" ] || TCL=$(cd "$LAUNCH" && readlink -f "$TCL")   # relative to <launch_dir>, like Jasper
[ -z "$TCL" ] || [ -f "$TCL" ] || { echo "submit.sh: no Tcl file $TCL" >&2; exit 2; }
python3 "$AGENT/tools/license_status.py" "$JASPER" > "$RUN/license-status.json"
python3 "$AGENT/tools/artifact_manifest.py" "$AGENT" > "$RUN/plugin-artifact.json"
for d in "$RUN" "$AGENT"; do
    case $d in /tmp/*|/var/tmp/*) echo "submit.sh: $d is not visible from the nodes" >&2; exit 2 ;; esac
done
if [ "$MODE" = session ] && [ -e "$RUN/io/session.jobid" ] &&
   "$SLURM_BIN/squeue" -h -j "$(cat "$RUN/io/session.jobid")" 2>/dev/null | grep -q .; then
    echo "submit.sh: a session is already running in $RUN (job $(cat "$RUN/io/session.jobid"))" >&2; exit 2
fi

# The job starts from a clean environment (--export=NONE); everything it needs is
# written here, quoted, so values may contain any character.
{
    printf 'MODE=%q\nRUN=%q\nLAUNCH=%q\nTCL=%q\nAGENT=%q\nJASPER=%q\n' \
        "$MODE" "$RUN" "$LAUNCH" "$TCL" "$AGENT" "$JASPER"
    printf 'JASPER_LAUNCHER=%q\n' "$JASPER_LAUNCHER"
    printf 'DIAGNOSTIC_GUI=%q\n' "${DIAGNOSTIC_GUI:-0}"
    printf 'TELEMETRY_SINK=%q\n' "${TELEMETRY_SINK:-disk}"
    printf 'FRAME_ENCODING=%q\n' "${FRAME_ENCODING:-tuple_chunks_v2}"
    printf 'ALLOW_UNSUPPORTED_OS=%q\n' "${ALLOW_UNSUPPORTED_OS:-1}"
    printf 'PASS=(%q %q %q' "HOME=$HOME" "USER=$USER" "LM_LICENSE_FILE=$LM_LICENSE_FILE"
    for v in $(echo "${PASS_ENV:-}" | tr , " "); do
        [ -n "${!v+x}" ] || { echo "submit.sh: PASS_ENV names $v, which is not set" >&2; exit 2; }
        printf ' %q' "$v=${!v}"
    done
    printf ')\n'
} > "$RUN/job.env"

TIME_ARGS=()
[ -z "$SLURM_TIME" ] || TIME_ARGS=(--time="$SLURM_TIME")   # minutes; every mode sets one
JOB=$("$SLURM_BIN/sbatch" --parsable \
    --job-name="${JOB_NAME:-jasper-$MODE}" --partition="${PARTITION:-Formal}" \
    --cpus-per-task="${CPUS:-4}" --mem="${MEM:-32G}" "${TIME_ARGS[@]}" \
    --export="NONE,IC3_JOB_ENV=$RUN/job.env" --output="$RUN/jg.log" \
    "$AGENT/slurm/jasper_job.sh" "$@")
echo "$JOB" > "$RUN/job.id"
# Label the run directory for tools/audit.py.
if [ -n "$SLURM_TIME" ]; then
    echo "$BUDGET class=$BUDGET_CLASS slurm_time_min=${SLURM_TIME} ${BUDGET_NOTE:-$MODE: labelled bounded run}" > "$RUN/BUDGET.txt"
fi
if [ "$BUDGET_CLASS" = replay ] && [ -n "${GRAPH_READY:-}" ]; then
    python3 - "$GRAPH_READY" "$RUN/GRAPH-READY.json" <<'PY'
import json, os, sys
r = json.load(open(sys.argv[1])); base = os.path.dirname(os.path.abspath(sys.argv[1]))
A = lambda p: p if (p is None or os.path.isabs(p)) else os.path.join(base, p)
for k in ('graph_tcl', 'checker', 'ledger'): r[k] = A(r.get(k))
if isinstance(r.get('basis_run'), dict):
    for k in ('run_dir', 'log'): r['basis_run'][k] = A(r['basis_run'].get(k))
json.dump(r, open(sys.argv[2], 'w'), indent=1)
PY
fi
if [ "$MODE" = session ]; then
    # Requests may be sent at once: send.sh waits while the job is pending.
    mkdir -p "$RUN/io"; rm -f "$RUN/io/"*.req "$RUN/io/"*.reqtmp "$RUN/io/"*.resp "$RUN/io/"*.tmp
    echo "$JOB" > "$RUN/io/session.jobid"
fi
echo "$JOB"
