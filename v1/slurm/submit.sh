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
#       Telemetry capture: <run_dir>/capture.log.
#
#   submit.sh check   <run_dir>
#       jipstats --check <jasper> (native M/M4 self-test) on a node.
#
# <run_dir> must be on a filesystem the nodes see (not the agent host's /tmp);
# it receives jg.log (job output), job.env, job.id and jgproject/. <launch_dir>
# is where the project Tcl expects to start (its relative paths resolve there).
# Prints the Slurm job id. The job has no time limit and adds none to proofs.
#
# Environment (optional):
#   JASPER        Jasper installation (default below)
#   PASS_ENV      names of further variables the project Tcl reads (space or comma separated)
#                 (HOME, USER and LM_LICENSE_FILE are always passed)
#   PARTITION     Slurm partition (default Formal)
#   CPUS, MEM     job resources (default 4, 32G); the coordinator, plus any engine
#                 the project does not dispatch as its own Slurm jobs, runs in them
#   ALLOW_UNSUPPORTED_OS  1 (default) = Jasper -allow_unsupported_OS; the Formal
#                 nodes run an OS the installed Jasper does not list
#   SLURM_BIN     directory of sbatch/squeue/scancel (default /netbatch/bin)
#   JOB_NAME      Slurm job name (default jasper-<mode>)
#=============================================================================
set -euo pipefail
AGENT=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)
JASPER=${JASPER:-/projects/external_ip/cadence/jasper_2026.0920260826065032}
SLURM_BIN=${SLURM_BIN:-/netbatch/bin}

usage() { sed -n '4,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 2 ] || usage
MODE=$1; RUN=$2; shift 2
case $MODE in
    batch)   [ $# -ge 2 ] || usage; LAUNCH=$1; TCL=$2; shift 2 ;;
    session) [ $# -ge 1 ] || usage; LAUNCH=$1; TCL=$AGENT/session/server.tcl; shift ;;
    check)   LAUNCH=$RUN; TCL= ;;
    *) usage ;;
esac

: "${LM_LICENSE_FILE:?LM_LICENSE_FILE must be set (the license server of the installed Jasper)}"
mkdir -p "$RUN"
RUN=$(cd "$RUN" && pwd); LAUNCH=$(cd "$LAUNCH" && pwd)
[ -z "$TCL" ] || TCL=$(cd "$LAUNCH" && readlink -f "$TCL")   # relative to <launch_dir>, like Jasper
[ -z "$TCL" ] || [ -f "$TCL" ] || { echo "submit.sh: no Tcl file $TCL" >&2; exit 2; }
[ -x "$JASPER/bin/jaspergold" ] || { echo "submit.sh: no Jasper at $JASPER" >&2; exit 2; }
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
    printf 'ALLOW_UNSUPPORTED_OS=%q\n' "${ALLOW_UNSUPPORTED_OS:-1}"
    printf 'PASS=(%q %q %q' "HOME=$HOME" "USER=$USER" "LM_LICENSE_FILE=$LM_LICENSE_FILE"
    for v in $(echo "${PASS_ENV:-}" | tr , " "); do
        [ -n "${!v+x}" ] || { echo "submit.sh: PASS_ENV names $v, which is not set" >&2; exit 2; }
        printf ' %q' "$v=${!v}"
    done
    printf ')\n'
} > "$RUN/job.env"

JOB=$("$SLURM_BIN/sbatch" --parsable \
    --job-name="${JOB_NAME:-jasper-$MODE}" --partition="${PARTITION:-Formal}" \
    --cpus-per-task="${CPUS:-4}" --mem="${MEM:-32G}" \
    --export="NONE,IC3_JOB_ENV=$RUN/job.env" --output="$RUN/jg.log" \
    "$AGENT/slurm/jasper_job.sh" "$@")
echo "$JOB" > "$RUN/job.id"
if [ "$MODE" = session ]; then
    # Requests may be sent at once: send.sh waits while the job is pending.
    mkdir -p "$RUN/io"; rm -f "$RUN/io/"*.req "$RUN/io/"*.reqtmp "$RUN/io/"*.resp "$RUN/io/"*.tmp
    echo "$JOB" > "$RUN/io/session.jobid"
fi
echo "$JOB"
