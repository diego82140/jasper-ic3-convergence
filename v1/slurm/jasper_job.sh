#!/bin/bash
#SBATCH --ntasks=1
#SBATCH --ntasks-per-core=1
#=============================================================================
# jasper_job.sh -- the Slurm job submitted by submit.sh; do not sbatch it directly.
# No --time: a proof must never be cut off by a job time limit.
# Arguments are passed to Jasper after the -tcl file.
#=============================================================================
set -euo pipefail
: "${IC3_JOB_ENV:?started without submit.sh}"
source "$IC3_JOB_ENV"
cd "$LAUNCH"
echo "IC3_JOB node=$(hostname) job=${SLURM_JOB_ID:-none} mode=$MODE launch=$LAUNCH tcl=$TCL jasper=$JASPER"

# Clean, explicit environment: nothing from the agent host leaks into Jasper.
ENVV=(PATH=/usr/bin:/bin LOGNAME="$USER" LANG=en_US.UTF-8 TMPDIR="${TMPDIR:-/tmp}"
      SLURM_JOB_ID="${SLURM_JOB_ID:-}" "${PASS[@]}")

rc=0
case $MODE in
batch)
    JG_ARGS=(-batch -proj "$RUN/jgproject")
    [ "$ALLOW_UNSUPPORTED_OS" = 0 ] || JG_ARGS+=(-allow_unsupported_OS)
    env -i "${ENVV[@]}" "$JASPER/bin/jaspergold" "${JG_ARGS[@]}" -tcl "$TCL" "$@" </dev/null || rc=$?
    ;;
session)
    mkdir -p "$RUN/io"
    echo "${SLURM_JOB_ID:-}" > "$RUN/io/session.jobid"
    JS_ARGS=()
    [ "$ALLOW_UNSUPPORTED_OS" = 0 ] || JS_ARGS+=(--allow-unsupported-os)
    # The capture is written by jipstats alone (no --live), for --analyse.
    env -i "${ENVV[@]}" JG_SESSION_DIR="$RUN/io" "$AGENT/jipstats" "${JS_ARGS[@]}" "$JASPER" \
        -batch -proj "$RUN/jgproject" -tcl "$TCL" "$@" > "$RUN/capture.log" 2>&1 </dev/null || rc=$?
    ;;
check)
    JS_ARGS=()
    [ "$ALLOW_UNSUPPORTED_OS" = 0 ] || JS_ARGS+=(--allow-unsupported-os)
    env -i "${ENVV[@]}" "$AGENT/jipstats" "${JS_ARGS[@]}" --check "$JASPER" </dev/null || rc=$?
    ;;
esac
echo "IC3_JOB jasper exited rc=$rc"
exit "$rc"
