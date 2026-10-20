#!/bin/bash
#SBATCH --ntasks=1
#SBATCH --ntasks-per-core=1
#=============================================================================
# jasper_job.sh -- the Slurm job submitted by submit.sh; do not sbatch it directly.
# No --time of its own: submit.sh adds --time=BUDGET+margin to every run.
# Arguments are passed to Jasper after the -tcl file.
#=============================================================================
set -euo pipefail
umask 022   # run directories are shared evidence: everything Jasper writes stays world-readable
: "${IC3_JOB_ENV:?started without submit.sh}"
source "$IC3_JOB_ENV"
if [ -f "$RUN/plugin-artifact.json" ]; then
    ARTIFACT_SHA=$(python3 "$AGENT/tools/artifact_manifest.py" "$AGENT" --verify "$RUN/plugin-artifact.json")
    echo "IC3_JOB plugin_runtime_sha256=$ARTIFACT_SHA"
fi
cd "$LAUNCH"
echo "IC3_JOB node=$(hostname) job=${SLURM_JOB_ID:-none} mode=$MODE launch=$LAUNCH tcl=$TCL jasper=$JASPER"

# Clean, explicit environment: nothing from the agent host leaks into Jasper.
ENVV=(PATH=/usr/bin:/bin LOGNAME="$USER" LANG=en_US.UTF-8 TMPDIR="${TMPDIR:-/tmp}"
      SLURM_JOB_ID="${SLURM_JOB_ID:-}" "${PASS[@]}")

python3 "$AGENT/tools/rss_monitor.py" "$$" "$RUN/rss.csv" &
MONITOR_PID=$!
trap 'kill "$MONITOR_PID" 2>/dev/null || true; wait "$MONITOR_PID" 2>/dev/null || true' EXIT
rc=0
case $MODE in
batch)
    JG_ARGS=(-batch -proj "$RUN/jgproject")
    [ "$ALLOW_UNSUPPORTED_OS" = 0 ] || JG_ARGS+=(-allow_unsupported_OS)
    env -i "${ENVV[@]}" "${JASPER_LAUNCHER:-$JASPER/bin/jaspergold}" "${JG_ARGS[@]}" -tcl "$TCL" "$@" </dev/null || rc=$?
    ;;
session|diagnostic)
    mkdir -p "$RUN/io"
    echo "${SLURM_JOB_ID:-}" > "$RUN/io/session.jobid"
    JS_ARGS=(--sink "$TELEMETRY_SINK" --capture-mode full --frame-encoding "${FRAME_ENCODING:-tuple_chunks_v2}")
    [ "$TELEMETRY_SINK" != disk ] || JS_ARGS+=(--compression gzip)
    [ "$ALLOW_UNSUPPORTED_OS" = 0 ] || JS_ARGS+=(--allow-unsupported-os)
    DISPLAY_ARGS=()
    JG_ARGS=(-batch)
    if [ "$MODE" = diagnostic ] && [ "$DIAGNOSTIC_GUI" = 1 ]; then
        JG_ARGS=(); DISPLAY_ARGS=(python3 "$AGENT/tools/with_display.py" "$RUN")
    fi
    # Telemetry bypasses the GUI; capture.log contains ordinary messages only.
    /usr/bin/time -v -o "$RUN/resources.txt" "${DISPLAY_ARGS[@]}" env -i "${ENVV[@]}" JG_SESSION_DIR="$RUN/io" "$AGENT/jipstats" --evidence-dir "$RUN/telemetry" "${JS_ARGS[@]}" "$JASPER" \
        "${JG_ARGS[@]}" -proj "$RUN/jgproject" -tcl "$TCL" "$@" > "$RUN/capture.log" 2>&1 </dev/null || rc=$?
    ;;
check)
    # Keep forced fresh-check receipts in the run unless a cache was explicitly
    # passed. An ordinary launch can reuse the exact producer key/provenance.
    CHECK_CACHE="$RUN/cache"
    for setting in "${PASS[@]}"; do
        case $setting in XDG_CACHE_HOME=*) CHECK_CACHE=${setting#XDG_CACHE_HOME=} ;; esac
    done
    ENVV+=(XDG_CACHE_HOME="$CHECK_CACHE")
    JS_ARGS=(--sink "$TELEMETRY_SINK" --capture-mode full --frame-encoding "${FRAME_ENCODING:-tuple_chunks_v2}")
    [ "$TELEMETRY_SINK" != disk ] || JS_ARGS+=(--compression gzip)
    [ "$ALLOW_UNSUPPORTED_OS" = 0 ] || JS_ARGS+=(--allow-unsupported-os)
    env -i "${ENVV[@]}" "$AGENT/jipstats" "${JS_ARGS[@]}" --check "$JASPER" </dev/null || rc=$?
    ;;
esac
echo "IC3_JOB jasper exited rc=$rc"
exit "$rc"
