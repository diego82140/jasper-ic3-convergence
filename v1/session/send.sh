#!/usr/bin/env bash
# Send Tcl to a running session/server.tcl and print its result.
# Usage: send.sh <io_dir> <tcl_file | -> [wait_s]   ("-" reads Tcl from stdin)
# Waits for the response without a time limit unless wait_s is given (the
# request keeps running in the session either way). When the session runs as
# a Slurm job (io_dir/session.jobid, written by slurm/submit.sh), a job that
# has ended is detected instead of waiting forever.
# Exit status is the request's Tcl rc (0 ok, 1 error), 124 when wait_s expired,
# 125 if the session is not running.
set -euo pipefail
io=$1
src=$2
wait_s=${3:-0}
SLURM_BIN=${SLURM_BIN:-/netbatch/bin}

[ -d "$io" ] || { echo "no session io dir: $io" >&2; exit 125; }
job=
[ -f "$io/session.jobid" ] && job=$(cat "$io/session.jobid")
alive() { [ -z "$job" ] || "$SLURM_BIN/squeue" -h -j "$job" 2>/dev/null | grep -q .; }
alive || { echo "session job $job is not running" >&2; exit 125; }

id=$(date +%s%N)
if [ "$src" = "-" ]; then
    cat > "$io/$id.reqtmp"
else
    cp "$src" "$io/$id.reqtmp"
fi
mv "$io/$id.reqtmp" "$io/$id.req"

start=$SECONDS; last=$SECONDS
while [ ! -f "$io/$id.resp" ]; do
    if [ "$wait_s" -gt 0 ] && [ $((SECONDS - start)) -ge "$wait_s" ]; then
        echo "request $id still running after ${wait_s}s (response will be $io/$id.resp)" >&2
        exit 124
    fi
    if [ $((SECONDS - last)) -ge 30 ]; then
        last=$SECONDS
        if ! alive; then
            # A job that answered and then exited (session_stop) can finish before
            # its response is visible here on a network filesystem: allow for that.
            for _ in $(seq 1 60); do
                ls "$io" > /dev/null 2>&1; [ -f "$io/$id.resp" ] && break; sleep 1
            done
            if [ ! -f "$io/$id.resp" ]; then
                rm -f "$io/$id.req"
                echo "session job $job ended before answering request $id" >&2
                exit 125
            fi
        fi
    fi
    sleep 0.5
done

rc=$(head -1 "$io/$id.resp" | sed 's/^rc=//')
tail -n +2 "$io/$id.resp"
rm -f "$io/$id.resp"
exit "$rc"
