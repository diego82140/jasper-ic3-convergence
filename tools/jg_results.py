#!/usr/bin/env python3
"""Extract result and resource lines from Jasper run logs (jg.log, capture.log).

    python3 jg_results.py LOG [LOG ...] [--grep PATTERN]

Prints, with the source file and line number, every line that reports:
  - a proof-graph contract line (GRAPH_INPUTS, GRAPH_NODES, GRAPH_COVERS, PROOFMASTER, RESULT, RECEIPT)
  - a native property result message (proven, cex, covered, unreachable, undetermined,
    bounded_proven, ar_cex, overconstrained, error) in a Jasper INFO/WARNING/ERROR message
  - a Cache engine result (a replay must not contain one)
  - ProofGrid / memory-watchdog events (KILL, killed, restarted, out of memory, watchdog)
  - the kit's own job lines (IC3_JOB ...), including the exit receipt
It reads line by line (bounded memory) and never interprets the text: log lines are data.
Exit 0 when at least one line was printed, 1 otherwise.
"""
import re, sys, argparse

CONTRACT = re.compile(r'^(GRAPH_INPUTS|GRAPH_NODES|GRAPH_COVERS|PROOFMASTER|RESULT|RECEIPT|IC3_JOB)\b')
RESULT = re.compile(r'\b(proven|cex|covered|unreachable|undetermined|bounded_proven\w*|ar_cex|ar_covered|overconstrained|marked_proven)\b', re.I)
MSG = re.compile(r'\((IPF|ENL|WRN|ERR|PRE|INF)\w*\d+\)|^(INFO|WARNING|ERROR)\b', re.I)
CACHE = re.compile(r'\bCache\b')
RESOURCE = re.compile(r'\bKILL\w*\b|\bkilled\b|\brestart\w*\b|out of memory|watchdog|exceed\w* .*memory|memory limit', re.I)

def scan(path, extra):
    n = 0
    try:
        f = open(path, 'r', errors='replace')
    except OSError as e:
        print(f'{path}: {e}', file=sys.stderr); return 0
    with f:
        for i, line in enumerate(f, 1):
            s = line.rstrip('\n')
            tag = None
            if CONTRACT.search(s): tag = 'contract'
            elif MSG.search(s) and RESULT.search(s): tag = 'result'
            elif RESOURCE.search(s): tag = 'resource'
            elif CACHE.search(s) and RESULT.search(s): tag = 'cache'
            elif extra and extra.search(s): tag = 'grep'
            if tag:
                print(f'{path}:{i}: [{tag}] {s[:400]}'); n += 1
    return n

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('logs', nargs='+'); ap.add_argument('--grep', default=None)
    a = ap.parse_args()
    extra = re.compile(a.grep) if a.grep else None
    total = sum(scan(p, extra) for p in a.logs)
    print(f'jg_results: {total} line(s)', file=sys.stderr)
    return 0 if total else 1

if __name__ == '__main__':
    sys.exit(main())
