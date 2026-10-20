#!/usr/bin/env python3
"""Bounded-prove gate for Tcl sent to Jasper (session requests and batch/diagnostic Tcl).

    python3 prove_gate.py FILE.tcl --max 60m

Exit 0 when every `prove` that starts a proof in FILE is bounded by at most --max:
either by its own `-time_limit <t>` or by a `set_prove_time_limit <t>` anywhere in
the file (Jasper's default limit for proves without their own), with every such
limit <= --max. Exit 3 with the offending line on stderr otherwise.

Scope (stated, not hidden): this is a textual gate over one file. It does not
follow `source`d files, limits held in variables, commands built by `eval`, or
code under a false `if`; a sourced project setup can even raise the limit after
this file set it. The Slurm --time backstop that submit.sh adds to every run and
the elapsed-time check of tools/audit.py are the controls for those cases; a run
cut by that backstop has no certificate and an unsealed telemetry archive.
It assumes the release accepts `prove -time_limit` and `set_prove_time_limit`;
confirm with `help prove` on a new release.
`prove -status/-stop/-wait/-list/-report` do not start a proof and are exempt.
Backslash line continuations are joined before scanning; `::prove` is matched.
"""
import re, sys, argparse

UNIT = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
EXEMPT = ('-status', '-stop', '-wait', '-list', '-report')
STARTERS = ('-property', '-all', '-task', '-from', '-bg', '-covers', '-asserts')
PROVE = re.compile(r'(?<![\w.-])(?:[\w]*::)*prove\b')
SETLIM = re.compile(r'(?<![\w.-])(?:[\w]*::)*set_prove_time_limit\s+(\S+)')

def seconds(tok):
    """Jasper time literal -> seconds, or None when not a bounded literal."""
    tok = tok.strip('{}"')
    m = re.fullmatch(r'(\d+(?:\.\d+)?)([smhd]?)', tok)
    if m:
        v = float(m.group(1)) * UNIT[m.group(2) or 's']
        return v if v > 0 else None
    m = re.fullmatch(r'(\d+):(\d\d):(\d\d)', tok)
    if m:
        h, mi, s = map(int, m.groups()); v = h * 3600 + mi * 60 + s
        return v if v > 0 else None
    return None

def prove_calls(line):
    """Yield the argument strings of each `prove` command on a line."""
    for m in PROVE.finditer(line):
        rest = line[m.end():]
        cut = re.search(r'[;\]]', rest)
        yield rest[:cut.start()] if cut else rest

def check(path, max_s):
    text = open(path, encoding='utf-8', errors='replace').read()
    text = re.sub(r'\\\r?\n', ' ', text)                 # join continuations
    lines = [l for l in text.splitlines() if not l.lstrip().startswith('#')]
    defaults = []
    for l in lines:
        for m in SETLIM.finditer(l):
            defaults.append((seconds(m.group(1)), m.group(1), l.strip()))
    for v, tok, l in defaults:
        if v is None or v > max_s:
            return 3, f'set_prove_time_limit {tok} is unbounded or above the cap: {l}'
    default_ok = bool(defaults)
    for l in lines:
        for args in prove_calls(l):
            toks = args.split()
            if any(t in EXEMPT for t in toks) and not any(t in STARTERS for t in toks):
                continue
            lim = None
            for i, t in enumerate(toks):
                if t == '-time_limit' and i + 1 < len(toks):
                    lim = toks[i + 1]
            if lim is None:
                if default_ok: continue
                return 3, f'prove without -time_limit and no set_prove_time_limit in file: {l.strip()}'
            v = seconds(lim)
            if v is None:
                return 3, f'prove -time_limit {lim} is not a bounded literal: {l.strip()}'
            if v > max_s:
                return 3, f'prove -time_limit {lim} exceeds the cap: {l.strip()}'
    return 0, 'all proves bounded'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file'); ap.add_argument('--max', default='60m')
    a = ap.parse_args()
    cap = seconds(a.max)
    if cap is None:
        print(f'prove_gate: bad --max {a.max}', file=sys.stderr); return 2
    rc, msg = check(a.file, cap)
    print(('prove_gate: ' if rc == 0 else 'prove_gate: refused: ') + msg, file=sys.stderr if rc else sys.stdout)
    return rc

if __name__ == '__main__':
    sys.exit(main())
