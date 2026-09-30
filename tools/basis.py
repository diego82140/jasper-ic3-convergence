#!/usr/bin/env python3
"""Reconstruct full M/M4 CTI and obligation cubes ("basis states") from a
`jipstats --analyse ... --details` output and inspect them.

    basis.py ANALYSIS.json RUN vectors [--min-lits N] [--match REGEX]
    basis.py ANALYSIS.json RUN table   VEC [VEC ...]   [--min-lits N]
    basis.py ANALYSIS.json RUN eval    'EXPR'          [--min-lits N]
    basis.py ANALYSIS.json RUN polarity                [--max-lits N]

RUN is the index of the run in the analysis (runs appear in execution order).
Values are decoded per vector (bits `name[i]`); latches whose retained name
starts with `~` are held inverted by the engine and are complemented here.
`eval` counts basis states where EXPR is true/false; EXPR is Python over
`v`, a dict from vector name to value (`v.get(name)` is None when the cube
does not constrain that vector). `polarity` looks at the generalized cubes
(at most --max-lits literals) and reports, per vector, how many of its bits
occur with both polarities: mixing over raw bits means the missing invariant
is not unate in that vocabulary.
"""
import argparse
import json
import re
from collections import Counter, defaultdict

BIT = re.compile(r'^(.*)\[(\d+)\]$')


def generalized_polarity(path, run_index, max_lits):
    run = list(json.load(open(path))["runs"].values())[run_index]
    model = run["model"]
    shift, sign = int(model["formula_index_shift"]), int(model["formula_sign_mask"])
    comp = int(model["formula_composite_mask"])
    names = run["signal_names"]
    pol = defaultdict(lambda: [0, 0])
    ncubes = 0
    for cube in run["cube_definitions"].values():
        if not 0 < cube["count"] <= max_lits or not cube.get("complete"):
            continue
        ncubes += 1
        for lit in cube["values"]:
            name = names.get(str(lit >> shift))
            if lit & comp or name is None:
                continue
            value = 0 if lit & sign else 1
            if name.startswith("~"):
                name, value = name[1:], value ^ 1
            pol[name][value] += 1
    vec = defaultdict(lambda: [0, 0])
    for name, (neg, pos) in pol.items():
        m = BIT.match(name)
        base = m.group(1) if m else name
        vec[base][0] += 1
        vec[base][1] += 1 if neg and pos else 0
    return ncubes, vec


def basis_states(path, run_index, min_lits):
    run = list(json.load(open(path))["runs"].values())[run_index]
    model = run["model"]
    shift = int(model["formula_index_shift"])
    sign = int(model["formula_sign_mask"])
    comp = int(model["formula_composite_mask"])
    names = run["signal_names"]
    for cube in run["cube_definitions"].values():
        if cube["count"] < min_lits or not cube.get("complete"):
            continue
        bits = defaultdict(dict)
        for lit in cube["values"]:
            if lit & comp:
                continue
            name = names.get(str(lit >> shift))
            if name is None:
                continue
            value = 0 if lit & sign else 1
            if name.startswith("~"):
                name, value = name[1:], value ^ 1
            m = BIT.match(name)
            base, idx = (m.group(1), int(m.group(2))) if m else (name, 0)
            bits[base][idx] = value
        yield {k: sum(b << i for i, b in d.items()) for k, d in bits.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("analysis")
    ap.add_argument("run", type=int)
    ap.add_argument("cmd", choices=["vectors", "table", "eval", "polarity"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--min-lits", type=int, default=1000)
    ap.add_argument("--max-lits", type=int, default=200)
    ap.add_argument("--match")
    a = ap.parse_args()
    if a.cmd == "polarity":
        ncubes, vec = generalized_polarity(a.analysis, a.run, a.max_lits)
        print(f"generalized cubes: {ncubes} (<= {a.max_lits} literals)")
        for base, (bits, mixed) in sorted(vec.items(), key=lambda kv: (-kv[1][1], -kv[1][0], kv[0]))[:40]:
            print(f"{bits:5d} bits {mixed:5d} mixed  {base}")
        return
    states = list(basis_states(a.analysis, a.run, a.min_lits))
    print(f"basis states: {len(states)} (cubes with >= {a.min_lits} literals)")
    if a.cmd == "vectors":
        seen = defaultdict(set)
        for s in states:
            for k, val in s.items():
                seen[k].add(val)
        pat = re.compile(a.match) if a.match else None
        for k, vals in sorted(seen.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            if pat is None or pat.search(k):
                print(f"{len(vals):5d} distinct  {k}  e.g. {', '.join(hex(x) for x in sorted(vals)[:4])}")
    elif a.cmd == "table":
        rows = Counter(tuple(s.get(k) for k in a.args) for s in states)
        print("(" + ", ".join(a.args) + "): count")
        for key, n in rows.most_common(30):
            print(f"  {key} {n}")
    else:
        expr = compile(a.args[0], "<expr>", "eval")
        res = Counter()
        for s in states:
            try:
                res[bool(eval(expr, {"v": s}))] += 1   # v as a global, so comprehensions in EXPR see it
            except (TypeError, KeyError):
                res["unconstrained"] += 1
        print(f"true={res[True]} false={res[False]} unconstrained={res['unconstrained']}")


if __name__ == "__main__":
    main()
