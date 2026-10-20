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
`eval` counts selected cube samples where EXPR is true/false; EXPR is Python over
`v`, a dict from vector name to value (unknown `v.get(name)` is unconstrained when the cube
does not constrain that vector). `polarity` looks at the generalized cubes
(at most --max-lits literals) and reports, per vector, how many of its bits
occur with both polarities. Mixed polarity is a heuristic for vocabulary choice,
not proof of a missing invariant. These definitions are engine cube samples;
their size alone does not establish a reachable CTI or obligation witness.
"""
import argparse
import json
import re
from collections import Counter, defaultdict

BIT = re.compile(r'^(.*)\[(\d+)\]$')


def generalized_polarity(path, run_index, max_lits):
    with open(path) as stream:
        run = list(json.load(stream)["runs"].values())[run_index]
    model = run["model"]
    shift, sign = int(model["formula_index_shift"]), int(model["formula_sign_mask"])
    comp = int(model["formula_composite_mask"])
    names = run["signal_names"]
    # Literal count alone does not identify a generalization result. A small
    # query/block input may have different scope from the returned cube.
    outputs = {str(row['after_cube_id']) for row in run.get('generalization_relations', [])}
    pol = defaultdict(lambda: [0, 0])
    ncubes = 0
    for ident, cube in run["cube_definitions"].items():
        if str(ident) not in outputs or cube.get("domain")!="jip_formula" or not 0 < cube["count"] <= max_lits or not cube.get("complete"):
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


def basis_states(path, run_index, min_lits, widths=None):
    with open(path) as stream:
        run = list(json.load(stream)["runs"].values())[run_index]
    model = run["model"]
    shift = int(model["formula_index_shift"])
    sign = int(model["formula_sign_mask"])
    comp = int(model["formula_composite_mask"])
    names = run["signal_names"]
    for cube in run["cube_definitions"].values():
        if cube.get("domain")!="jip_formula" or cube["count"] < min_lits or not cube.get("complete"):
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
        # Retained names do not prove a vector's RTL width. Missing bits are
        # unconstrained, not zero. Scalar names constrain their single bit.
        result={}
        for k,d in bits.items():
            scalar=k in names.values() or '~'+k in names.values()
            width=1 if scalar else (widths or {}).get(k)
            result[k]=sum(b<<i for i,b in d.items()) if isinstance(width,int) and width>0 and set(d)==set(range(width)) else None
        yield result


class Unconstrained(ValueError):
    pass
class KnownValues(dict):
    def __getitem__(self,key):
        value=super().get(key)
        if value is None:raise Unconstrained(key)
        return value
    def get(self,key,default=None):
        # A caller-provided default must not manufacture an unconstrained bit.
        return self[key]
def evaluate(expr,state):
    try:return bool(eval(expr,{"v":KnownValues(state)}))
    except (Unconstrained,TypeError,KeyError):return "unconstrained"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("analysis")
    ap.add_argument("run", type=int)
    ap.add_argument("cmd", choices=["vectors", "table", "eval", "polarity"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--min-lits", type=int, default=1000)
    ap.add_argument("--max-lits", type=int, default=200)
    ap.add_argument("--match")
    ap.add_argument("--widths", help="JSON object of independently verified RTL vector widths; sparse values stay unknown")
    a = ap.parse_args()
    if a.cmd == "polarity":
        ncubes, vec = generalized_polarity(a.analysis, a.run, a.max_lits)
        print(f"observed generalization output cubes: {ncubes} (<= {a.max_lits} literals; native transformation, not a validity certificate)")
        for base, (bits, mixed) in sorted(vec.items(), key=lambda kv: (-kv[1][1], -kv[1][0], kv[0])):
            print(f"{bits:5d} bits {mixed:5d} mixed  {base}")
        return
    widths=json.load(open(a.widths)) if a.widths else None
    states = list(basis_states(a.analysis, a.run, a.min_lits,widths))
    print(f"basis states: {len(states)} (cubes with >= {a.min_lits} literals)")
    if a.cmd == "vectors":
        seen = defaultdict(set)
        for s in states:
            for k, val in s.items():
                seen[k].add(val)
        pat = re.compile(a.match) if a.match else None
        for k, vals in sorted(seen.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            if pat is None or pat.search(k):
                known=sorted(x for x in vals if x is not None)
                print(f"{len(known):5d} distinct  {k}  e.g. {', '.join(hex(x) for x in known[:4])} unknown={None in vals}")
    elif a.cmd == "table":
        rows = Counter(tuple(s.get(k) for k in a.args) for s in states)
        print("(" + ", ".join(a.args) + "): count")
        for key, n in rows.most_common():
            print(f"  {key} {n}")
    else:
        expr = compile(a.args[0], "<expr>", "eval")
        res = Counter()
        for s in states:
            res[evaluate(expr,s)] += 1
        print(f"true={res[True]} false={res[False]} unconstrained={res['unconstrained']}")


if __name__ == "__main__":
    main()
