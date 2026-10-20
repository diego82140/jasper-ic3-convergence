#!/usr/bin/env python3
"""Validate a GRAPH-READY receipt: the file-linked declaration that justifies the
budget of a cold proof-graph replay (BUDGET_CLASS=replay in slurm/submit.sh).

    python3 graph_ready.py validate RECEIPT.json [--no-freshness]

Exit 0, print "GRAPH-READY OK max_budget_s=<n> basis_total_s=<m>" when the
receipt is admissible; otherwise print every failure and exit 1.

There is no unlimited run. A replay is admitted with a budget of at most
replay_factor x the measured basis time, where the *basis run* is a bounded,
labelled run of the SAME proof-graph Tcl (same graph and checker hashes, so the
same levels, the same order and therefore the same eligible context per level)
in which every node and every cover reported proven/covered. The basis may have
run warm (ProofMaster on); the replay runs it cold. A basis is evidence of
feasibility, not a guarantee: a replay that reaches its budget is an interrupted
experiment with no certificate.

The validator checks declared fields, file existence, hashes, and the basis
run's own log lines; it cannot verify a status against Jasper. A false claim
does not run forever: the replay is budgeted, and its result lines are what count.

The proof-graph Tcl must print (see example/proof_graph.tcl):
  GRAPH_INPUTS graph_sha256=<hex> checker_sha256=<hex|none>
  GRAPH_NODES <name> ...            every assertion it proves (target and helpers)
  GRAPH_COVERS <name> ...           every cover it proves (may be empty)
  PROOFMASTER <on|off>
  RESULT <name> <status> <validity_status> <engine> <time_s>   one per node/cover

Receipt fields:
  target              exact property name (must be in GRAPH_NODES)
  created_utc         ISO-8601; at most 48 h old (skipped with --no-freshness)
  graph_tcl, graph_tcl_sha256, checker (null only when helpers is empty), checker_sha256
  basis_run           {run_dir, log}: run_dir holds a parseable BUDGET.txt; log holds
                      GRAPH_INPUTS equal to the receipt hashes, GRAPH_NODES/GRAPH_COVERS,
                      and RESULT lines: every node "proven proven" with engine != Cache,
                      every cover "covered covered"
  replay_factor       number in [1, 8] (default 4)
  helpers             list of {name (in GRAPH_NODES), consumer (target or another helper;
                      chains must end at the target, no cycles), witness in
                      {sufficiency, cti-exclusion-checked, cti-exclusion-hand},
                      covers: [{name (in GRAPH_COVERS)}] or [] with covers_note}
  open_base_cases     list; must be empty
  ledger, ledger_sha256 (hash skipped with --no-freshness)
Relative paths in the receipt resolve against the receipt's own directory.
"""
import hashlib, json, sys, datetime, os, re

WITNESSES = {'sufficiency', 'cti-exclusion-checked', 'cti-exclusion-hand'}

def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()

def read_log(path, limit=64 << 20):
    with open(path, 'r', errors='replace') as f:
        return f.read(limit)

def parse_log(text):
    """GRAPH_* and RESULT lines -> dict (token-exact, last occurrence wins)."""
    d = {'nodes': None, 'covers': None, 'inputs': None, 'proofmaster': None, 'results': {}}
    for line in text.splitlines():
        t = line.split()
        if not t: continue
        if t[0] == 'GRAPH_NODES': d['nodes'] = set(t[1:])
        elif t[0] == 'GRAPH_COVERS': d['covers'] = set(t[1:])
        elif t[0] == 'GRAPH_INPUTS':
            kv = dict(x.split('=', 1) for x in t[1:] if '=' in x); d['inputs'] = kv
        elif t[0] == 'PROOFMASTER' and len(t) > 1: d['proofmaster'] = t[1]
        elif t[0] == 'RESULT' and len(t) >= 6:
            try: tm = float(t[5])
            except ValueError: tm = None
            d['results'][t[1]] = {'status': t[2], 'validity': t[3], 'engine': t[4], 'time_s': tm}
    return d

def validate(path, max_age_hours=48, freshness=True):
    fails = []
    try:
        r = json.load(open(path))
    except Exception as e:
        return [f'unreadable receipt: {e}'], None
    base = os.path.dirname(os.path.abspath(path))
    P = lambda p: p if (p is None or os.path.isabs(p)) else os.path.join(base, p)
    for k in ('target', 'created_utc', 'graph_tcl', 'graph_tcl_sha256', 'checker', 'checker_sha256',
              'basis_run', 'helpers', 'open_base_cases', 'ledger', 'ledger_sha256'):
        if k not in r:
            fails.append(f'missing field {k}')
    if fails:
        return fails, None
    if freshness:
        try:
            t = datetime.datetime.fromisoformat(str(r['created_utc']).replace('Z', '+00:00'))
            age = (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 3600
            if age > max_age_hours:
                fails.append(f'receipt is {age:.1f} h old (max {max_age_hours})')
        except Exception as e:
            fails.append(f'bad created_utc: {e}')
    target = r['target']
    if not isinstance(target, str) or not target:
        fails.append('target must be a non-empty property name'); target = None
    g = P(r['graph_tcl']); gsha = None
    if not os.path.isfile(g):
        fails.append(f'graph_tcl missing: {g}')
    else:
        gsha = sha(g)
        if gsha != r['graph_tcl_sha256']:
            fails.append('graph_tcl_sha256 does not match the graph Tcl on disk')
    helpers = r['helpers'] if isinstance(r['helpers'], list) else []
    if not isinstance(r['helpers'], list):
        fails.append('helpers must be a list')
    csha = 'none'
    if helpers:
        c = P(r['checker'])
        if not c or not os.path.isfile(c):
            fails.append(f'checker missing: {c}')
        else:
            csha = sha(c)
            if csha != r['checker_sha256']:
                fails.append('checker_sha256 does not match the checker on disk')
    if r['open_base_cases']:
        fails.append(f"open base cases: {r['open_base_cases']}")
    try:
        factor = float(r.get('replay_factor', 4))
        if not (1 <= factor <= 8): fails.append('replay_factor must be in [1, 8]')
    except Exception:
        fails.append('replay_factor must be a number'); factor = 0
    # basis run
    b = r['basis_run'] if isinstance(r['basis_run'], dict) else {}
    log = P(b.get('log')); rd = P(b.get('run_dir'))
    parsed = None; basis_total = 0.0
    if not rd or not os.path.isfile(os.path.join(rd, 'BUDGET.txt')) or \
            not re.match(r'\s*\d+[smh]\b', open(os.path.join(rd, 'BUDGET.txt')).read() if rd and os.path.isfile(os.path.join(rd, 'BUDGET.txt')) else ''):
        fails.append(f'basis_run.run_dir {rd} has no parseable BUDGET.txt (the basis must be a bounded, labelled run)')
    if not log or not os.path.isfile(log):
        fails.append(f'basis_run.log missing: {log}')
    else:
        parsed = parse_log(read_log(log))
        if parsed['inputs'] is None:
            fails.append('basis log has no GRAPH_INPUTS line')
        else:
            if gsha and parsed['inputs'].get('graph_sha256') != gsha:
                fails.append('basis log GRAPH_INPUTS graph_sha256 differs from the graph Tcl (not the same graph)')
            if helpers and parsed['inputs'].get('checker_sha256') != csha:
                fails.append('basis log GRAPH_INPUTS checker_sha256 differs from the checker (not the same checker)')
        if parsed['nodes'] is None:
            fails.append('basis log has no GRAPH_NODES line')
        if parsed['covers'] is None:
            fails.append('basis log has no GRAPH_COVERS line')
        if parsed['proofmaster'] not in ('on', 'off'):
            fails.append('basis log has no PROOFMASTER on|off line')
        nodes = parsed['nodes'] or set(); covers = parsed['covers'] or set()
        if target and target not in nodes:
            fails.append(f'target {target} is not in GRAPH_NODES of the basis run')
        for n in sorted(nodes):
            res = parsed['results'].get(n)
            if not res:
                fails.append(f'node {n}: no RESULT line in the basis log')
            elif res['status'] != 'proven' or res['validity'] != 'proven':
                fails.append(f"node {n}: basis RESULT {res['status']}/{res['validity']} is not proven/proven")
            elif res['engine'].lower().startswith('cache'):
                fails.append(f'node {n}: basis result came from the Cache engine (not a measured proof)')
            else:
                basis_total += res['time_s'] or 0.0
        for n in sorted(covers):
            res = parsed['results'].get(n)
            if not res:
                fails.append(f'cover {n}: no RESULT line in the basis log')
            elif res['status'] != 'covered' or res['validity'] != 'covered':
                fails.append(f"cover {n}: basis RESULT {res['status']}/{res['validity']} is not covered/covered")
            else:
                basis_total += res['time_s'] or 0.0
    # helpers
    names = {h.get('name') for h in helpers}
    for h in helpers:
        name = h.get('name', '?')
        for k in ('name', 'consumer', 'witness', 'covers'):
            if k not in h:
                fails.append(f'helper {name}: missing {k}')
        if h.get('witness') not in WITNESSES:
            fails.append(f'helper {name}: witness must be one of {sorted(WITNESSES)}')
        if parsed and parsed['nodes'] is not None and name not in parsed['nodes']:
            fails.append(f'helper {name}: not in GRAPH_NODES of the basis run')
        covers = h.get('covers')
        if not isinstance(covers, list):
            fails.append(f'helper {name}: covers must be a list')
        elif not covers:
            if not h.get('covers_note'):
                fails.append(f'helper {name}: no covers and no covers_note explaining why no nonvacuity gate applies')
        else:
            for c in covers:
                cn = c.get('name') if isinstance(c, dict) else None
                if parsed and parsed['covers'] is not None and cn not in parsed['covers']:
                    fails.append(f'helper {name}: cover {cn} is not in GRAPH_COVERS of the basis run')
    # consumer chains end at the target
    for h in helpers:
        seen = set(); cur = h.get('name')
        while True:
            if cur in seen:
                fails.append(f"helper {h.get('name')}: consumer chain is cyclic"); break
            seen.add(cur)
            nxt = next((x.get('consumer') for x in helpers if x.get('name') == cur), None)
            if nxt == target: break
            if nxt not in names:
                fails.append(f"helper {h.get('name')}: consumer chain ends at {nxt!r}, not at the target"); break
            cur = nxt
    if not os.path.isfile(P(r['ledger'])):
        fails.append(f"ledger missing: {r['ledger']}")
    elif freshness and sha(P(r['ledger'])) != r['ledger_sha256']:
        fails.append('ledger_sha256 does not match the ledger on disk (receipt is stale)')
    info = {'basis_total_s': basis_total, 'max_budget_s': factor * basis_total}
    return fails, info

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    flags = {a for a in sys.argv[1:] if a.startswith('--')}
    if len(args) != 2 or args[0] != 'validate':
        print(__doc__); return 2
    fails, info = validate(args[1], freshness='--no-freshness' not in flags)
    if fails:
        for f in fails: print('GRAPH-READY FAIL:', f)
        return 1
    print(f"GRAPH-READY OK max_budget_s={int(info['max_budget_s'])} basis_total_s={int(info['basis_total_s'])} {args[1]}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
