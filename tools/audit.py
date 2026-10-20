#!/usr/bin/env python3
"""Round audit: mechanical self-check of the running proof work against the
method's budget rules. Run at the end of every round, and as the plugin's
Stop hook (with --hook it reads the hook JSON from stdin; exit 2 with the
reason on stderr blocks the stop until the violation is corrected; without
--hook stdin is never read, so a scripted call cannot hang).

    python3 audit.py [--workspace DIR] [--max-unlabeled-hours H] [--margin-hours M] [--strict] [--hook]

Scope (stated): it sees the jobs launched by slurm/submit.sh whose run directory
lies under the workspace (found through <run>/job.id). ProofGrid workers that
the project dispatches appear only through their head job; runs launched
elsewhere, or not through submit.sh, are not covered.

Checks (all read-only), for every such job that squeue reports:
  1. Label: <run>/BUDGET.txt ("<duration> class=<experiment|baseline|replay> ...");
     a replay also carries <run>/GRAPH-READY.json, validated structurally with
     graph_ready.py --no-freshness (the ledger may change and the receipt may
     age after launch). A job older than --max-unlabeled-hours with no label
     is a violation.
  2. Budget: class experiment at most 4 h; a job whose elapsed time exceeds its
     budget plus --margin-hours is a violation whatever its class.
  3. Liveness is verified, not assumed: when squeue is unavailable and some
     <run>/job.id under the workspace has no "IC3_JOB jasper exited" line in its
     jg.log, the audit cannot tell whether that job is live and fails closed.
Prints one line per job and a summary on stdout; in --strict mode a violation
exits 2 and prints the reason on stderr (hook semantics), else exit 0.
When invoked as a Stop hook with stop_hook_active=true (Claude is already
continuing because of this hook) the audit still reports but does not block
again, so a violation the agent cannot correct cannot trap the session.
squeue is taken from $SLURM_BIN (default /netbatch/bin); IC3_SQUEUE overrides
the executable for offline tests only.
"""
import argparse, json, os, re, subprocess, sys

EXPERIMENT_CAP_H = 4.0
SQUEUE = os.environ.get('IC3_SQUEUE') or os.path.join(os.environ.get('SLURM_BIN', '/netbatch/bin'), 'squeue')
SKIP_DIRS = {'telemetry', 'jgproject', 'cache', '.git', '__pycache__', 'rebuilt', 'source', 'third_party'}

def squeue(user):
    try:
        out = subprocess.run([SQUEUE, '-u', user, '-h', '-o', '%i %M %j'],
                             capture_output=True, text=True, timeout=20)
        if out.returncode != 0:
            return None, f'squeue rc={out.returncode}: {out.stderr.strip()[:200]}'
        out = out.stdout
    except Exception as e:
        return None, f'squeue unavailable: {e}'
    jobs = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 2:
            jobs[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else '')
    return jobs, None

def hours(elapsed):
    d, _, rest = elapsed.rpartition('-')
    h, *ms = rest.split(':')
    if len(ms) == 1:  # M:S
        return (int(d) * 24 if d else 0) + int(h) / 60
    return (int(d) * 24 if d else 0) + int(h) + int(ms[0]) / 60

def budget(text):
    """BUDGET.txt -> (hours or None, class)."""
    m = re.match(r'\s*(\d+(?:\.\d+)?)\s*([smhd])\b', text)
    c = re.search(r'\bclass=(\w+)', text)
    cls = c.group(1) if c else 'experiment'
    if not m: return None, cls
    v, u = float(m.group(1)), m.group(2)
    return v * {'s': 1/3600, 'm': 1/60, 'h': 1, 'd': 24}[u], cls

def hook_input(hook):
    """Hook JSON on stdin, read only with --hook (an interactive or scripted call
    must never block on an open stdin); {} otherwise."""
    if not hook: return {}
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}

def exited(run):
    try:
        with open(os.path.join(run, 'jg.log'), 'rb') as f:
            f.seek(0, 2); n = f.tell(); f.seek(max(0, n - 65536))
            return b'IC3_JOB jasper exited' in f.read()
    except Exception:
        return False

def find_runs(workspace):
    runs = {}
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if 'job.id' in files:
            try: runs[root] = open(os.path.join(root, 'job.id')).read().strip()
            except Exception: pass
    return runs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--workspace', default=None)
    ap.add_argument('--max-unlabeled-hours', type=float, default=1.0)
    ap.add_argument('--margin-hours', type=float, default=1.0)
    ap.add_argument('--strict', action='store_true')
    ap.add_argument('--hook', action='store_true', help='read the Claude Code hook JSON from stdin')
    a = ap.parse_args()
    hk = hook_input(a.hook)
    workspace = a.workspace or hk.get('cwd') or os.environ.get('CLAUDE_PROJECT_DIR') or os.getcwd()
    user = os.environ.get('USER') or subprocess.run(['id', '-un'], capture_output=True, text=True).stdout.strip()
    here = os.path.dirname(os.path.abspath(__file__))
    runs = find_runs(workspace)
    jobs, err = squeue(user)
    violations = []; seen = 0
    if jobs is None:
        unknown = [r for r in runs if not exited(r)]
        print(f'AUDIT: {err}; runs with unverified liveness: {len(unknown)}')
        if unknown:
            violations.append('cannot verify liveness of ' + ', '.join(unknown[:5]) + (' ...' if len(unknown) > 5 else ''))
        jobs = {}
    for run, jid in sorted(runs.items()):
        if jid not in jobs: continue
        seen += 1
        elapsed, name = jobs[jid]
        h = hours(elapsed)
        gr = os.path.join(run, 'GRAPH-READY.json'); bt = os.path.join(run, 'BUDGET.txt')
        label = 'none'; bad = False
        if os.path.isfile(bt):
            b, cls = budget(open(bt).read())
            if b is None:
                label = 'budget UNPARSEABLE'; bad = True
            else:
                label = f'budget {b:.2f}h class={cls}'
                if cls == 'experiment' and b > EXPERIMENT_CAP_H:
                    label += f' (above {EXPERIMENT_CAP_H:g}h experiment cap)'; bad = True
                if h > b + a.margin_hours:
                    label += f' (elapsed {h:.2f}h exceeds budget+margin)'; bad = True
                if cls == 'replay':
                    if not os.path.isfile(gr):
                        label += ' (replay without GRAPH-READY.json)'; bad = True
                    else:
                        rc = subprocess.run([sys.executable, os.path.join(here, 'graph_ready.py'), 'validate', gr, '--no-freshness'],
                                            capture_output=True, text=True).returncode
                        if rc != 0: label += ' (receipt INVALID)'; bad = True
        else:
            bad = h > a.max_unlabeled_hours
        if bad: violations.append(f'job {jid} ({name}, {elapsed}) in {run}: {label}')
        print(f"AUDIT job={jid} name={name} elapsed={elapsed} run={run} label={label} {'VIOLATION' if bad else 'ok'}")
    print(f'AUDIT summary: workspace={workspace} jobs_in_workspace={seen} violations={len(violations)}')
    if violations:
        reason = ('AUDIT: ' + '; '.join(violations) +
                  '. Time makes nothing inductive: cancel an unlabelled or over-budget run as an interrupted experiment '
                  '(record the receipt), write its missing BUDGET.txt / GRAPH-READY.json, or restore liveness checks.')
        print(reason, file=sys.stderr)
        if a.strict and not hk.get('stop_hook_active'):
            return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
