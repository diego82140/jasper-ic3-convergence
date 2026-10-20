#!/usr/bin/env python3
"""Release-gate tests: graph_ready.py receipt validation (basis-run contract), prove_gate.py,
audit.py labelling/elapsed/fail-closed behaviour, and the send.sh / submit.sh budget gates
(offline: no Slurm, no Jasper; a fake squeue script stands in for the scheduler)."""
import json, os, subprocess, sys, tempfile, unittest, datetime, hashlib, shutil
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
GR = ROOT / 'tools' / 'graph_ready.py'
PG = ROOT / 'tools' / 'prove_gate.py'
AUDIT = ROOT / 'tools' / 'audit.py'
SEND = ROOT / 'session' / 'send.sh'
SUBMIT = ROOT / 'slurm' / 'submit.sh'
T = '<embedded>::top.t'; H = '<embedded>::top.u_chk.H1'; C = '<embedded>::top.u_chk.H1_cov'

def run(cmd, env=None, cwd=None, stdin=None):
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd, input=stdin)

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def basis_log(gsha, csha, nodes, covers, results, proofmaster='on'):
    lines = [f'GRAPH_INPUTS graph_sha256={gsha} checker_sha256={csha}', 'GRAPH_NODES ' + ' '.join(nodes),
             'GRAPH_COVERS ' + ' '.join(covers), f'PROOFMASTER {proofmaster}']
    lines += [f'RESULT {n} {s} {v} {e} {t}' for n, s, v, e, t in results]
    return '\n'.join(lines) + '\nIC3_JOB jasper exited rc=0\n'

def good_receipt(d, helpers=True):
    ledger = d / 'LEDGER.md'; ledger.write_text('# ledger\n')
    graph = d / 'proof_graph.tcl'; graph.write_text(f'set target {T}\nset helper {H}\nset cov {C}\nprove -property [list $helper $cov]\nprove -property $target -with_proven\n')
    checker = d / 'checker.tcl'; checker.write_text('assert -name H1 {1}\n')
    rd = d / 'basis'; rd.mkdir(exist_ok=True)
    (rd / 'BUDGET.txt').write_text('90m class=experiment slurm_time_min=150 warm graph\n')
    nodes = [T, H] if helpers else [T]; covers = [C] if helpers else []
    res = [(T, 'proven', 'proven', 'Hp', 300.0)] + ([(H, 'proven', 'proven', 'Hp', 60.0), (C, 'covered', 'covered', 'Hp', 5.0)] if helpers else [])
    (rd / 'jg.log').write_text(basis_log(sha(graph), sha(checker) if helpers else 'none', nodes, covers, res))
    return {'target': T, 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'graph_tcl': str(graph), 'graph_tcl_sha256': sha(graph),
            'checker': str(checker) if helpers else None, 'checker_sha256': sha(checker) if helpers else None,
            'basis_run': {'run_dir': str(rd), 'log': str(rd / 'jg.log')}, 'replay_factor': 4,
            'helpers': [{'name': H, 'consumer': T, 'witness': 'sufficiency', 'covers': [{'name': C}]}] if helpers else [],
            'open_base_cases': [], 'ledger': str(ledger), 'ledger_sha256': sha(ledger)}

def rewrite_log(r, **kw):
    d = Path(r['basis_run']['run_dir'])
    text = (d / 'jg.log').read_text()
    for a, b in kw.items(): text = text.replace(a, b)
    (d / 'jg.log').write_text(text)

class GraphReady(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp())
    def tearDown(self): shutil.rmtree(self.d)
    def check(self, r, *flags):
        p = self.d / 'r.json'; p.write_text(json.dumps(r))
        return run([sys.executable, str(GR), 'validate', str(p), *flags])
    def test_good_reports_budget(self):
        out = self.check(good_receipt(self.d)); self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn('max_budget_s=1460', out.stdout); self.assertIn('basis_total_s=365', out.stdout)
    def test_helper_free_graph(self):
        self.assertEqual(self.check(good_receipt(self.d, helpers=False)).returncode, 0)
    def test_open_base_case(self):
        r = good_receipt(self.d); r['open_base_cases'] = ['stage-1 entry'] ; self.assertEqual(self.check(r).returncode, 1)
    def test_target_not_in_graph_nodes(self):
        r = good_receipt(self.d); r['target'] = '<embedded>::top.other'; out = self.check(r)
        self.assertEqual(out.returncode, 1); self.assertIn('not in GRAPH_NODES', out.stdout)
    def test_basis_node_undetermined(self):
        r = good_receipt(self.d); rewrite_log(r, **{f'RESULT {T} proven proven': f'RESULT {T} undetermined undetermined'})
        self.assertEqual(self.check(r).returncode, 1)
    def test_basis_cache_engine_rejected(self):
        r = good_receipt(self.d); rewrite_log(r, **{f'RESULT {T} proven proven Hp': f'RESULT {T} proven proven Cache'})
        out = self.check(r); self.assertEqual(out.returncode, 1); self.assertIn('Cache', out.stdout)
    def test_basis_cover_missing(self):
        r = good_receipt(self.d); rewrite_log(r, **{f'RESULT {C} covered covered Hp 5.0\n': ''})
        self.assertEqual(self.check(r).returncode, 1)
    def test_basis_graph_hash_mismatch(self):
        r = good_receipt(self.d); rewrite_log(r, **{'graph_sha256=' + r['graph_tcl_sha256']: 'graph_sha256=' + '0' * 64})
        out = self.check(r); self.assertEqual(out.returncode, 1); self.assertIn('not the same graph', out.stdout)
    def test_basis_not_budgeted(self):
        r = good_receipt(self.d); os.remove(Path(r['basis_run']['run_dir']) / 'BUDGET.txt')
        self.assertEqual(self.check(r).returncode, 1)
    def test_basis_empty_budget_file(self):
        r = good_receipt(self.d); (Path(r['basis_run']['run_dir']) / 'BUDGET.txt').write_text('')
        self.assertEqual(self.check(r).returncode, 1)
    def test_token_exact_names(self):
        r = good_receipt(self.d); rewrite_log(r, **{f'RESULT {T} ': f'RESULT {T}x '})
        self.assertEqual(self.check(r).returncode, 1)
    def test_graph_edited_after_basis(self):
        r = good_receipt(self.d); Path(r['graph_tcl']).write_text(Path(r['graph_tcl']).read_text() + '# edited\n'); r['graph_tcl_sha256'] = sha(r['graph_tcl'])
        self.assertEqual(self.check(r).returncode, 1)
    def test_helper_witness_kinds(self):
        r = good_receipt(self.d); r['helpers'][0]['witness'] = 'regression'; self.assertEqual(self.check(r).returncode, 1)
        r['helpers'][0]['witness'] = 'cti-exclusion-hand'; self.assertEqual(self.check(r).returncode, 0)
    def test_consumer_chain_must_end_at_target(self):
        r = good_receipt(self.d); r['helpers'][0]['consumer'] = '<embedded>::top.unrelated'; self.assertEqual(self.check(r).returncode, 1)
        r['helpers'][0]['consumer'] = H; out = self.check(r); self.assertEqual(out.returncode, 1); self.assertIn('cyclic', out.stdout)
    def test_no_cover_needs_note(self):
        r = good_receipt(self.d); r['helpers'][0]['covers'] = []
        self.assertEqual(self.check(r).returncode, 1)
        r['helpers'][0]['covers_note'] = 'not an implication'; self.assertEqual(self.check(r).returncode, 0)
    def test_replay_factor_bounds(self):
        r = good_receipt(self.d); r['replay_factor'] = 20; self.assertEqual(self.check(r).returncode, 1)
    def test_stale_ledger_and_no_freshness(self):
        r = good_receipt(self.d); (self.d / 'LEDGER.md').write_text('changed\n')
        self.assertEqual(self.check(r).returncode, 1); self.assertEqual(self.check(r, '--no-freshness').returncode, 0)
    def test_relative_paths_resolve_against_receipt(self):
        r = good_receipt(self.d)
        for k in ('graph_tcl', 'checker', 'ledger'): r[k] = os.path.basename(r[k])
        r['basis_run'] = {'run_dir': 'basis', 'log': 'basis/jg.log'}
        self.assertEqual(self.check(r).returncode, 0)

class ProveGate(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp())
    def tearDown(self): shutil.rmtree(self.d)
    def gate(self, text, mx='60m'):
        f = self.d / 't.tcl'; f.write_text(text); return run([sys.executable, str(PG), str(f), '--max', mx]).returncode
    def test_unbounded_refused(self): self.assertEqual(self.gate('prove -property {x}\n'), 3)
    def test_bounded_ok(self): self.assertEqual(self.gate('prove -property {x} -time_limit 10m\n'), 0)
    def test_bare_seconds_ok(self): self.assertEqual(self.gate('prove -property {x} -time_limit 3600\n'), 0)
    def test_over_cap(self): self.assertEqual(self.gate('prove -property {x} -time_limit 61m\n'), 3)
    def test_zero_is_unbounded(self): self.assertEqual(self.gate('prove -property {x} -time_limit 0\n'), 3)
    def test_variable_limit_refused(self): self.assertEqual(self.gate('set l 10m\nprove -property {x} -time_limit $l\n'), 3)
    def test_status_exempt(self): self.assertEqual(self.gate('prove -status -silent\nprove -stop -tag T\nprove -wait\n'), 0)
    def test_list_substring_does_not_bypass(self):
        self.assertEqual(self.gate('prove -property {x} ;# -list\n'), 3)
        self.assertEqual(self.gate('set l [prove -list]\nprove -property $l\n'), 3)
    def test_second_prove_on_line_checked(self): self.assertEqual(self.gate('prove -property a -time_limit 10m; prove -property b\n'), 3)
    def test_namespaced_prove_checked(self): self.assertEqual(self.gate('::prove -property $x\n'), 3)
    def test_continuation_joined(self): self.assertEqual(self.gate('prove -property $x \\\n  -time_limit 10m\n'), 0)
    def test_global_limit_covers_bare_prove(self):
        self.assertEqual(self.gate('set_prove_time_limit 30m\nproc go {} { prove -property $::x }\ngo\n'), 0)
        self.assertEqual(self.gate('set_prove_time_limit 3h\nprove -property $x\n'), 3)
        self.assertEqual(self.gate('set_prove_time_limit 10m\nprove -property $a\nset_prove_time_limit 0\nprove -property $b\n'), 3)
    def test_comment_lines_ignored(self): self.assertEqual(self.gate('# prove -property x\nputs ok\n'), 0)
    def test_cap_argument(self):
        self.assertEqual(self.gate('set_prove_time_limit 10m\nprove -all\n', '10m'), 0)
        self.assertEqual(self.gate('set_prove_time_limit 11m\nprove -all\n', '10m'), 3)

class SendGate(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp()); (self.d / 'io').mkdir()
    def tearDown(self): shutil.rmtree(self.d)
    def send(self, text, env=None):
        f = self.d / 'req.tcl'; f.write_text(text)
        r = run(['timeout', '8', str(SEND), str(self.d / 'io'), str(f), '1'], env=env); return r.returncode, r.stderr
    def test_unbounded_prove_refused(self):
        rc, err = self.send('prove -property {<embedded>::x}\n')
        self.assertEqual(rc, 3); self.assertIn('refused', err); self.assertEqual(list((self.d / 'io').glob('*.req')), [])
    def test_over_budget_refused(self):
        rc, _ = self.send('prove -property {<embedded>::x} -time_limit 3h\n'); self.assertEqual(rc, 3)
    def test_send_max_env_does_not_lift(self):
        rc, _ = self.send('prove -property {<embedded>::x} -time_limit 3h\n', env=dict(os.environ, SEND_MAX='10h')); self.assertEqual(rc, 3)
    def test_bounded_accepted(self):
        rc, _ = self.send('prove -property {<embedded>::x} -time_limit 10m\nprove -status -tag T -silent\n')
        self.assertEqual(rc, 124); self.assertEqual(len(list((self.d / 'io').glob('*.req'))), 1)
    def test_status_only_accepted(self):
        rc, _ = self.send('prove -status -silent\nprove -stop -tag T\n'); self.assertEqual(rc, 124)
    def test_receipt_line_does_not_lift(self):
        r = good_receipt(self.d); p = self.d / 'r.json'; p.write_text(json.dumps(r))
        rc, _ = self.send(f'# GRAPH-READY: {p}\nprove -property {{<embedded>::x}}\n'); self.assertEqual(rc, 3)

class SubmitGate(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()); (self.d / 'launch').mkdir()
        (self.d / 'launch' / 'limited.tcl').write_text('set_prove_time_limit 10m\nprove -all\n')
        (self.d / 'launch' / 'unlimited.tcl').write_text('prove -all\n')
        (self.d / 'launch' / 'project48.tcl').write_text('set_prove_time_limit 48h\nprove -all\n')
        self.env = dict(os.environ, LM_LICENSE_FILE='1@x', JASPER='/nonexistent-jasper')
        for k in ('BUDGET', 'BUDGET_CLASS', 'BUDGET_NOTE', 'BUDGET_MARGIN', 'GRAPH_READY'): self.env.pop(k, None)
    def tearDown(self): shutil.rmtree(self.d)
    def submit(self, tcl, mode='batch', **extra):
        return run([str(SUBMIT), mode, str(self.d / 'run'), str(self.d / 'launch'), tcl], env=dict(self.env, **extra))
    def passed_gate(self, r): return 'no Jasper launcher' in r.stderr
    def test_batch_without_budget_refused(self):
        r = self.submit('limited.tcl'); self.assertEqual(r.returncode, 2); self.assertIn('BUDGET', r.stderr)
    def test_experiment_unbounded_tcl_refused(self):
        r = self.submit('unlimited.tcl', BUDGET='30m'); self.assertEqual(r.returncode, 2); self.assertIn('not bounded', r.stderr)
    def test_experiment_budget_smaller_than_tcl_limit_refused(self):
        self.assertEqual(self.submit('limited.tcl', BUDGET='5m').returncode, 2)
    def test_bad_budget_format_refused(self):
        self.assertEqual(self.submit('limited.tcl', BUDGET='soon').returncode, 2)
        self.assertEqual(self.submit('limited.tcl', BUDGET='1.5h').returncode, 2)
    def test_experiment_over_4h_refused(self):
        r = self.submit('project48.tcl', BUDGET='48h'); self.assertEqual(r.returncode, 2); self.assertIn('4h experiment cap', r.stderr)
    def test_margin_capped(self):
        self.assertEqual(self.submit('limited.tcl', BUDGET='30m', BUDGET_MARGIN='9999h').returncode, 2)
        self.assertEqual(self.submit('limited.tcl', BUDGET='30m', BUDGET_MARGIN='1d').returncode, 2)
        self.assertTrue(self.passed_gate(self.submit('limited.tcl', BUDGET='30m', BUDGET_MARGIN='2h')))
    def test_baseline_needs_note_then_passes(self):
        r = self.submit('project48.tcl', BUDGET='48h', BUDGET_CLASS='baseline'); self.assertEqual(r.returncode, 2); self.assertIn('BUDGET_NOTE', r.stderr)
        self.assertTrue(self.passed_gate(self.submit('project48.tcl', BUDGET='48h', BUDGET_CLASS='baseline', BUDGET_NOTE='project limit 48h')))
    def test_baseline_not_for_diagnostic(self):
        self.assertEqual(self.submit('project48.tcl', 'diagnostic', BUDGET='48h', BUDGET_CLASS='baseline', BUDGET_NOTE='x').returncode, 2)
    def test_replay_needs_receipt_and_matching_tcl(self):
        r = self.submit('unlimited.tcl', BUDGET='20m', BUDGET_CLASS='replay'); self.assertEqual(r.returncode, 2); self.assertIn('GRAPH_READY', r.stderr)
        rec = good_receipt(self.d); p = self.d / 'r.json'; p.write_text(json.dumps(rec))
        r = self.submit('unlimited.tcl', BUDGET='20m', BUDGET_CLASS='replay', GRAPH_READY=str(p))
        self.assertEqual(r.returncode, 2); self.assertIn('not the graph Tcl the receipt hashes', r.stderr)
    def test_replay_budget_bounded_by_basis(self):
        rec = good_receipt(self.d); p = self.d / 'r.json'; p.write_text(json.dumps(rec))
        shutil.copy(rec['graph_tcl'], self.d / 'launch' / 'graph.tcl')
        r = self.submit('graph.tcl', BUDGET='30m', BUDGET_CLASS='replay', GRAPH_READY=str(p))   # 1800 s > 4 x 365 s
        self.assertEqual(r.returncode, 2); self.assertIn("exceeds the receipt's replay budget", r.stderr)
        self.assertTrue(self.passed_gate(self.submit('graph.tcl', BUDGET='24m', BUDGET_CLASS='replay', GRAPH_READY=str(p))))
    def test_replay_bad_receipt_refused(self):
        r = self.submit('unlimited.tcl', BUDGET='20m', BUDGET_CLASS='replay', GRAPH_READY='/nonexistent.json'); self.assertEqual(r.returncode, 2); self.assertIn('not admissible', r.stderr)
    def test_console_sink_refused(self):
        r = self.submit('limited.tcl', BUDGET='30m', TELEMETRY_SINK='console'); self.assertEqual(r.returncode, 2); self.assertIn('console', r.stderr)
    def test_experiment_passes_gate(self):
        r = self.submit('limited.tcl', BUDGET='30m'); self.assertTrue(self.passed_gate(r))
    def test_diagnostic_unbounded_tcl_refused(self):
        r = self.submit('unlimited.tcl', mode='diagnostic'); self.assertEqual(r.returncode, 2); self.assertIn('not bounded', r.stderr)
    def test_diagnostic_bounded_passes_gate(self):
        self.assertTrue(self.passed_gate(self.submit('limited.tcl', mode='diagnostic')))
    def test_session_lifetime_capped(self):
        r = run([str(SUBMIT), 'session', str(self.d / 'run'), str(self.d / 'launch')], env=dict(self.env, BUDGET='48h'))
        self.assertEqual(r.returncode, 2); self.assertIn('at most 4h', r.stderr)
        r = run([str(SUBMIT), 'session', str(self.d / 'run'), str(self.d / 'launch')], env=dict(self.env, BUDGET='2h'))
        self.assertTrue(self.passed_gate(r))

class FakeSbatchSubmit(unittest.TestCase):
    """Drive submit.sh through its post-gate path with a fake sbatch that records its arguments."""
    def setUp(self):
        # submit.sh rejects run directories under /tmp (not visible from the nodes): use a scratch dir inside tests/,
        # and skip when the kit itself lives under /tmp (an installed copy in a scratch config dir)
        if str(ROOT).startswith(('/tmp/', '/var/tmp/')):
            self.skipTest('kit is under /tmp; submit.sh refuses run directories there by design')
        (ROOT / 'tests' / '.tmp').mkdir(exist_ok=True)
        self.d = Path(tempfile.mkdtemp(dir=ROOT / 'tests' / '.tmp')); (self.d / 'bin').mkdir(); (self.d / 'launch').mkdir(); (self.d / 'jasper' / 'bin').mkdir(parents=True)
        (self.d / 'jasper' / 'bin' / 'jaspergold').write_text('#!/bin/sh\n'); (self.d / 'jasper' / 'bin' / 'jaspergold').chmod(0o755)
        (self.d / 'bin' / 'sbatch').write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/sbatch.args"\necho 4242\n'); (self.d / 'bin' / 'sbatch').chmod(0o755)
        (self.d / 'bin' / 'squeue').write_text('#!/bin/sh\nexit 0\n'); (self.d / 'bin' / 'squeue').chmod(0o755)
        (self.d / 'launch' / 'limited.tcl').write_text('set_prove_time_limit 10m\nprove -all\n')
        self.env = dict(os.environ, LM_LICENSE_FILE='1@x', JASPER=str(self.d / 'jasper'), SLURM_BIN=str(self.d / 'bin'))
        for k in ('BUDGET', 'BUDGET_CLASS', 'BUDGET_NOTE', 'BUDGET_MARGIN', 'GRAPH_READY'): self.env.pop(k, None)
    def tearDown(self): shutil.rmtree(self.d)
    def args(self): return (self.d / 'bin' / 'sbatch.args').read_text().splitlines()
    def test_check_mode_is_labelled_and_timed(self):
        run_dir = self.d / 'run'
        r = run([str(SUBMIT), 'check', str(run_dir)], env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn('--time=180', self.args())
        self.assertIn('class=experiment', (run_dir / 'BUDGET.txt').read_text()); self.assertEqual((run_dir / 'job.id').read_text().strip(), '4242')
    def test_experiment_time_and_label(self):
        r = run([str(SUBMIT), 'batch', str(self.d / 'run'), str(self.d / 'launch'), 'limited.tcl'], env=dict(self.env, BUDGET='30m', BUDGET_MARGIN='30m'))
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn('--time=60', self.args())
        self.assertTrue((self.d / 'run' / 'BUDGET.txt').read_text().startswith('30m class=experiment slurm_time_min=60'))
    def test_replay_copies_receipt_with_absolute_paths(self):
        rec = good_receipt(self.d)
        for k in ('graph_tcl', 'checker', 'ledger'): rec[k] = os.path.basename(rec[k])
        rec['basis_run'] = {'run_dir': 'basis', 'log': 'basis/jg.log'}
        p = self.d / 'r.json'; p.write_text(json.dumps(rec)); shutil.copy(self.d / 'proof_graph.tcl', self.d / 'launch' / 'graph.tcl')
        r = run([str(SUBMIT), 'batch', str(self.d / 'run'), str(self.d / 'launch'), 'graph.tcl'], env=dict(self.env, BUDGET='24m', BUDGET_CLASS='replay', GRAPH_READY=str(p)))
        self.assertEqual(r.returncode, 0, r.stderr)
        copied = json.load(open(self.d / 'run' / 'GRAPH-READY.json'))
        self.assertTrue(os.path.isabs(copied['graph_tcl'])); self.assertTrue(os.path.isabs(copied['basis_run']['log']))
        self.assertIn('class=replay', (self.d / 'run' / 'BUDGET.txt').read_text())

class Audit(unittest.TestCase):
    def setUp(self): self.d = Path(tempfile.mkdtemp()); self.fake = self.d / 'squeue'
    def tearDown(self): shutil.rmtree(self.d)
    def squeue(self, rows):
        self.fake.write_text('#!/bin/sh\n' + ''.join(f"echo '{r}'\n" for r in rows)); self.fake.chmod(0o755)
    def runs(self, name, jid, label=None, exited=False):
        r = self.d / name; r.mkdir(); (r / 'job.id').write_text(f'{jid}\n')
        if label: (r / 'BUDGET.txt').write_text(label + '\n')
        if exited: (r / 'jg.log').write_text('IC3_JOB jasper exited rc=0\n')
        return r
    def audit(self, *args, squeue=None):
        env = dict(os.environ, IC3_SQUEUE=squeue or str(self.fake))
        return run([sys.executable, str(AUDIT), '--workspace', str(self.d), '--strict', '--hook', *args], env=env, stdin='{}')
    def test_within_budget_ok(self):
        self.squeue(['11 0:20:00 a']); self.runs('r1', 11, '30m class=experiment x')
        r = self.audit(); self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertIn('ok', r.stdout)
    def test_elapsed_over_budget_violation(self):
        self.squeue(['11 2:05:00 a']); self.runs('r1', 11, '30m class=experiment x')
        r = self.audit(); self.assertEqual(r.returncode, 2); self.assertIn('exceeds budget', r.stdout)
    def test_baseline_long_budget_ok(self):
        self.squeue(['11 1-02:00:00 a']); self.runs('r1', 11, '48h class=baseline project limit')
        self.assertEqual(self.audit().returncode, 0)
    def test_experiment_over_cap_violation(self):
        self.squeue(['11 0:05:00 a']); self.runs('r1', 11, '8h class=experiment x')
        self.assertEqual(self.audit().returncode, 2)
    def test_unlabeled_old_violation(self):
        self.squeue(['11 1:30:00 a']); self.runs('r1', 11)
        self.assertEqual(self.audit().returncode, 2)
        self.squeue(['11 0:30:00 a']); self.assertEqual(self.audit().returncode, 0)
    def test_replay_needs_receipt_and_validates_without_freshness(self):
        self.squeue(['11 0:10:00 a']); r1 = self.runs('r1', 11, '24m class=replay graph')
        self.assertEqual(self.audit().returncode, 2)
        rec = good_receipt(self.d); rec['created_utc'] = '2020-01-01T00:00:00+00:00'
        (r1 / 'GRAPH-READY.json').write_text(json.dumps(rec))
        out = self.audit(); self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
    def test_fail_closed_when_squeue_unavailable(self):
        self.runs('r1', 11, '30m class=experiment x')
        r = self.audit(squeue='/nonexistent/squeue'); self.assertEqual(r.returncode, 2); self.assertIn('cannot verify', r.stderr)
        (self.d / 'r1' / 'jg.log').write_text('IC3_JOB jasper exited rc=0\n')
        self.assertEqual(self.audit(squeue='/nonexistent/squeue').returncode, 0)
    def test_stop_hook_active_does_not_block_twice(self):
        self.squeue(['11 2:05:00 a']); self.runs('r1', 11, '30m class=experiment x')
        env = dict(os.environ, IC3_SQUEUE=str(self.fake))
        r = run([sys.executable, str(AUDIT), '--workspace', str(self.d), '--strict', '--hook'], env=env, stdin='{"stop_hook_active": true}')
        self.assertEqual(r.returncode, 0); self.assertIn('AUDIT:', r.stderr)
    def test_no_hook_flag_does_not_read_stdin(self):
        self.squeue(['11 0:20:00 a']); self.runs('r1', 11, '30m class=experiment x')
        env = dict(os.environ, IC3_SQUEUE=str(self.fake))
        pr = subprocess.Popen([sys.executable, str(AUDIT), '--workspace', str(self.d), '--strict'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        try: out, _ = pr.communicate(timeout=10)   # stdin stays open and empty: must not block
        except subprocess.TimeoutExpired: pr.kill(); self.fail('audit.py blocked on an open stdin without --hook')
        self.assertEqual(pr.returncode, 0); self.assertIn('violations=0', out)
    def test_skips_telemetry_trees(self):
        self.squeue(['11 0:10:00 a']); (self.d / 'telemetry' / 'deep').mkdir(parents=True); (self.d / 'telemetry' / 'deep' / 'job.id').write_text('11\n')
        r = self.audit(); self.assertIn('jobs_in_workspace=0', r.stdout)

if __name__ == '__main__':
    unittest.main()
