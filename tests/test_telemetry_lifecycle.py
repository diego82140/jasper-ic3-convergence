"""Reader independently rejects false completion and cross-restart naming."""
import contextlib,hashlib,importlib.util,io,json,sqlite3,struct,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('telemetry',ROOT/'tools/telemetry_db.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)

class Lifecycle(unittest.TestCase):
 def setUp(self):
  self.db=sqlite3.connect(':memory:');self.db.executescript(t.SCHEMA);t.observer_tables(self.db)
  self.run='c:1:1:1'
  self.db.execute('INSERT INTO runs(run,event,tip) VALUES(?,0,?)',(self.run,''))
 def tearDown(self):self.db.close()
 def observe(self,phase,**kw):
  t.observer_record(self.db,self.run,dict(capture='c',pid='1',tid='1',run='1',phase=phase,**{k:str(v) for k,v in kw.items()}))
 def begin(self):
  self.observe('run_contract',activation_tracking=1)
  self.observe('invocation_begin',activation=1,hook='relative',operation=3,gum_depth=0,run_generation=1,parent_activation=0)
  self.observe('relative_begin',query=5)
 def seal(self,**kw):
  self.observe('run_seal',capture_status='complete',activation_begins=1,activation_returns=0,activation_aborts=1,activation_live=0,observer_errors=0,**kw)
 def test_abort_balances_without_inventing_result(self):
  self.begin();self.observe('query_abort',query=5,native_return_observed=0)
  self.observe('invocation_abort',activation=1,hook='relative',operation=3,gum_depth=0,native_return_observed=0)
  self.seal()
 def test_private_balance_alone_does_not_close_query(self):
  self.begin();self.observe('invocation_abort',activation=1,hook='relative',operation=3,gum_depth=0,native_return_observed=0)
  with self.assertRaisesRegex(ValueError,'unfinished'):self.seal()
 def test_foreign_generation_parent_and_close_are_rejected(self):
  self.observe('run_contract',activation_tracking=1)
  with self.assertRaisesRegex(ValueError,'parent mismatch'):
   self.observe('invocation_begin',activation=1,hook='relative',operation=3,gum_depth=0,run_generation=1,parent_activation=9)
  with self.assertRaisesRegex(ValueError,'generation mismatch'):
   self.observe('invocation_begin',activation=1,hook='relative',operation=3,gum_depth=0,run_generation=2,parent_activation=0)
  with self.assertRaisesRegex(ValueError,'close mismatch'):
   self.observe('invocation_return',activation=1,hook='relative',operation=3,gum_depth=0,native_return_observed=1)
 def test_result_on_abort_is_rejected(self):
  self.begin()
  with self.assertRaisesRegex(ValueError,'invents a result'):
   self.observe('query_abort',query=5,native_return_observed=0,result='unsat')
 def event(self,phase,**kw):
  self.next_event=getattr(self,'next_event',0)+1
  event=self.next_event
  self.observe(phase,event=event,**kw)
  self.db.execute('INSERT INTO events(run,event,phase) VALUES(1,?,?)',(event,phase))
  if phase=='final':self.db.execute('UPDATE runs SET final=? WHERE run=?',(event,self.run))
  return event
 def validation_abort(self,tracking=1,reason='native_handler_unwind',begin=True,final='valid'):
  self.event('run_contract',activation_tracking=1,completion_tail_tracking=1,validation_abort_tracking=tracking)
  self.final=self.event('final',result=final)
  self.event('invocation_begin',activation=1,hook='validation',operation=3,gum_depth=0,run_generation=1,parent_activation=0)
  if begin:self.event('native_validation_begin')
  self.event('native_validation_stage',stage='base',result='pass',checks=0)
  self.event('native_validation_solver',result_raw=5,result='limit_or_unknown')
  self.abort=self.event('invocation_abort',activation=1,hook='validation',operation=3,gum_depth=0,native_return_observed=0,reason=reason)
 def marker(self,**overrides):
  fields=dict(native_final_event=self.final,abort_event=self.abort,reason='native_handler_unwind',native_return_observed=0,native_validation_end_observed=0,validation_pass_observed=0,validation_outcome='aborted_inconclusive')
  fields.update(overrides);self.event('native_validation_abort',**fields)
 def tail(self,**overrides):
  fields=dict(native_final_event=self.final,native_verdict_already_observed=1,proof_frontier=0,native_validation_expected=1,native_validation_observed=0,native_validation_aborted=1,native_validation_abort_event=self.abort)
  fields.update(overrides);self.event('native_tail_begin',**fields)
 def test_observed_validation_abort_is_complete_telemetry(self):
  self.validation_abort();self.marker();self.tail();self.seal()
  self.assertEqual(t.frame_summary(self.db,1)['native_validation_disposition'],'aborted_inconclusive')
 def test_abort_marker_requires_actual_declared_causal_boundary(self):
  self.validation_abort()
  for changes in [dict(abort_event=self.abort+1),dict(native_final_event=self.final+1),dict(native_return_observed=1),dict(validation_pass_observed=1),dict(result='valid')]:
   with self.subTest(changes=changes),self.assertRaises(ValueError):self.marker(**changes)
  self.marker()
  with self.assertRaises(ValueError):self.marker()
 def test_abort_cannot_be_replaced_by_normal_validation_or_pass(self):
  self.validation_abort()
  for phase,kw in [('native_validation_begin',{}),('native_validation_missing',{}),('native_validation_end',{}),('native_validation_stage',dict(stage='property',result='pass')),('native_validation_stage',dict(stage='property',result='inconclusive'))]:
   with self.subTest(phase=phase),self.assertRaises(ValueError):self.event(phase,**kw)
  self.marker()
  with self.assertRaises(ValueError):self.tail(native_validation_observed=1)
  with self.assertRaisesRegex(ValueError,'reference mismatch'):self.tail(native_validation_abort_event=self.abort+1)
 def test_abort_without_validation_begin_rejected(self):
  self.validation_abort(begin=False)
  with self.assertRaisesRegex(ValueError,'without observed validation begin'):self.marker()
 def test_validation_begin_without_own_activation_rejected(self):
  self.event('run_contract',activation_tracking=1,validation_abort_tracking=1)
  with self.assertRaisesRegex(ValueError,'own live native activation'):self.event('native_validation_begin')
 def test_inner_validation_begin_does_not_qualify_outer_abort(self):
  self.event('run_contract',activation_tracking=1,completion_tail_tracking=1,validation_abort_tracking=1)
  self.final=self.event('final',result='valid')
  for token,depth,parent in [(1,0,0),(2,1,1)]:
   self.event('invocation_begin',activation=token,hook='validation',operation=token,gum_depth=depth,run_generation=1,parent_activation=parent)
  self.event('native_validation_begin')
  self.event('invocation_return',activation=2,hook='validation',operation=2,gum_depth=1,native_return_observed=1)
  self.abort=self.event('invocation_abort',activation=1,hook='validation',operation=1,gum_depth=0,native_return_observed=0,reason='native_handler_unwind')
  with self.assertRaisesRegex(ValueError,'aborted activation'):self.marker()
 def test_abort_without_contract_rejected(self):
  self.validation_abort(tracking=0)
  with self.assertRaisesRegex(ValueError,'declared tracking'):self.marker()
 def test_nonhandler_abort_stays_unqualified(self):
  self.validation_abort(reason='gum_unwind_observed')
  with self.assertRaisesRegex(ValueError,'actual native validation abort'):self.marker()
 def test_abort_requires_native_valid_final(self):
  self.validation_abort(final='cex')
  with self.assertRaisesRegex(ValueError,'valid final'):self.marker()
 def test_abort_marker_rejects_live_native_query(self):
  self.validation_abort();self.event('sat_begin',call=2)
  with self.assertRaisesRegex(ValueError,'unfinished scopes'):self.marker()
 def test_missing_validation_remains_incomplete(self):
  self.validation_abort(begin=False,reason='gum_unwind_observed')
  self.event('native_validation_missing')
  self.tail(native_validation_aborted=0,native_validation_abort_event=0)
  with self.assertRaisesRegex(ValueError,'missing native validation'):self.seal()
 def test_run_abort_precludes_validation_tail(self):
  self.validation_abort();self.marker()
  self.event('invocation_begin',activation=2,hook='run',operation=4,gum_depth=0,run_generation=1,parent_activation=0)
  self.event('invocation_abort',activation=2,hook='run',operation=4,gum_depth=0,native_return_observed=0,reason='native_handler_unwind')
  with self.assertRaisesRegex(ValueError,'one observed final'):self.tail()
 def cube(self,ident,epoch,qualified,name):
  model=f'phase=model formula_index_shift=3 formula_sign_mask=4 formula_composite_mask=2 model_epoch={epoch}'.encode()
  self.db.execute('INSERT INTO models VALUES(?,?,?)',(self.run,epoch,model))
  raw=struct.pack('<I',8);digest=hashlib.sha256(b'jip_formula\0'+struct.pack('<I',1)+raw).hexdigest()
  for r in [dict(phase='cube_definition',cube_id=str(ident),literals='1',sha256=digest,domain='jip_formula'),
            dict(phase='cube_chunk',cube_id=str(ident),offset='0',count='1',values='00000008'),
            dict(phase='cube_definition_end',cube_id=str(ident),literals='1',complete='1')]:t.payload(self.db,self.run,r)
  self.db.execute('INSERT INTO cube_epochs VALUES(?,?,?,?)',(self.run,ident,epoch,qualified))
  for r in [dict(phase='signal_name_chunk',variable='1',model_epoch=str(epoch),offset='0',bytes=str(len(name)),utf8_hex=name.encode().hex()),
            dict(phase='signal_name_end',variable='1',model_epoch=str(epoch),bytes=str(len(name)),complete='1')]:t.payload(self.db,self.run,r)
 def test_identical_raw_atom_decodes_against_its_own_epoch(self):
  self.cube(1,1,1,'before[0]');self.cube(2,2,1,'after[0]')
  output=io.StringIO()
  with contextlib.redirect_stdout(output):
   decode=t.cube_decoder(self.db,self.run);decode(1);decode(2);decode(1)
  rows=[json.loads(x) for x in output.getvalue().splitlines()]
  self.assertEqual([rows[x]['name'] for x in (1,3,5)],['before[0]','after[0]','before[0]'])
 def test_prequalification_cube_cannot_gain_later_names(self):
  self.cube(1,1,0,'later[0]');output=io.StringIO()
  with contextlib.redirect_stdout(output),self.assertRaisesRegex(ValueError,'before model qualification'):
   t.cube_decoder(self.db,self.run)(1)
  self.assertEqual(output.getvalue(),'')

if __name__=='__main__':unittest.main()
