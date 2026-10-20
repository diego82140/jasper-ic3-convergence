"""Sparse engine cubes must never invent concrete RTL vector values."""
import importlib.util,json,tempfile,unittest,sqlite3,struct,io,contextlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
 s=importlib.util.spec_from_file_location(name,ROOT/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
db=load('telemetry','tools/telemetry_db.py');basis=load('basis','tools/basis.py')
class Semantics(unittest.TestCase):
 def test_polarity_selects_observed_outputs_not_small_inputs(self):
  run={'model':{'formula_index_shift':3,'formula_sign_mask':4,'formula_composite_mask':2},'signal_names':{'1':'flag'},'cube_definitions':{'1':{'domain':'jip_formula','count':1,'complete':True,'values':[8]},'2':{'domain':'jip_formula','count':1,'complete':True,'values':[12]}},'generalization_relations':[{'before_cube_id':'1','after_cube_id':'2'}]}
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.json';p.write_text(json.dumps({'runs':{'x':run}}))
   count,vectors=basis.generalized_polarity(p,0,200)
   self.assertEqual(count,1);self.assertEqual(vectors['flag'],[1,0])
   run['generalization_relations']=[];p.write_text(json.dumps({'runs':{'x':run}}))
   self.assertEqual(basis.generalized_polarity(p,0,200)[0],0)
 def test_batch_matches_single_decode_with_unknowns_and_inversion(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'model.log';line=b'IC3_STATS formula_index_shift=3 formula_sign_mask=4 formula_composite_mask=2\n';p.write_bytes(line)
   con=sqlite3.connect(':memory:');con.executescript(db.SCHEMA)
   con.execute('INSERT INTO files VALUES(1,?,NULL,NULL)',(str(p),))
   con.execute("INSERT INTO runs(run,event,tip) VALUES('r',1,'')")
   con.execute("INSERT INTO events(run,event,phase,source,offset,length) VALUES(1,1,'model',1,0,?)",(len(line),))
   con.execute("INSERT INTO payloads(run,kind,id,expected,complete) VALUES('r','name',1,4,1)")
   con.execute("INSERT INTO chunks VALUES('r','name',1,0,?)",(b'~bit',))
   for ident,raw in [(1,12),(2,10),(3,16)]:
    con.execute("INSERT INTO payloads(run,kind,id,expected,domain,complete) VALUES('r','cube',?,1,'jip_formula',1)",(ident,))
    con.execute("INSERT INTO chunks VALUES('r','cube',?,0,?)",(ident,struct.pack('<I',raw)))
   single=io.StringIO();batch=io.StringIO()
   with contextlib.redirect_stdout(single):
    for ident in (1,2,3):db.decode_cube(con,'r',ident)
   with contextlib.redirect_stdout(batch):db.decode_cubes(con,'r',iter(['1\n','\n','2\n','3\n']))
   self.assertEqual(single.getvalue(),batch.getvalue())
   rows=[json.loads(line) for line in batch.getvalue().splitlines()]
   self.assertEqual(rows[1]['value'],1);self.assertEqual(rows[3]['status'],'unresolved_composite');self.assertEqual(rows[5]['status'],'unresolved_name')
   with self.assertRaisesRegex(ValueError,'one nonnegative decimal'):
    db.decode_cubes(con,'r',['1,2'])
   con.close()
 def test_empty_terminal_name_chunk_preserves_complete_name(self):
  con=sqlite3.connect(':memory:');con.executescript(db.SCHEMA)
  head={'phase':'signal_name_chunk','variable':'7','offset':'0','bytes':'64','utf8_hex':(b'a'*64).hex()}
  db.payload(con,'r',head)
  row=db.fields(b'phase=signal_name_chunk variable=7 offset=64 bytes=0 utf8_hex= chain=abc')
  self.assertEqual(row['utf8_hex'],'');db.payload(con,'r',row)
  db.payload(con,'r',{'phase':'signal_name_end','variable':'7','bytes':'64','complete':'1'})
  self.assertEqual(con.execute("SELECT complete,seen FROM payloads").fetchone(),(1,64));con.close()
 def test_unresolved_and_inverted_literals(self):
  model={'formula_index_shift':3,'formula_sign_mask':4,'formula_composite_mask':2}
  self.assertEqual(db.decode_literal(12,model,'~v[7]')['value'],1)
  self.assertTrue(db.decode_literal(12,model,'~v[7]')['retained_name_inverted'])
  self.assertFalse(db.decode_literal(8,model,'v[7]')['retained_name_inverted'])
  self.assertEqual(db.decode_literal(8,model,None)['status'],'unresolved_name')
  self.assertEqual(db.decode_literal(10,model,'v')['status'],'unresolved_composite')
 def test_sat_domain_cannot_be_decoded_as_jip_atoms(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'model.log';line=b'IC3_STATS formula_index_shift=3 formula_sign_mask=4 formula_composite_mask=2\n';p.write_bytes(line)
   con=sqlite3.connect(':memory:');con.executescript(db.SCHEMA)
   con.execute("INSERT INTO files VALUES(1,?,NULL,NULL)",(str(p),))
   con.execute("INSERT INTO runs(run,event,tip) VALUES('r',1,'')")
   con.execute("INSERT INTO events(run,event,phase,source,offset,length) VALUES(1,1,'model',1,0,?)",(len(line),))
   con.execute("INSERT INTO payloads(run,kind,id,expected,domain,complete) VALUES('r','cube',1,1,'sat_literal_raw',1)")
   with self.assertRaisesRegex(ValueError,'not reviewed jip_formula'):db.decode_cube(con,'r',1)
   con.close()
 def test_unknown_comparison_cannot_label_a_sample(self):
  self.assertEqual(basis.evaluate("v.get('phase') == 0",{'phase':None}),'unconstrained')
  self.assertEqual(basis.evaluate("v.get('missing',0) != 1",{}),'unconstrained')
  self.assertTrue(basis.evaluate("v['flag'] == 1 or v['phase'] == 0",{'flag':1,'phase':None}))
 def test_sparse_vector_is_unknown_even_with_width(self):
  run={'model':{'formula_index_shift':3,'formula_sign_mask':4,'formula_composite_mask':2},'signal_names':{'1':'v[0]','2':'v[1]','3':'flag'},'cube_definitions':{'1':{'domain':'jip_formula','count':2,'complete':True,'values':[8,24]}}}
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.json';p.write_text(json.dumps({'runs':{'x':run}}))
   self.assertEqual(next(basis.basis_states(p,0,0,{'v':2})),{'v':None,'flag':1})
   run['cube_definitions']['1'].update(count=3,values=[8,20,24]);p.write_text(json.dumps({'runs':{'x':run}}))
   self.assertIsNone(next(basis.basis_states(p,0,0))['v'])
   self.assertEqual(next(basis.basis_states(p,0,0,{'v':2}))['v'],1)
if __name__=='__main__':unittest.main()
