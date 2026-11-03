"""Counterfeit CTI information must not pass the direct consumer comparison."""
import sqlite3
import gzip,hashlib,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'source/tests/parity'))
spec=importlib.util.spec_from_file_location('agent_cti_parity',ROOT/'source/tests/parity/agent_cti_parity.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
import raw_payload_parity as raw_words
class AgentCTIParity(unittest.TestCase):
 def stream(self,path,rows):
  with gzip.open(path,'wb') as f:
   for row in rows:f.write(m.canonical(row))
 def compare(self,reference,candidate,subsequence=False):
  with tempfile.TemporaryDirectory() as d:
   a=Path(d)/'a.gz';b=Path(d)/'b.gz';self.stream(a,reference);self.stream(b,candidate)
   return m.compare_streams(a,b,subsequence=subsequence)
 def test_named_cti_multiplicity_and_order_are_not_sets(self):
  a={'raw_hex':b'IC3_CTI state="y"'.hex()};b={'raw_hex':b'IC3_CTI state="!x"'.hex()}
  self.assertTrue(self.compare([a,a,b],[a,a,b])['pass_'])
  self.assertFalse(self.compare([a,a,b],[a,b])['pass_'])
  self.assertFalse(self.compare([a,a,b],[a,b,a])['pass_'])
 def test_changed_constrained_bit_or_unknown_label_is_rejected(self):
  base={'kind':'literal','status':'mapped_literal','name':'q[2]','value':1,'scope':'one_constrained_bit; absent_bits_unknown; not_a_concrete_RTL_witness'}
  for candidate in [dict(base,value=0),dict(base,name='q[3]'),dict(base,scope='all_absent_bits_zero'),dict(base,status='concrete_reachable_state')]:self.assertFalse(self.compare([base],[candidate])['pass_'])
 def test_only_declared_legacy_additions_are_subsequence(self):
  a={'phase':'cube','value':'not_unknown_zero'};extra={'phase':'new_capability'}
  self.assertTrue(self.compare([a],[extra,a],True)['pass_'])
  self.assertFalse(self.compare([a],[extra,a])['pass_'])
  self.assertFalse(self.compare([a],[extra],True)['pass_'])
 def test_empty_frames_are_part_of_agent_information(self):
  db=sqlite3.connect(':memory:');db.execute('CREATE TABLE frame_manifests(run,snapshot,frame,members,closed)')
  db.executemany('INSERT INTO frame_manifests VALUES(1,7,?,?,1)',[(0,0),(1,0),(-1,0)])
  baseline=m.frame_layout(db,1,7);self.assertEqual(baseline,[{'frame':0,'cubes':0},{'frame':1,'cubes':0},{'frame':-1,'cubes':0}])
  db.execute('DELETE FROM frame_manifests WHERE frame=1');changed=m.frame_layout(db,1,7)
  # Both snapshots have the same empty member hash; omitting the frame would
  # otherwise make a changed depth ladder appear equal.
  self.assertFalse(self.compare([{'layout':baseline}],[{'layout':changed}])['pass_']);db.close()
 def test_unreferenced_cube_and_decoded_bit_cannot_escape_the_gate(self):
  with tempfile.TemporaryDirectory() as tmp:
   a=Path(tmp)/'a';b=Path(tmp)/'b';a.mkdir();b.mkdir()
   for name in m.VIEW_STREAMS:self.stream(a/name,[{'native':'same'}]);self.stream(b/name,[{'native':'same'}])
   self.assertTrue(all(x['pass_'] for x in m.compare_views(a,b).values()))
   for name in ['cube-definitions.jsonl.gz','decoded-cubes.jsonl.gz']:
    self.stream(b/name,[{'native':'lost_or_wrong_unused_cube'}])
    self.assertFalse(m.compare_views(a,b)[name]['pass_'])
    self.stream(b/name,[{'native':'same'}])
 def test_missing_field_is_not_hidden_by_field_intersection(self):
  self.assertFalse(self.compare([{'query_class':'relative_induction','context_complete':'0'}],[{'query_class':'relative_induction'}])['pass_'])
 def test_legacy_view_uses_verified_captured_payload_not_guessed_text(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);old=root/'old';old.mkdir();payload=b'IC3_CTI state="~long_name[65]"';header=dict(phase='parity_record',capture='c',pid='7',tid='7',run='1',parity_sequence='1',bytes=str(len(payload)),family='IC3_CTI',sha256=hashlib.sha256(payload).hexdigest())
   chunk=dict(header,phase='parity_record_chunk',offset='0',utf8_hex=payload.hex());end=dict(header,phase='parity_record_end',complete='1')
   def line(r):return b'IC3_STATS '+b' '.join((k+'='+v).encode() for k,v in r.items())+b'\n'
   source=b''.join(line(r) for r in [header,chunk,end]);(old/'IC3-STATS.log').write_bytes(source);(old/'worker-7.manifest.json').write_text(json.dumps({'pid':7}))
   result=m.legacy_view(old,root/'view');self.assertEqual((old/'IC3-STATS.log').read_bytes(),source);self.assertEqual((root/'view/events-7-7.log').read_bytes(),source+payload+b'\n');self.assertEqual(result['payloads_reinserted'],1)
   chunk['utf8_hex']=(payload[:-1]+b'X').hex();(old/'IC3-STATS.log').write_bytes(b''.join(line(r) for r in [header,chunk,end]))
   with self.assertRaisesRegex(ValueError,'payload hash/extent mismatch'):m.legacy_view(old,root/'corrupt-view')
 def test_decoder_output_keeps_inversion_and_unresolved_values(self):
  import io
  out=io.BytesIO();sink=m.DecodedWriter(out,1,4)
  rows=[{'run':'opaque','cube':4,'model_epoch':2,'literals':2,'proof_certificate':False,'absent_bits':'unknown','composite_formulas':'unresolved'}, {'raw':'00000004','variable':0,'status':'mapped_literal','name':'q[2]','value':1,'retained_name_inverted':True,'vector':'q','bit':2,'scope':'one_constrained_bit'}, {'raw':'00000002','variable':0,'status':'unresolved_composite','value':None}]
  for row in rows:sink.write(json.dumps(row)+'\n')
  exported=[json.loads(z) for z in out.getvalue().splitlines()];self.assertEqual(exported[1]['value'],1);self.assertTrue(exported[1]['retained_name_inverted']);self.assertIsNone(exported[2]['value']);self.assertEqual(sink.count,2);self.assertEqual(sink.statuses['unresolved_composite'],1)
 def raw_source(self,root,words='00000004,00000009',offset='0',complete='1'):
  records=[dict(phase='cube_definition',domain='sat_literal_raw',literals='2'),dict(phase='cube_chunk',offset=offset,count='2',values=words),dict(phase='cube_definition_end',literals='2',complete=complete)]
  data=b''
  for record in records:
   row=dict(capture='c',pid='1',tid='1',run='1',cube_id='1',**record)
   data+=b'IC3_STATS '+b' '.join((k+'='+v).encode() for k,v in row.items())+b'\n'
  (root/'IC3-STATS.log').write_bytes(data)
 def test_raw_sat_words_are_compared_in_full_and_in_order(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);self.raw_source(root);a=root/'a.gz';counts=raw_words.export_words(root,a,legacy=True)
   self.assertEqual(counts['sat_literal_raw_words'],2)
   for words in ['00000004,00000008','00000009,00000004','00000004,00000004']:
    self.raw_source(root,words=words);b=root/'b.gz';raw_words.export_words(root,b,legacy=True)
    self.assertFalse(m.compare_streams(a,b)['pass_'])
 def test_raw_payload_rejects_incomplete_extent(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   for options in [dict(offset='1'),dict(complete='0'),dict(words='00000004')]:
    self.raw_source(root,**options)
    with self.assertRaises(ValueError):raw_words.export_words(root,root/'out.gz',legacy=True)
if __name__=='__main__':unittest.main()
