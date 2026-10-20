"""A cached PASS must not survive changes to the client or its reader/job."""
import ast,hashlib,json,re,sys,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
# Load only the production qualification functions; the optional ELF package
# and embedded adapter blobs are unrelated to these cache regressions.
module=ast.parse((ROOT/'source/jipstats.py').read_text())
code=compile(ast.Module(body=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name in ('qualification_inputs','qualify')],type_ignores=[]),str(ROOT/'source/jipstats.py'),'exec')
class QualificationRequired(Exception):pass
class Identity(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  for name in ('slurm/jasper_job.sh','tools/telemetry_db.py','libjipstats.so','client','jasper','worker','profile','entry.py'):
   p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('details 1\n' if name=='profile' else name)
  self.ns=dict(Path=Path,sys=types.SimpleNamespace(frozen=True),__file__='/missing/pyinstaller/entry.py',hashlib=hashlib,json=json,re=re,tempfile=tempfile,HOME=self.root,LIB=self.root/'libjipstats.so',VERSION='same-version',RTL='rtl',TCL='tcl',Unsupported=RuntimeError)
  self.paths=[]
  def sha(p):
   self.paths.append(str(p));p=self.root/'client' if str(p)=='/proc/self/exe' else p
   return hashlib.sha256(Path(p).read_bytes()).hexdigest()
  self.ns['sha']=sha;exec(code,self.ns)
  self.args=(self.root/'jasper',self.root/'worker',self.root/'profile','worker-digest')
  self.policy={'JIPSTATS_CAPTURE_MODE':'full','JIPSTATS_SINK':'disk','JIPSTATS_COMPRESSION':'gzip','JIPSTATS_FRAME_ENCODING':'tuple_chunks_v2'}
  self.cache=self.root/'cache';self.cache.mkdir()
 def tearDown(self):self.tmp.cleanup()
 def inputs(self):return self.ns['qualification_inputs'](*self.args,self.policy,True)
 def cached(self):
  inputs=self.inputs();key=hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  (self.cache/('qualified-'+key+'.json')).write_text(json.dumps({'status':'PASS','qualifier_inputs':inputs,'marker':'old-pass'}))
 def qualify(self):return self.ns['qualify'](*self.args,self.cache,self.policy)
 def test_frozen_client_hashes_running_executable_and_invalidates_same_version_pass(self):
  self.cached();self.assertEqual(self.qualify()['marker'],'old-pass')
  self.assertIn('/proc/self/exe',self.paths);self.assertNotIn(self.ns['__file__'],self.paths)
  before=self.inputs();(self.root/'client').write_text('new bundle, identical version and native library')
  self.assertNotEqual(before['qualifier_sha256'],self.inputs()['qualifier_sha256'])
  # A changed client must attempt qualification, rather than return old PASS.
  self.ns['subprocess']=types.SimpleNamespace(STDOUT=-2,Popen=lambda *a,**kw:(_ for _ in ()).throw(QualificationRequired()))
  with self.assertRaises(QualificationRequired):self.qualify()
 def test_reader_job_and_transport_changes_do_not_reuse_pass(self):
  for component in ('tools/telemetry_db.py','slurm/jasper_job.sh','policy'):
   with self.subTest(component=component):
    self.cached();self.assertEqual(self.qualify()['marker'],'old-pass')
    if component=='policy':self.policy['JIPSTATS_FRAME_ENCODING']='members_v1'
    else:(self.root/component).write_text('changed '+component)
    self.ns['subprocess']=types.SimpleNamespace(STDOUT=-2,Popen=lambda *a,**kw:(_ for _ in ()).throw(QualificationRequired()))
    with self.assertRaises(QualificationRequired):self.qualify()
 def test_source_client_uses_real_script(self):
  self.ns['sys'].frozen=False;self.ns['__file__']=str(self.root/'entry.py')
  i=self.inputs();self.assertEqual(i['qualifier_kind'],'producer_script')
  self.assertEqual(i['qualifier_sha256'],hashlib.sha256((self.root/'entry.py').read_bytes()).hexdigest())
if __name__=='__main__':unittest.main()
