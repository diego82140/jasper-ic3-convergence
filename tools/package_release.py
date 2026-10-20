#!/usr/bin/env python3
"""Package a runtime/source kit separately from optional offline rebuild inputs."""
import argparse,gzip,hashlib,json,os,subprocess,tarfile
from pathlib import Path

def archive(root,paths,destination):
    with destination.open('xb') as raw:
        with gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=9,mtime=0) as z:
            with tarfile.open(fileobj=z,mode='w|') as tar:
                for path in sorted(paths):
                    info=tar.gettarinfo(str(path),arcname='jasper-ic3-convergence/'+str(path.relative_to(root)))
                    info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
                    with path.open('rb') as stream:tar.addfile(info,stream)
        raw.flush();os.fsync(raw.fileno())
    h=hashlib.sha256()
    with destination.open('rb') as stream:
        for b in iter(lambda:stream.read(1024*1024),b''):h.update(b)
    return {'file':destination.name,'bytes':destination.stat().st_size,'sha256':h.hexdigest(),'members':len(paths)}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--inputs',type=Path,default=None,help='third-party rebuild inputs directory (default: <root>/third_party if present, else <root>/../jasper-ic3-convergence-build/third_party); kept outside the plugin root so a local-path install copies only the runtime')
    a=p.parse_args()
    root=a.root.resolve();a.output.mkdir(parents=True,exist_ok=False)
    version=json.loads((root/'.claude-plugin/plugin.json').read_text())['version']
    paths=[x for x in root.rglob('*') if x.is_file() and not x.is_symlink() and not any(part in {'.git','rebuilt','third_party','__pycache__'} for part in x.relative_to(root).parts) and x.suffix!='.pyc']
    inputs_dir=a.inputs or ((root/'third_party') if (root/'third_party').is_dir() else root.parent/'jasper-ic3-convergence-build'/'third_party')
    inputs_dir=inputs_dir.resolve()
    if not inputs_dir.is_dir():raise SystemExit(f'rebuild inputs directory not found: {inputs_dir} (pass --inputs)')
    inputs=[x for x in inputs_dir.rglob('*') if x.is_file() and not x.is_symlink()]
    runtime=paths
    def archive_inputs(dest):
        # rebuild inputs are archived under jasper-ic3-convergence/third_party/... whatever directory they live in
        with dest.open('xb') as raw:
            with gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=9,mtime=0) as z:
                with tarfile.open(fileobj=z,mode='w|') as tar:
                    for path in sorted(inputs):
                        info=tar.gettarinfo(str(path),arcname='jasper-ic3-convergence/third_party/'+str(path.relative_to(inputs_dir)))
                        info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
                        with path.open('rb') as stream:tar.addfile(info,stream)
            raw.flush();os.fsync(raw.fileno())
        h=hashlib.sha256()
        with dest.open('rb') as stream:
            for b in iter(lambda:stream.read(1024*1024),b''):h.update(b)
        return {'file':dest.name,'bytes':dest.stat().st_size,'sha256':h.hexdigest(),'members':len(inputs)}
    manifest=json.loads(subprocess.check_output(['/usr/bin/python3',str(root/'tools/artifact_manifest.py'),str(root)]))
    provenance=[x for x in inputs if x.name in {'COPYING','ASSET.json','SOURCE-EXCLUSIONS.json'}]
    result={'plugin_version':version,'published':False,'runtime_manifest':manifest,'rebuild_inputs_dir':str(inputs_dir),'license_provenance_in_inputs':[str(x.relative_to(inputs_dir)) for x in provenance],'artifacts':[archive(root,runtime,a.output/f'jasper-ic3-convergence-{version}.tar.gz'),archive_inputs(a.output/f'jasper-ic3-convergence-{version}-rebuild-inputs.tar.gz')],'install':'Extract the runtime archive. To rebuild offline, also extract the rebuild-inputs archive into the same parent directory (it unpacks as jasper-ic3-convergence/third_party). Native qualifications and agent validation have separate dispositions in references/validation.json.'}
    (a.output/'RELEASE.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='runtime_manifest'},indent=2))
if __name__=='__main__':main()
