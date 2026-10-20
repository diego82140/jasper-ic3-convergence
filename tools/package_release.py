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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    root=a.root.resolve();a.output.mkdir(parents=True,exist_ok=False)
    version=json.loads((root/'.claude-plugin/plugin.json').read_text())['version']
    paths=[x for x in root.rglob('*') if x.is_file() and not x.is_symlink() and not any(part in {'.git','rebuilt','__pycache__'} for part in x.relative_to(root).parts) and x.suffix!='.pyc']
    inputs=[x for x in paths if x.relative_to(root).parts[0]=='third_party']
    runtime=[x for x in paths if x.relative_to(root).parts[0]!='third_party']
    # Retain the linked Frida license/asset provenance in the runnable kit.
    runtime += [x for x in inputs if x.name in {'COPYING','ASSET.json','SOURCE-EXCLUSIONS.json'}]
    manifest=json.loads(subprocess.check_output(['/usr/bin/python3',str(root/'tools/artifact_manifest.py'),str(root)]))
    result={'plugin_version':version,'published':False,'runtime_manifest':manifest,'artifacts':[archive(root,runtime,a.output/f'jasper-ic3-convergence-{version}.tar.gz'),archive(root,inputs,a.output/f'jasper-ic3-convergence-{version}-rebuild-inputs.tar.gz')],'install':'Extract the runtime archive. To rebuild offline, also extract the rebuild-inputs archive into the same parent directory. Native qualifications and agent validation have separate dispositions in references/validation.json.'}
    (a.output/'RELEASE.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='runtime_manifest'},indent=2))
if __name__=='__main__':main()
