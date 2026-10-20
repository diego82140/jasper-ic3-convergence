#!/usr/bin/env python3
"""Rebuild only the reviewed exact 2026.06p002 profile; never infer an unknown ABI."""
import argparse,hashlib,json
from pathlib import Path
from build_b5006df1 import image_reader

def build(worker,output):
    meta=json.loads(Path(__file__).with_name('e8cbfa93-adapter.json').read_text())
    raw=worker.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!=meta['worker_sha256']:raise ValueError('wrong worker hash')
    read=image_reader(raw)
    for line in meta['profile_lines']:
        if line.startswith('hook '):
            parts=line.split();guard=bytes.fromhex(parts[-1])
            if read(int(parts[2],16),len(guard))!=guard:raise ValueError('instruction guard mismatch')
    text='\n'.join(meta['profile_lines'])+'\n'
    if hashlib.sha256(text.encode()).hexdigest()!=meta['profile_sha256']:raise ValueError('profile hash mismatch')
    output.mkdir(parents=True,exist_ok=True);p=output/(digest+'.events');p.write_text(text);print(p)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('worker',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.worker,a.output)
