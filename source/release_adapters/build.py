#!/usr/bin/env python3
"""Select only a reviewed exact-hash profile regenerator."""
import argparse,hashlib
from pathlib import Path
from build_b5006df1 import build as original
from build_e8cbfa93 import build as june
from build_production_202609 import build as september, SUPPORTED

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('worker',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();h=hashlib.sha256(a.worker.read_bytes()).hexdigest()
    if h=='b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604':fn=original
    elif h=='e8cbfa93df42061662aaa530125f47d9255ff29b160aa3559d65c706bb24ce1d':fn=june
    elif h in SUPPORTED:fn=september
    else:raise SystemExit('Unknown worker SHA256; no adapter generated')
    print(fn(a.worker,a.output))
