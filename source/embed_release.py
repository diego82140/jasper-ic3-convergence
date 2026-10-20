#!/usr/bin/env python3
"""Producer: embed current prebuilt-library checksum and exact profiles in launcher.
Does not invent a profile, add compatibility, or claim unexecuted qualification.
"""
from pathlib import Path
import ast,hashlib,json,argparse

def embed(package):
    source=package/'source/jipstats.py';text=source.read_text();lines=text.splitlines(keepends=True)
    profiles={p.stem:p.read_text() for p in sorted((package/'profiles').glob('*.events'))}
    replacements={'BUILTIN_LIBRARY_SHA256':hashlib.sha256((package/'libjipstats.so').read_bytes()).hexdigest(),
                  'BUILTIN_EVENT_ADAPTERS':profiles,
                  'BUILTIN_ADAPTER_METADATA':{k:{'markers_required':False,'details_abi':('details 1' in v),
                     'hook_count':sum(x.startswith('hook ') for x in v.splitlines()),
                     'profile_sha256':hashlib.sha256(v.encode()).hexdigest(),
                     'Dollar_parity_contract':('cti-validation-lens-queue-focus-and-scalars' if k=='b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604' else 'not_differentially_certified_for_this_profile'),
                     'validation_scope':'See packaged 1.5.0 differential parity certificate; local --check still required',
                     'native_frontend_qualification':'RUN_LOCALLY_FOR_MATCHING_INSTALLATION'} for k,v in profiles.items()}}
    edits=[]
    for node in ast.parse(text).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name in replacements:edits.append((node.lineno-1,node.end_lineno,name+' = '+repr(replacements[name])+'\n'))
    if len(edits)!=3:raise RuntimeError('Expected three versioned declarations')
    for a,b,new in sorted(edits,reverse=True):lines[a:b]=[new]
    text=''.join(lines);compile(text,str(source),'exec');source.write_text(text)
    return replacements['BUILTIN_LIBRARY_SHA256']
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('package',type=Path)
    a=p.parse_args();print(embed(a.package.resolve()))
