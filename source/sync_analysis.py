#!/usr/bin/env python3
"""Embed exactly the extension-owned analysis.py into the portable entry module."""
from pathlib import Path
import hashlib

def synchronize(source: Path) -> dict:
    module=(source/'analysis.py').read_text()
    boundary="\nif __name__=='__main__':"
    if module.count(boundary)!=1:raise ValueError('Cannot identify analysis module entry point')
    body=module.split(boundary,1)[0]
    entry=source/'jipstats.py';text=entry.read_text()
    marker='# Embedded extension-owned analysis, exactly matching source/analysis.py.'
    if text.count(marker)!=1 or text.count('\ndef main(argv=None):')!=1:raise ValueError('Unexpected launcher structure')
    before=text.index(marker);after=text.index('\ndef main(argv=None):',before)
    replacement=marker+'\n'+body+'\n'
    updated=text[:before]+replacement+text[after:]
    compile(updated,str(entry),'exec')
    if updated!=text:entry.write_text(updated)
    return {'analysis_sha256':hashlib.sha256(module.encode()).hexdigest(),'changed':updated!=text}
if __name__=='__main__':
    import json
    print(json.dumps(synchronize(Path(__file__).resolve().parent),indent=2))
