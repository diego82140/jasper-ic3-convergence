#!/usr/bin/env python3
"""Pin the executable, skill and runtime scripts consumed by one Slurm run."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--verify',type=Path);a=p.parse_args()
root=a.root.resolve();paths=['jipstats','libjipstats.so','AGENTS.md','CLAUDE.md','.claude-plugin/plugin.json']
for glob in ['slurm/*.sh','session/*.sh','session/*.tcl','tools/*.py','skills/**/SKILL.md','references/*.md','hooks/*.py','hooks/*.json','profiles/*.events','profiles/*.json']:
 paths.extend(str(x.relative_to(root)) for x in root.glob(glob) if x.is_file())
files={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in sorted(set(paths))}
tree=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
result={'runtime_sha256':tree,'root':str(root),'plugin_version':json.loads((root/'.claude-plugin/plugin.json').read_text())['version'],'files':files}
if a.verify:
 prior=json.loads(a.verify.read_text())
 if prior['root']!=str(root) or prior['files']!=files:raise SystemExit('Plugin artifact changed after submission; use a frozen plugin copy and a fresh run')
 print(tree)
else:print(json.dumps(result,indent=2))
