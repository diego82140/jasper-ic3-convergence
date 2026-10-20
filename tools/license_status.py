#!/usr/bin/env python3
"""Read-only aggregate FlexNet status; never expose per-user checkout records."""
import argparse,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('jasper');a=p.parse_args()
root=Path(a.jasper)
tool=next((x for x in ([Path(os.environ['LMUTIL'])] if os.environ.get('LMUTIL') else [])+[root/'bin/lmutil',root/'Linux64/bin/lmutil'] if x.is_file() and os.access(x,os.X_OK)),None)
result={'status':'unavailable','installation':str(root.resolve()),'features':{},'note':'Availability is a snapshot, not a reserved license or proof result.'}
if not tool:result['reason']='no executable lmutil in selected installation; set LMUTIL explicitly'
if tool and not os.environ.get('LM_LICENSE_FILE'):
 result['reason']='LM_LICENSE_FILE not set'
 tool=None
if tool:
 try:
  r=subprocess.run([str(tool),'lmstat','-a','-c',os.environ['LM_LICENSE_FILE']],capture_output=True,text=True,timeout=15)
  for name,total,used in re.findall(r'Users of (jasper_\w+):.*?Total of (\d+) licenses issued;.*?Total of (\d+) licenses in use',r.stdout):
   result['features'][name]={'issued':int(total),'in_use':int(used),'available':max(0,int(total)-int(used))}
  result['status']='observed' if result['features'] else 'unavailable'
  if not result['features']:result['reason']='lmstat returned no Jasper feature summaries (exit '+str(r.returncode)+')'
  result['note']+=' Native checkout logs identify the actual feature; an absent aggregate feature is not evidence that no license is required.'
 except subprocess.TimeoutExpired:result['reason']='lmstat timed out after15s'
 except OSError as e:result['reason']='lmstat could not start: '+str(e)
print(json.dumps(result,indent=2))
