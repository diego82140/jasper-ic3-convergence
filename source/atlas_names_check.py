"""Finite differential check of directly retained Atlas names versus native display.
Names come from the observed table, never polarity-vote inference. Native FNV
fingerprints are only used to locate matching observed full raw cubes.
"""
import re

def check(text):
 names={};cubes={};domains={};models=set();display=[]
 for line in text.splitlines():
  if line.startswith('NATIVE_IC3_REPORT '):
   header,native=line.split(' text=',1);r=dict(re.findall(r'(\w+)=([^ ]*)',header));native_run=':'.join(r[k] for k in ('capture','pid','tid','run'));display.append((native_run,native));continue
  if not line.startswith('IC3_STATS '):continue
  r=dict(re.findall(r'(\w+)=([^ ]*)',line));run=':'.join(r[k] for k in ('capture','pid','tid','run'));p=r['phase']
  if p=='model':models.add(run)
  if p=='signal_name_chunk':
   key=(run,int(r['variable']));names[key]=names.get(key,b'')+bytes.fromhex(r['utf8_hex'])
  if p=='cube_definition':domains[(run,int(r['cube_id']))]=r['domain'];cubes[(run,int(r['cube_id']))]=[]
  if p=='cube_chunk':cubes[(run,int(r['cube_id']))].extend(int(x,16) for x in r['values'].split(','))
 def fingerprint(values):
  h=0xcbf29ce484222325
  for v in values:
   for i in range(8):h=((h^((v>>(i*8))&255))*0x100000001b3)&((1<<64)-1)
  return f'{((h^len(values))*0x100000001b3)&((1<<64)-1):016x}'
 lookup={}
 for key,values in cubes.items():
  if domains[key]=='jip_formula':lookup.setdefault((fingerprint(values),len(values)),[]).append((key[0],values))
 verified=0
 for native_run,line in display:
  if not line.startswith('IC3_OBLIGATION_FOCUS '):continue
  f=dict(re.findall(r'(\w+)=([^ ]*)',line));q=dict(re.findall(r'(\w+)="([^"]*)"',line))
  if 'fingerprint' not in f or 'cube_lits' not in f or 'state' not in q:continue
  tokens=[x for x in q['state'].split() if x!='...' and not x.startswith('+')]
  candidates=lookup.get((f['fingerprint'],int(f['cube_lits'])),[])
  for run,values in candidates:
   if run!=native_run:continue
   rendered=[]
   for v in values[:len(tokens)]:
    if v&2:break
    raw=names.get((run,v>>3))
    if raw is None:break
    name=raw.decode()
    if v&4:name=name[1:] if name.startswith('~') else '~'+name
    rendered.append(name)
   if len(rendered)==len(tokens):
    if rendered!=tokens:raise ValueError('Direct retained-name rendering disagrees with native fingerprint-matched cube display')
    verified+=1;break
 if not models:raise ValueError('Atlas direct model payload absent')
 depth={name.decode().lstrip('~') for name in names.values() if re.search(rb'(?:^|\.)depth\[\d+\]$',name.lstrip(b'~'))}
 return dict(models=len(models),retained_names=len(names),depth_bits=len(depth),fingerprint_matched_display_checks=verified,scope='finite retained-name ABI/display differential; not a closed RTL/formula mapping')
