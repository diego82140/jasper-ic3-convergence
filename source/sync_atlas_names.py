"""Embed our finite Atlas retained-name checker in the portable own entry module."""
from pathlib import Path
root=Path(__file__).resolve().parent
body=(root/'atlas_names_check.py').read_text();body=body[body.index('def check(text):'):].replace('def check(text):','def check_atlas_names(text):',1)
p=root/'jipstats.py';s=p.read_text();begin='# BEGIN EMBEDDED ATLAS NAME CHECK\n';end='# END EMBEDDED ATLAS NAME CHECK\n'
block=begin+body+'\n'+end
if begin in s:
 a=s.index(begin);z=s.index(end,a)+len(end);s=s[:a]+block+s[z:]
else:s=s.replace('def qualify(',block+'\ndef qualify(',1)
p.write_text(s)
