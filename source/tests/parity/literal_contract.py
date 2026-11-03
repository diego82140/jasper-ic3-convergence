"""Syntactic interface anchor. This does not prove presence predicates or an ABI."""
import argparse,ast,hashlib,json,re
from pathlib import Path
FILES=('events.c','details.h','semantics.h','parity.h','activations.h')
TOKEN=re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|[^\s]',re.S)

def inventory(root):
    sites=[];hashes={}
    for name in FILES:
        raw=(root/'source/src'/name).read_bytes();text=raw.decode();hashes[name]=hashlib.sha256(raw).hexdigest()
        tokens=[m.group() for m in TOKEN.finditer(text) if not m.group().startswith(('/*','//'))]
        for i,word in enumerate(tokens[:-1]):
            if word!='emit' or tokens[i+1]!='(':continue
            args=[[]];depth=1
            for token in tokens[i+2:]:
                if token=='(':depth+=1
                if token==')':depth-=1
                if not depth:break
                if token==',' and depth==1:args.append([])
                else:args[-1].append(token)
            if len(args)<4 or 'struct' in args[0]:continue
            literals=lambda seq:[ast.literal_eval(t) for t in seq if t.startswith('"')]
            phases=literals(args[1]);fmt=''.join(literals(args[3]))
            if not phases:raise ValueError('Dynamic phase requires explicit contract review: '+name)
            sites.append(dict(phases=phases,fields=sorted(set(re.findall(r'\b(\w+)=',fmt)))))
    return dict(scope='Literal call-site fields only; dynamic fragments and semantic applicability require separate review',source_sha256=hashes,sites=sites)

def missing_sites(baseline,current):
    remaining=list(current['sites']);missing=[]
    for site in sorted(baseline['sites'],key=lambda s:-len(s['fields'])):
        for i,candidate in enumerate(remaining):
            if site['phases']==candidate['phases'] and set(site['fields'])<=set(candidate['fields']):
                remaining.pop(i);break
        else:missing.append(site)
    return missing

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.write_text(json.dumps(inventory(args.root),indent=2)+'\n')
