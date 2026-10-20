#!/usr/bin/env python3
"""Record RSS for a Slurm job's local Jasper process tree; external jobs are separate."""
import csv,os,re,subprocess,sys,time
parent=int(sys.argv[1])
with open(sys.argv[2],'w') as f:
    out=csv.writer(f);out.writerow(['unix_seconds','pid','command','rss_kib'])
    while os.path.exists('/proc/'+str(parent)):
        rows=[]
        for line in subprocess.check_output(['ps','-eo','pid=,ppid=,rss=,comm=,args='],text=True).splitlines():
            p,pp,rss,comm,args=line.split(None,4)
            # Atlas executes native images through its bundled ELF loader. The
            # kernel comm can therefore name ld-linux rather than the engine.
            if comm.startswith('ld-linux'):
                match=re.search(r'/(jg_console|jg_session|jg_proof)(?:\.bin)?(?:\s|$)',args)
                if match:comm=match[1]
            rows.append((int(p),int(pp),int(rss),comm))
        descendants={parent}
        for _ in range(20):
            added={p for p,pp,rss,comm in rows if pp in descendants};new=added-descendants
            if not new:break
            descendants.update(new)
        now=time.time()
        for p,pp,rss,comm in rows:
            if p in descendants and comm.startswith(('jg_','jasper')):out.writerow([now,p,comm,rss])
        f.flush();time.sleep(.5)
