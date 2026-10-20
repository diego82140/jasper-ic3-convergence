#!/usr/bin/env python3
"""Keep observed Slurm/license polling loops out of Claude Bash calls.
This is a workflow guard, not a shell parser or a proof timeout. The same
checks apply to foreground and run_in_background calls: a background watcher
belongs to the CLI process and cannot resume the investigation after it exits.
Native jobs, monitors and ordinary one-shot status reads are unaffected.
"""
import json,re,sys

def reason(request):
    if request.get('tool_name')!='Bash':return None
    tool=request.get('tool_input',{})
    command=tool.get('command','')
    # Restrict to the Slurm/log polling patterns seen in validation. A command
    # which writes a script/heredoc may contain a worker sleep; leave it alone.
    if '<<' in command:return None
    if re.search(r'\btail\b[^\n;]*--pid(?:=|\s)',command) and re.search(r'\btail\b[^\n;]*(?:-f\b|--follow\b)',command):
        return 'Do not wait in tail --pid/--follow calls, foreground or run_in_background: a CLI watcher is no durable continuation and ends with the CLI. Record the exact task PID/job/step handles and a completion/exit-code receipt, inspect them once, and record an explicit external checkpoint with the resume command. pgrep -f can match the waiting shell itself and deadlock. Native proof jobs continue unchanged.'
    if re.search(r'\b(?:python\d*|sbatch|srun)\b',command):return None
    poll=re.search(r'\b(?:squeue|sacct)\b',command) or re.search(r'\b(?:cat|tail|grep|rg|test)\b[^\n;]*(?:capture\.log|jg\.log|iter\.report|diag\.report|receipts\.txt|job\.id)',command)
    if not poll:return None
    delays=re.findall(r'(?:^|[\n;&]|\bdo)\s*sleep\s+(\d+(?:\.\d+)?)([smh]?)\b',command)
    long_delay=any(float(n)*{'':1,'s':1,'m':60,'h':3600}[unit]>60 for n,unit in delays)
    loop=bool(delays and re.search(r'\b(?:while|until|for)\b[^\n]*',command))
    if long_delay or loop:
        return 'Do not poll in a loop, foreground or run_in_background: a CLI watcher is no durable continuation and cannot resume the work after the CLI exits. Use one nonblocking Slurm/log status read, continue independent analysis, and if still pending record the exact job/step/wrapper handles and an explicit external checkpoint with the resume command. Native Slurm proof jobs continue unchanged.'
    return None

def main():
    message=reason(json.load(sys.stdin))
    if message:print(message,file=sys.stderr);return 2
    return 0
if __name__=='__main__':sys.exit(main())
