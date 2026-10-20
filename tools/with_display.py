#!/usr/bin/env python3
"""Run a command on a private Xvnc display on its Slurm node, with no VNC TCP listener."""
import os,secrets,signal,subprocess,sys,time,tempfile
from pathlib import Path

def main():
    run=Path(sys.argv[1]);command=sys.argv[2:];auth=run/'display.xauth'
    auth.touch(mode=0o600);auth.chmod(0o600)
    socket_dir=tempfile.TemporaryDirectory(prefix='jasper-display-')
    socket=str(Path(socket_dir.name)/'vnc.sock')
    display=None;server=None;log=(run/'display.log').open('wb')
    try:
        for _ in range(20):
            number=secrets.randbelow(500)+100
            if Path(f'/tmp/.X{number}-lock').exists() or Path(f'/tmp/.X11-unix/X{number}').exists():continue
            display=f':{number}'
            subprocess.run(['xauth','-f',str(auth),'add',display,'MIT-MAGIC-COOKIE-1',secrets.token_hex(16)],check=True,stdout=subprocess.DEVNULL,stderr=log)
            server=subprocess.Popen(['Xvnc',display,'-auth',str(auth),'-geometry','1280x800','-depth','24','-rfbport','-1','-rfbunixpath',socket,'-rfbunixmode','0600','-nolisten','tcp','-localhost','-SecurityTypes','None'],stdout=log,stderr=log)
            env=dict(os.environ,DISPLAY=display,XAUTHORITY=str(auth))
            for _ in range(100):
                if server.poll() is not None:break
                if subprocess.run(['xdpyinfo'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                time.sleep(.1)
            else:raise RuntimeError('display readiness timeout')
            if server.poll() is None:break
        else:raise RuntimeError('could not allocate a private display')
        (run/'display.txt').write_text(f'node={os.uname().nodename}\nDISPLAY={display}\nXAUTHORITY={auth}\nVNC TCP disabled; private node-local Unix X socket; RFB_SOCKET={socket}\n')
        # submit.sh starts Jasper through an explicit clean environment.
        if '-i' in command:
            i=command.index('-i')+1;command[i:i]=['DISPLAY='+display,'XAUTHORITY='+str(auth)]
        return subprocess.call(command,env=env)
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait()
        auth.unlink(missing_ok=True);log.close();socket_dir.cleanup()
if __name__=='__main__':sys.exit(main())
