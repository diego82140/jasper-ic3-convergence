#!/usr/bin/env python3
"""Inspect an authorized Jasper display without optional desktop utilities.
Run on its allocation with DISPLAY and XAUTHORITY from display.txt.
"""
import argparse,ctypes as C,ctypes.util,struct,zlib
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    shot=sub.add_parser('snapshot');shot.add_argument('output')
    key=sub.add_parser('key');key.add_argument('window',type=lambda s:int(s,0));key.add_argument('keysym',help='e.g. Return; explicitly targets the named window')
    a=p.parse_args();x=C.CDLL(ctypes.util.find_library('X11'))
    def bind(name,args,result):
        f=getattr(x,name);f.argtypes=args;f.restype=result;return f
    ptr=C.c_void_p;ul=C.c_ulong;i=C.c_int
    d=bind('XOpenDisplay',[C.c_char_p],ptr)(None)
    if not d:raise SystemExit('Cannot open authorized display')
    try:
        if a.action=='key':
            xt=C.CDLL(ctypes.util.find_library('Xtst'))
            xt.XTestFakeKeyEvent.argtypes=[ptr,C.c_uint,i,ul]
            bind('XSetInputFocus',[ptr,ul,i,ul],i)(d,a.window,2,0)
            sym=bind('XStringToKeysym',[C.c_char_p],ul)(a.keysym.encode())
            code=bind('XKeysymToKeycode',[ptr,ul],C.c_uint)(d,sym)
            if not code:raise SystemExit('Unknown keysym')
            xt.XTestFakeKeyEvent(d,code,1,0);xt.XTestFakeKeyEvent(d,code,0,0)
            bind('XSync',[ptr,i],i)(d,0)
        else:
            screen=bind('XDefaultScreen',[ptr],i)(d)
            w=bind('XDisplayWidth',[ptr,i],i)(d,screen);h=bind('XDisplayHeight',[ptr,i],i)(d,screen)
            root=bind('XRootWindow',[ptr,i],ul)(d,screen)
            im=bind('XGetImage',[ptr,ul,i,i,C.c_uint,C.c_uint,ul,i],ptr)(d,root,0,0,w,h,ul(-1).value,2)
            if not im:raise SystemExit('XGetImage failed')
            pixel=bind('XGetPixel',[ptr,i,i],ul)
            # Xvnc is deliberately configured at depth 24 (TrueColor RGB).
            def chunk(k,b):return struct.pack('!I',len(b))+k+b+struct.pack('!I',zlib.crc32(k+b)&0xffffffff)
            compressor=zlib.compressobj(3)
            with Path(a.output).open('wb') as f:
                f.write(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',w,h,8,2,0,0,0)))
                for y in range(h):
                    row=bytearray([0])
                    for j in range(w):
                        v=pixel(im,j,y);row.extend(((v>>16)&255,(v>>8)&255,v&255))
                    b=compressor.compress(row)
                    if b:f.write(chunk(b'IDAT',b))
                f.write(chunk(b'IDAT',compressor.flush())+chunk(b'IEND',b''))
            bind('XDestroyImage',[ptr],i)(im)
    finally:bind('XCloseDisplay',[ptr],i)(d)
if __name__=='__main__':main()
