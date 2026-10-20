#!/usr/bin/env python3
"""Update only own Python entry and own prepare module in a portable launcher.
Native loaded bootloader sections, Python runtime and all third-party modules
are unchanged. Producer-only: Python 3.13 and binutils are required.
"""
from pathlib import Path
import sys,marshal,struct,zlib,subprocess,hashlib,tempfile,json
MAGIC=b'MEI\x0c\x0b\x0a\x0b\x0e';COOKIE='!8sIIII64s'
def unpack(path):
 data=Path(path).read_bytes();end=data.rfind(MAGIC)
 magic,length,off,sz,version,lib=struct.unpack_from(COOKIE,data,end);base=end+88-length;pos=base+off
 if base<0 or pos+sz!=end:raise ValueError('Invalid CArchive')
 entries=[]
 while pos<end:
  n,offset,clen,ulen,flag,kind=struct.unpack_from('!IIIIBc',data,pos)
  name=data[pos+18:pos+n].split(b'\0',1)[0].decode();blob=data[base+offset:base+offset+clen]
  entries.append((name,blob,ulen,flag,kind));pos+=n
 return data,entries,version,lib

def update_pyz(raw,source):
 assert raw[:4]==b'PYZ\0'
 import importlib.util
 assert raw[4:8]==importlib.util.MAGIC_NUMBER
 toc_off=struct.unpack_from('!i',raw,8)[0];toc=marshal.loads(raw[toc_off:]);assert isinstance(toc,list)
 start=min(entry[1] for _,entry in toc)
 body=bytearray(raw[:start]);newtoc=[];changed=[]
 for name,(kind,offset,size) in toc:
  blob=raw[offset:offset+size]
  if name=='prepare':
   code=compile(Path(source).read_text(),'prepare.py','exec',optimize=0)
   blob=zlib.compress(marshal.dumps(code),6);changed.append(name)
  newtoc.append((name,(kind,len(body),len(blob))));body+=blob
 assert changed==['prepare']
 at=len(body);body+=marshal.dumps(newtoc);body[8:12]=struct.pack('!i',at)
 for (name,old),(name2,new) in zip(toc,newtoc):
  assert name==name2
  if name!='prepare':assert raw[old[1]:old[1]+old[2]]==body[new[1]:new[1]+new[2]]
 return body

def loaded_sections(data):
 assert data[:6]==b'\x7fELF\x02\x01'
 off=struct.unpack_from('<Q',data,40)[0];size,n,stridx=struct.unpack_from('<HHH',data,58)
 hdr=[struct.unpack_from('<IIQQQQIIQQ',data,off+i*size) for i in range(n)]
 h=hdr[stridx];names=data[h[4]:h[4]+h[5]]
 return {names[h[0]:].split(b'\0',1)[0]:(h[1:4],h[5],b'' if h[1]==8 else data[h[4]:h[4]+h[5]]) for h in hdr if h[2]&2}

def rebuild(old,entry,prepare,new):
 before,entries,version,lib=unpack(old)
 assert version==sys.version_info.major*100+sys.version_info.minor
 body=bytearray();toc=bytearray()
 for name,blob,ulen,flag,kind in entries:
  if name=='jipstats' and kind==b's':
   raw=marshal.dumps(compile(Path(entry).read_text(),'jipstats.py','exec',optimize=0));blob=zlib.compress(raw,9);ulen=len(raw);flag=1
  elif kind==b'z':
   raw=zlib.decompress(blob) if flag else blob;raw=update_pyz(raw,prepare);ulen=len(raw);blob=zlib.compress(raw,9) if flag else raw
  enc=name.encode()+b'\0';length=(18+len(enc)+15)//16*16
  toc+=struct.pack('!IIIIBc',length,len(body),len(blob),ulen,flag,kind)+enc+b'\0'*(length-18-len(enc));body+=blob
 offset=len(body);body+=toc;body+=struct.pack(COOKIE,MAGIC,len(body)+88,offset,len(toc),version,lib)
 with tempfile.TemporaryDirectory() as d:
  payload=Path(d)/'archive';payload.write_bytes(body)
  subprocess.run(['objcopy','--update-section','pydata='+str(payload),str(old),str(new)],check=True)
 Path(new).chmod(0o755);after,newentries,v2,lib2=unpack(new)
 assert (version,lib)==(v2,lib2) and len(entries)==len(newentries)
 assert loaded_sections(before)==loaded_sections(after)
 for a,b in zip(entries,newentries):
  if a[0] not in ('jipstats','PYZ.pyz'):assert a==b
 return {'changed_own_modules':['jipstats','prepare'],'other_python_modules_unchanged':True,
         'native_bootloader_loaded_sections_unchanged':True,'python_version':version,
         'old_sha256':hashlib.sha256(before).hexdigest(),'new_sha256':hashlib.sha256(after).hexdigest()}
if __name__=='__main__':print(json.dumps(rebuild(*sys.argv[1:]),indent=2))
