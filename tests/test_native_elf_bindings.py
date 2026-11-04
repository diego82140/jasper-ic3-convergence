"""Semantic ELF symbol selection, independently of matching prologue bytes."""
import struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'source/release_adapters'))
from build_b5006df1 import plt_symbols

class NativeElfBindings(unittest.TestCase):
    def test_relocation_selects_the_actual_symbol(self):
        raw=bytearray(0x600);raw[:6]=b'\x7fELF\x02\x01'
        struct.pack_into('<Q',raw,40,0x100);struct.pack_into('<HHH',raw,58,64,6,1)
        names=b'\0.shstrtab\0.dynstr\0.dynsym\0.rela.plt\0.plt\0';raw[0x400:0x400+len(names)]=names
        symbol=b'\0_ZNSt8__detail15_List_node_base9_M_unhookEv\0';raw[0x450:0x450+len(symbol)]=symbol
        def section(i,name,kind,address,offset,size,link=0,entry=0):
            struct.pack_into('<IIQQQQIIQQ',raw,0x100+i*64,names.index(name+b'\0'),kind,0,address,offset,size,link,0,8,entry)
        section(1,b'.shstrtab',3,0,0x400,len(names));section(2,b'.dynstr',3,0,0x450,len(symbol))
        section(3,b'.dynsym',11,0,0x480,48,2,24);section(4,b'.rela.plt',4,0,0x4c0,24,3,24)
        section(5,b'.plt',1,0x1000,0x4e0,32)
        struct.pack_into('<IBBHQQ',raw,0x480+24,1,0,0,0,0,0)
        struct.pack_into('<QQq',raw,0x4c0,0,1<<32|7,0)
        self.assertEqual(plt_symbols(bytes(raw)),{0x1010:symbol[1:-1].decode()})
    def test_other_elf_layouts_are_not_guessed(self):
        with self.assertRaises(ValueError):plt_symbols(b'unknown')

if __name__=='__main__':unittest.main()
