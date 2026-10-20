#!/usr/bin/env python3
"""Create an exact-ELF JIP telemetry profile, without modifying the executable.
Requires pyelftools. A generated profile is structural evidence, NOT a native
Jasper validation certificate. Unsupported or stripped binaries are rejected.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser

class Unsupported(RuntimeError):
    pass

def name(die):
    a=die.attributes.get('DW_AT_name')
    return a.value.decode('utf-8',errors='replace') if a else ''

def type_die(die):
    if 'DW_AT_type' not in die.attributes: return None
    d=die.get_DIE_from_attribute('DW_AT_type')
    while d and d.tag in ('DW_TAG_typedef','DW_TAG_const_type','DW_TAG_volatile_type','DW_TAG_restrict_type'):
        d=d.get_DIE_from_attribute('DW_AT_type')
    return d

def primitive(die):
    d=type_die(die)
    if d is None: return ('void',0,None)
    if d.tag=='DW_TAG_pointer_type':
        return ('pointer',int(d.attributes.get('DW_AT_byte_size').value) if d.attributes.get('DW_AT_byte_size') else 8,None)
    a=d.attributes.get('DW_AT_byte_size'); e=d.attributes.get('DW_AT_encoding')
    return (d.tag,int(a.value) if a else None,int(e.value) if e else None)

def const_location(attr,structs):
    if isinstance(attr.value,int): return int(attr.value)
    ops=DWARFExprParser(structs).parse_expr(attr.value)
    if len(ops)==1 and ops[0].op_name in ('DW_OP_constu','DW_OP_plus_uconst'):
        return int(ops[0].args[0])
    raise Unsupported('Nonconstant DWARF layout expression')

def member(die,key):
    for c in die.iter_children():
        if c.tag=='DW_TAG_member' and name(c)==key:
            a=c.attributes.get('DW_AT_data_member_location')
            if a is None or c.attributes.get('DW_AT_bit_size'): raise Unsupported('Missing/bitfield member '+key)
            return const_location(a,die.cu.structs),primitive(c)
    raise Unsupported('Missing Jip member '+key)

def method_slot(die,key,arg_types):
    candidates=[]
    for c in die.iter_children():
        if c.tag!='DW_TAG_subprogram' or name(c)!=key: continue
        a=c.attributes.get('DW_AT_vtable_elem_location')
        if a is None: continue
        params=[d for d in c.iter_children() if d.tag=='DW_TAG_formal_parameter' and not (d.attributes.get('DW_AT_artificial') and d.attributes['DW_AT_artificial'].value)]
        types=[primitive(d) for d in params]
        if types!=arg_types or primitive(c)!=('void',0,None):
            raise Unsupported(f'Unexpected signature for {name(die)}::{key}: {types}')
        candidates.append(const_location(a,die.cu.structs))
    if len(set(candidates))!=1: raise Unsupported('Missing or ambiguous virtual slot '+name(die)+'::'+key)
    return candidates[0]


"""Marker-independent exact-ELF event profile derivation.
No marker, source tree, compiler, symbol demangler or external program is needed
on the customer machine. Stripped builds require a supplied exact-hash adapter.
"""
from pathlib import Path
import hashlib, json, re, struct
from elftools.elf.elffile import ELFFile
ep_name=name; ep_member=member; ep_type=type_die; ep_slot=method_slot; ep_primitive=primitive


def derive(binary):
    binary=Path(binary)
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    with binary.open('rb') as stream:
        elf=ELFFile(stream)
        if elf.elfclass!=64 or not elf.little_endian or elf['e_machine']!='EM_X86_64':
            raise Unsupported('EVENT_ABI_ARCHITECTURE: only little-endian x86-64 is supported')
        table=elf.get_section_by_name('.symtab')
        if table is None:
            raise Unsupported('EVENT_HOOK_LOCATIONS_UNRESOLVED: this stripped worker needs an exact-build event adapter; absence of IC3_STATS is NOT the reason')
        if not (elf.get_section_by_name('.debug_info') or elf.get_section_by_name('.zdebug_info')):
            raise Unsupported('EVENT_ABI_LAYOUT_UNRESOLVED: no DWARF layout and no matching bundled event adapter; telemetry markers are not required')
        symbols=[s for s in table.iter_symbols() if s['st_shndx']!='SHN_UNDEF' and s['st_value']]
        functions=[s for s in symbols if s['st_info']['type']=='STT_FUNC' and not s.name.endswith('.cold')]
        segments=list(elf.iter_segments())
        def read_va(address,size):
            segment=next((s for s in segments if s['p_type']=='PT_LOAD' and s['p_vaddr']<=address and address+size<=s['p_vaddr']+s['p_filesz']),None)
            if segment is None:raise Unsupported('Event metadata address is not in file-backed memory')
            stream.seek(segment['p_offset']+address-segment['p_vaddr']);data=stream.read(size)
            if len(data)!=size:raise Unsupported('Truncated event target')
            return data
        def code(address,size=16):
            if not any(s['p_type']=='PT_LOAD' and s['p_flags']&1 and s['p_vaddr']<=address and address+size<=s['p_vaddr']+s['p_filesz'] for s in segments):
                raise Unsupported('Event hook is not in executable memory')
            return read_va(address,size)
        def matches(prefix):return [s for s in functions if s.name.startswith(prefix)]
        def constant(suffix):
            candidates=[s for s in symbols if s.name.endswith(suffix) and s['st_size']==4]
            values={struct.unpack('<i',read_va(s['st_value'],4))[0] for s in candidates}
            if len(values)!=1:raise Unsupported('EVENT_RESULT_DECODER_UNRESOLVED: '+suffix)
            return next(iter(values))
        true,false,unknown=(constant('6l_True'),constant('7l_False'),constant('7l_Undef'))
        if len({true,false,unknown})!=3:raise Unsupported('Invalid lbool result constants')
        classes={};enums={};dwarf=elf.get_dwarf_info()
        needed={'Jip','ICSeq','JipCallbackHook','vec<Formula>','Formula','ProofResult','lbool'}
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                nm=ep_name(die)
                if die.tag in ('DW_TAG_class_type','DW_TAG_structure_type') and nm in needed and nm not in classes and 'DW_AT_byte_size' in die.attributes:
                    classes[nm]=die
                if die.tag=='DW_TAG_enumeration_type':
                    vals={ep_name(c):c.attributes['DW_AT_const_value'].value for c in die.iter_children() if c.tag=='DW_TAG_enumerator'}
                    if {'PR_Valid','PR_Cex'}<=vals.keys():enums['proof']=vals
                    if {'MODEL','UNSAT','UNSAT_ASSUME'}<=vals.keys():enums['solver']=vals
            if needed<=classes.keys() and {'proof','solver'}<=enums.keys():break
        missing=needed-classes.keys()
        if missing or {'proof','solver'}-enums.keys():raise Unsupported('EVENT_ABI_LAYOUT_UNRESOLVED: '+str(sorted(missing))+'; enums='+str(sorted(enums)))
        if any(c.tag=='DW_TAG_inheritance' for c in classes['Jip'].iter_children()):
            raise Unsupported('Jip inheritance requires an explicit adapter')
        cb,cbtype=ep_member(classes['Jip'],'callback')
        if cbtype!=('pointer',8,None):raise Unsupported('Callback is not a 64-bit pointer')
        report=ep_slot(classes['JipCallbackHook'],'report',[('pointer',8,None),('DW_TAG_base_type',4,7),('DW_TAG_base_type',1,2)])
        k,kt=ep_member(classes['ICSeq'],'k');ob,ot=ep_member(classes['ICSeq'],'obligations')
        if kt!=('DW_TAG_base_type',4,5) or ot!=kt:raise Unsupported('ICSeq counter types not signed 32-bit')
        data,dt=ep_member(classes['vec<Formula>'],'data');size,st=ep_member(classes['vec<Formula>'],'sz')
        if dt!=('pointer',8,None) or st!=kt or classes['Formula'].attributes['DW_AT_byte_size'].value!=4:
            raise Unsupported('Cube/Formula representation needs a different adapter')
        result,rt=ep_member(classes['ProofResult'],'_result')
        if result!=0 or rt[0]!='DW_TAG_enumeration_type' or rt[1]!=4:raise Unsupported('Unsupported ProofResult representation')
        value,vt=ep_member(classes['lbool'],'value')
        if value!=0 or vt!=kt or classes['lbool'].attributes['DW_AT_byte_size'].value!=4:raise Unsupported('Unsupported lbool return representation')
        # Validate parameter roles from concrete C++ member declarations, not strings.
        expected={'ic_init_solver':(1,[('DW_TAG_reference_type',8,None)]),
                  'ic_solve_relative':(5,[('DW_TAG_reference_type',8,None),kt,('DW_TAG_base_type',4,7),('DW_TAG_reference_type',8,None),('pointer',8,None)]),
                  'ic_stats':(2,[('DW_TAG_reference_type',8,None),('DW_TAG_reference_type',8,None)])}
        for method,(n,types) in expected.items():
            ds=[c for c in classes['Jip'].iter_children() if c.tag=='DW_TAG_subprogram' and ep_name(c)==method]
            if len(ds)!=1:raise Unsupported('Ambiguous event method declaration '+method)
            params=[c for c in ds[0].iter_children() if c.tag=='DW_TAG_formal_parameter' and not (c.attributes.get('DW_AT_artificial') and c.attributes['DW_AT_artificial'].value)]
            if len(params)!=n or [ep_primitive(p) for p in params]!=types:raise Unsupported('Parameter ABI mismatch '+method)
        hooks=[];metadata=[]
        def add(kind,s,args):
            address=int(s['st_value'])
            if any(x[1]==address for x in hooks):return
            hooks.append((kind,address,args,code(address).hex()));metadata.append({'kind':kind,'symbol':s.name,'address':hex(address),'argument_roles':args})
        # kind, source name, ABI: this, ICSeq, frame, flags, cube, constant_flags
        mappings=[('init','14ic_init_solver',[0,1,-1,-1,-1,-1],True),
                  ('frame','13ic_init_level',[0,1,-1,-1,-1,-1],False),
                  ('relative','17ic_solve_relative',[0,1,2,3,4,-1],True),
                  ('relative','28ic_refineinit_solve_relative',[0,1,2,3,4,-1],False),
                  ('stats','8ic_stats',[0,1,-1,-1,-1,-1],True),
                  ('generalize','13ic_generalize',[0,3,2,-1,1,-1],False),
                  ('block','8ic_block',[0,3,-1,-1,1,-1],False),
                  ('obligation','20ic_process_proof_obl',[0,4,-1,-1,-1,-1],False),
                  ('push','7ic_push',[0,1,-1,-1,-1,-1],False),
                  ('run','17ic_fixture_driver',[0,1,-1,-1,-1,-1],False)]
        refine={int(s['st_value']) for s in matches('_ZN3Jip28ic_refineinit_solve_relative') if '.' not in s.name}
        for kind,part,args,required in mappings:
            funcs=matches('_ZN3Jip'+part)
            if required and not funcs:raise Unsupported('EVENT_HOOK_LOCATIONS_UNRESOLVED: '+part)
            for s in funcs:
                roles=list(args)
                if '.constprop.' in s.name:
                    if kind=='relative':
                        # Specialized flags and removedLits cause argument elision.
                        # Decode the actual register move/fixed-argument tail-call;
                        # never apply the unspecialized signature to a clone.
                        b=code(int(s['st_value']),40)
                        signature=b'\x49\x89\xc8\x45\x31\xc9\xb9'
                        pos=b.find(signature)
                        if pos<0 or b[pos+11]!=0xe9:raise Unsupported('EVENT_CLONE_ABI_UNRESOLVED: '+s.name)
                        flag=struct.unpack_from('<I',b,pos+7)[0]
                        target=int(s['st_value'])+pos+16+struct.unpack_from('<i',b,pos+12)[0]
                        if target not in refine or flag not in (0,1):raise Unsupported('Unverified specialized relative-query target')
                        roles=[0,1,2,-1,3,flag]
                    else:
                        raise Unsupported('EVENT_CLONE_ABI_UNRESOLVED: '+s.name+'; an exact build adapter is needed to cover all clones')
                elif '.' in s.name:
                    raise Unsupported('Unknown optimized function variant '+s.name)
                add(kind,s,roles)
        solver_funcs=[s for s in functions if s.name.startswith('_ZN8JSolverTI7FormulaE12solveLimited')]
        if not solver_funcs:
            # Fixture and non-template builds can expose the same verified ABI.
            solver_funcs=[s for s in functions if s.name.startswith('_ZN7JSolver12solveLimited')]
        if not solver_funcs:raise Unsupported('EVENT_SOLVER_BOUNDARY_UNRESOLVED: no supported solveLimited method')
        for s in solver_funcs:
            if '.isra.' in s.name:
                b=code(int(s['st_value']))
                if not b.startswith(b'\x41\x54\x48\x63\xd2\x41\x89\xcc'):
                    raise Unsupported('EVENT_SOLVER_CLONE_ABI_UNRESOLVED: '+s.name)
                args=[-1,-1,2,3,-1,-1] # input data pointer + length, budget
            elif '.' not in s.name:args=[-1,-1,-1,2,1,-1] # vec reference, budget
            else:raise Unsupported('Unknown solver method variant '+s.name)
            add('sat',s,args)
        fields=[k,ob,-1,-1,-1,-1]
        lines=['JIPSTATS_EVENTS 1','sha256 '+digest,f'callback {cb} {report}',
               'fields '+' '.join(map(str,fields)),f'cube {data} {size} 4',
               f'relative_results {true} {false} {unknown}',
               'solver_results '+' '.join(str(enums['solver'][n]) for n in ('MODEL','UNSAT','UNSAT_ASSUME')),
               'proof_results '+' '.join(str(enums['proof'][n]) for n in ('PR_Valid','PR_Cex'))]
        for kind,address,args,guard in hooks:lines.append('hook '+kind+' '+format(address,'x')+' '+' '.join(map(str,args))+' '+guard)
    return '\n'.join(lines)+'\n',{'backend':'events','binary':str(binary.resolve()),'sha256':digest,
           'markers_required':False,'hook_sites_are_algorithm_operations_not_logging_sites':True,
           'validation':'STRUCTURAL_ONLY_NATIVE_QUALIFICATION_REQUIRED','hooks':metadata,
           'callback_offset':cb,'callback_report_slot':report,'icseq_depth_offset':k,'icseq_obligations_offset':ob}
