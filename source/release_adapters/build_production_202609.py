#!/usr/bin/env python3
"""Regenerate reviewed production September adapters, never infer an unknown ABI.

Metadata contains exact worker, instruction, callback and helper-reference guards.
Regeneration is an offline check; native M/M4 qualification remains separate.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from build_b5006df1 import image_reader, plt_symbols

SUPPORTED = {
    'b3e7723c4335266b1cd1436277111d54ee7802944b8b4f7d6eaacaa28b7c84b4',
    'e1b53cf546e048df0f9996646afba34b0faf7b38095b22ed700a507b64cf4e7b',
}

def build(worker, output):
    raw = worker.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in SUPPORTED:
        raise ValueError('Unknown exact worker hash; no adapter generated')
    meta = json.loads((Path(__file__).resolve().parents[2]/'profiles'/(digest+'.json')).read_text())
    if meta['worker_sha256'] != digest or meta['worker_bytes'] != len(raw):
        raise ValueError('Worker identity mismatch')
    read = image_reader(raw)
    for line in meta['profile_lines']:
        if line.startswith('hook '):
            p = line.split()
            guard = bytes.fromhex(p[-1])
            if read(int(p[2],16),len(guard)) != guard:
                raise ValueError('Instruction guard mismatch: '+p[1])
    hooks={}
    for line in meta['profile_lines']:
        if line.startswith('hook '):
            p=line.split();hooks.setdefault(p[1],[]).append(int(p[2],16))
    unlink=meta['queueunlink_plt'];unlink_rva=int(unlink['rva'],16)
    symbol='_ZNSt8__detail15_List_node_base9_M_unhookEv'
    if unlink['symbol']!=symbol or hooks['queueunlink']!=[unlink_rva] or plt_symbols(raw).get(unlink_rva)!=symbol:
        raise ValueError('Queue-unlink native relocation symbol mismatch')
    cb = meta['callback_proof']
    fn = int(cb['report_function'],16)
    slot = int(cb['native_callback_vtable_address_point'],16)+8*cb['report_vtable_slot']
    guard = bytes.fromhex(cb['report_function_bytes'])
    if struct.unpack('<Q',read(slot,8))[0] != fn or read(fn,len(guard)) != guard:
        raise ValueError('Native report callback mismatch')
    for ref in meta['formula_global_references']:
        guard = bytes.fromhex(ref['guard'])
        if read(int(ref['new_ref'],16),len(guard)) != guard:
            raise ValueError('Formula global reference guard mismatch')
    helper = meta['helper_layout']
    initial=int(helper['isinitial_return'],16)
    if read(initial-5,1)!=b'\xe8' or initial+struct.unpack('<i',read(initial-4,4))[0] not in hooks['isinitial']:
        raise ValueError('Initial validation callsite mismatch')
    step=int(helper['validation_step_after'],16);prop=int(helper['validation_property_after'],16)
    if step not in hooks['satafter'] or prop not in hooks['satafter'] or not (hooks['valbase'][0]<step<hooks['valstep'][0]<prop<hooks['valproperty'][0]):
        raise ValueError('Native validation stage ordering mismatch')
    ret = int(helper['pending_front_return'],16)
    if read(ret-5,1) != b'\xe8' or ret+struct.unpack('<i',read(ret-4,4))[0] != int(helper['pending_front_entry'],16):
        raise ValueError('Pending invariant callsite mismatch')
    text = '\n'.join(meta['profile_lines'])+'\n'
    if hashlib.sha256(text.encode()).hexdigest() != meta['profile_sha256']:
        raise ValueError('Profile content mismatch')
    output.mkdir(parents=True,exist_ok=True)
    dest = output/(digest+'.events')
    dest.write_text(text)
    return dest

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('worker',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    print(build(args.worker,args.output))
