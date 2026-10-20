from pathlib import Path
import hashlib,json,shutil,tarfile,io,stat,zipfile,os
R=Path('/mnt/data/jipstats-fix');P=R/'1.1.2/jipstats-linux-x86_64';O=Path('/mnt/data');E=R/'evidence'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
hashworker='b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604'
release_evidence=P/'evidence/repair-1.1.2';release_evidence.mkdir(exist_ok=True)
for name in ['rebuild-1.1.2.json','repair-tests.log','discovery-1.1.0.json','discovery-1.1.0.log','discovery-1.1.2.json','discovery-1.1.2.log']:
 shutil.copy2(E/name,release_evidence/name)
shutil.copytree(E/'target-abi-1.1.2',release_evidence/'target-abi',dirs_exist_ok=True)
# The ABI-probe .so is a producer test executable, not part of customer payload.
for f in (release_evidence/'target-abi').rglob('*.so'):f.unlink()
report={'version':'1.1.2','fix':'Exact worker adapter embedded in standalone launcher; absent or stale profiles/ cannot remove support.',
        'target_worker_sha256':hashworker,'target_markers':0,
        'old_1_1_0_error_reproduced':True,'frozen_launcher_regressions':{'passed':16,'failed':0},
        'target_function_abi_tests':'PASS_CONTROLLED_FIXTURES_NOT_NATIVE_PROVE',
        'target_generated_records':201,'target_relative_query_pairs':32,'target_solver_wrapper_pairs':32,
        'target_whole_native_M_M4_proofs':'NOT_RUN_COMPLETE_MATCHING_RUNTIME_NOT_PRESENT',
        'event_library_sha256':sha(P/'libjipstats.so'),'event_library_unchanged_from_1_1_0':True,
        'customer_sources_required':False,'customer_compiler_required':False,'customer_python_required':False,
        'discovery_is_not_native_qualification':True}
(P/'STATUS.json').write_text(json.dumps(report,indent=2)+'\n')
(P/'VERIFICATION.json').write_text(json.dumps(report,indent=2)+'\n')
changelog='''JIPSTATS 1.1.2 — REPAIR FOR THE REPORTED STRIPPED WORKER

Run from a complete package:
  ./jipstats --check -vv /path/to/jasper

Known exact adapters are now EMBEDDED in the frozen launcher. The profiles/
directory is optional for those supported images. The new launcher selects the
uploaded marker-free b5006df1...a81604 worker even when profiles/ is deleted,
empty, or contains an inconsistent sidecar. It verifies the paired event DSO
hash and all 17 original instruction guards before selecting this adapter.
The DSO still produces its own IC3_STATS records; missing legacy markers are
not a compatibility requirement.

The supplied repair-jipstats-1.1.2.sh updates an existing 1.1.0/1.1.1 package
in place. Run it FROM THE DIRECTORY CONTAINING YOUR CURRENT ./jipstats:
  bash /path/to/repair-jipstats-1.1.2.sh /path/to/jasper
It checks the installed runtime/library hashes, backs up changed files, installs
the prebuilt launcher and own source updates, then runs native --check locally.
It neither edits the Jasper installation nor supplies/replaces a Jasper engine.
Use --discover-only before the target path to repair and inspect without a
license checkout or full native check. No customer compiler/Python is used.

This repair was tested against the actual uploaded worker for discovery and
controlled function ABI calls. Those are NOT full Jasper M/M4 proof runs.
The complete matching 2026.09 frontend/runtime was not supplied; the three
uploaded binaries do not comprise a full installation. The old native proof
evidence belongs to its stated Atlas derivative, not this release worker.
The customer --check must pass on the complete matching installation.

A frontend/worker EPF101 mismatch is now reported as such, with native error
text and its evidence path. No binary-version or license guard is bypassed.

Telemetry remains session-wide. Cube payloads are raw/bounded Formula values;
a complete proof-obligation dependency graph is not implemented.
'''
(P/'CHANGES-1.1.2.txt').write_text(changelog)
(P/'README.txt').write_text(changelog+'\n--- Previous backend and adapter documentation ---\n'+(P/'README.txt').read_text())
# The self-check now uses an explicitly supplied test directory, not info script.
(P/'tests/prove.tcl').write_text((P/'tests/prove.tcl').read_text().replace('set dir [file dirname [info script]]','set dir $::env(JIPSTATS_TEST_DIR)'))
# Production/review source is included; no customer compilation is required.
shutil.copy2(R/'test_repair.py',P/'source/tests/repair_regressions.py')
(P/'source/tests/repair_regressions.py').write_text((P/'source/tests/repair_regressions.py').read_text().replace("R=Path('/mnt/data/jipstats-fix')", "R=Path(os.environ.get('JIPSTATS_REPAIR_TEST_WORKSPACE','/mnt/data/jipstats-fix'))"))
(P/'source/README.md').write_text((P/'source/README.md').read_text()+'''\n\n1.1.2: Exact .events payloads are embedded in source/jipstats.py. Rebuild with\nmake launcher using Python 3.13 and objcopy; the customer uses the supplied\nexecutable. The DSO and its native build inputs have not changed.\nrepair_regressions.py uses JIPSTATS_REPAIR_TEST_WORKSPACE as an optional producer\nworkspace containing extracted 1.1.0/1.1.2 packages and the actual target archive.\n''')
# Remove bytecode generated by producer test imports; do not ship runtime tests as libs.
for f in P.rglob('__pycache__'):
 if f.is_dir():shutil.rmtree(f)
manifest=''.join(sha(f)+'  '+str(f.relative_to(P))+'\n' for f in sorted(P.rglob('*')) if f.is_file() and f.name!='SHA256SUMS')
(P/'SHA256SUMS').write_text(manifest)
# Payload excludes frozen Python and the unchanged native observer, already installed.
base=R/'1.1.0/jipstats-linux-x86_64'
changed=[]
for f in sorted(P.rglob('*')):
 if not f.is_file():continue
 rel=f.relative_to(P)
 if rel.parts[0] in ('_internal','third_party') or str(rel) in ('libjipstats.so','SHA256SUMS'):continue
 old=base/rel
 if not old.is_file() or sha(old)!=sha(f):changed.append(str(rel))
payload_io=io.BytesIO()
with tarfile.open(fileobj=payload_io,mode='w:gz') as t:
 for rel in changed:t.add(P/rel,arcname=rel,recursive=False)
 for name,data in [('INSTALL-FILES','\n'.join(changed)+'\n'),
                   ('PAYLOAD-SHA256SUMS',''.join(sha(P/rel)+'  '+rel+'\n' for rel in changed)),
                   ('RUNTIME-SHA256SUMS',''.join(sha(f)+'  '+str(f.relative_to(P))+'\n' for f in sorted((P/'_internal').rglob('*')) if f.is_file()))]:
  b=data.encode();i=tarfile.TarInfo(name);i.size=len(b);i.mode=0o644;t.addfile(i,io.BytesIO(b))
payload=payload_io.getvalue();phash=hashlib.sha256(payload).hexdigest()
header=r'''#!/bin/sh
# Self-contained prebuilt repair. The payload contains only own changes.
# Run from the folder containing the existing ./jipstats, with one Jasper path.
set -eu
mode=--check
if [ "${1:-}" = --discover-only ]; then mode=--discover-only; shift; fi
if [ "$#" -ne 1 ]; then
    printf '%s\n' 'Usage: bash repair-jipstats-1.1.2.sh [--discover-only] /path/to/jasper' >&2
    exit 2
fi
target=$1
for cmd in sha256sum tar awk tail mktemp cp mv mkdir chmod ln rm find sort xargs; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing standard Linux utility: $cmd" >&2; exit 2; }
done
[ "$(uname -m)" = x86_64 ] || { echo 'This package is for Linux x86-64.' >&2; exit 2; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
package=
for candidate in "$PWD" "$script_dir" "$PWD/jipstats-linux-x86_64" "$script_dir/jipstats-linux-x86_64"; do
    if [ -f "$candidate/jipstats" ] && [ -f "$candidate/libjipstats.so" ] && [ -d "$candidate/_internal" ]; then
        package=$(CDPATH= cd -- "$candidate" && pwd -P); break
    fi
done
if [ -z "$package" ]; then
    echo 'Run this repair from the folder containing your existing ./jipstats.' >&2
    exit 2
fi
actual=$(sha256sum -- "$package/libjipstats.so"); actual=${actual%% *}
[ "$actual" = '@LIBHASH@' ] || {
    echo 'The installed .so is not the 1.1.x event-producing library. No files were changed.' >&2
    echo "Package: $package  Library SHA-256: $actual" >&2
    exit 2
}
lock="$package/.jipstats-repair.lock"
mkdir -- "$lock" 2>/dev/null || { echo "Repair lock exists: $lock. Another repair may be running." >&2; exit 2; }
tmp=
committed=0
begun=0
backup=
cleanup() {
    if [ "$begun" = 1 ] && [ "$committed" = 0 ] && [ -n "$tmp" ] && [ -f "$tmp/changed" ]; then
        while IFS= read -r rel; do
            if [ -f "$backup/$rel" ]; then
                cp -p -- "$backup/$rel" "$package/$rel" || :
            else rm -f -- "$package/$rel" || :; fi
        done < "$tmp/changed"
        echo 'Repair did not commit; original changed files were restored.' >&2
    fi
    if [ -n "$tmp" ]; then rm -rf -- "$tmp"; fi
    rmdir -- "$lock" 2>/dev/null || :
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' HUP TERM
tmp=$(mktemp -d "$package/.jipstats-repair.XXXXXX")
line=$(awk '/^__JIPSTATS_PAYLOAD__$/ {print NR+1; exit}' "$0")
[ -n "$line" ] || { echo 'Repair payload missing.' >&2; exit 2; }
tail -n "+$line" -- "$0" > "$tmp/update.tgz"
actual=$(sha256sum -- "$tmp/update.tgz"); actual=${actual%% *}
[ "$actual" = '@PAYLOADHASH@' ] || { echo 'Repair download checksum mismatch; nothing changed.' >&2; exit 2; }
mkdir "$tmp/stage"
tar -xzf "$tmp/update.tgz" -C "$tmp/stage"
(cd "$tmp/stage" && sha256sum -c PAYLOAD-SHA256SUMS) > "$tmp/payload-check.log"
(cd "$package" && sha256sum -c "$tmp/stage/RUNTIME-SHA256SUMS") > "$tmp/runtime-check.log" || {
    echo 'Frozen Python runtime differs from the tested 1.1.x package. No changes made.' >&2
    cat "$tmp/runtime-check.log" >&2; exit 2
}
ln -s "$package/_internal" "$tmp/stage/_internal"
ln -s "$package/libjipstats.so" "$tmp/stage/libjipstats.so"
chmod 755 "$tmp/stage/jipstats"
echo '[repair] Checking the actual worker with the fixed prebuilt launcher.'
"$tmp/stage/jipstats" --discover-only -v --diagnostic "$tmp/preflight.json" "$target"
backup="$package/.jipstats-backup-$$"
mkdir "$backup"
: > "$tmp/changed"
begun=1
# Install supporting files first. The executable is switched last, by rename.
for pass in data launcher; do
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        if [ "$pass" = data ] && [ "$rel" = jipstats ]; then continue; fi
        if [ "$pass" = launcher ] && [ "$rel" != jipstats ]; then continue; fi
        mkdir -p -- "$backup/$(dirname -- "$rel")" "$package/$(dirname -- "$rel")"
        if [ -f "$package/$rel" ]; then cp -p -- "$package/$rel" "$backup/$rel"; fi
        printf '%s\n' "$rel" >> "$tmp/changed"
        cp -p -- "$tmp/stage/$rel" "$tmp/replacement"
        mv -f -- "$tmp/replacement" "$package/$rel"
    done < "$tmp/stage/INSTALL-FILES"
done
if [ -f "$package/SHA256SUMS" ]; then cp -p "$package/SHA256SUMS" "$backup/SHA256SUMS"; fi
printf '%s\n' SHA256SUMS >> "$tmp/changed"
printf '%s\n' "version=1.1.2" "package=$package" "backup=$backup" \
    "event_library_sha256=@LIBHASH@" "library_unchanged=true" \
    'preflight=exact_adapter_selected_not_native_proof' > "$package/REPAIR-1.1.2.txt"
(
    cd "$package"
    find . -type f ! -path './.jipstats-*/*' ! -path './SHA256SUMS' -print0 |
        sort -z | xargs -0 sha256sum
) > "$tmp/new-manifest"
mv -f "$tmp/new-manifest" "$package/SHA256SUMS"
"$package/jipstats" --version
committed=1
echo "[repair] Updated: $package"
echo "[repair] Backup: $backup"
echo '[repair] Jasper installation files and libjipstats.so were not changed.'
cleanup
trap - 0 INT HUP TERM
exec "$package/jipstats" "$mode" -vv "$target"
exit 2
__JIPSTATS_PAYLOAD__
'''
header=header.replace('@LIBHASH@',sha(P/'libjipstats.so')).replace('@PAYLOADHASH@',phash)
installer=O/'repair-jipstats-1.1.2.sh';installer.write_bytes(header.encode()+payload);installer.chmod(0o755)
# Store the readable source and payload creation information separately for review.
(P/'source/repair-1.1.2-header.sh').write_text(header)
(P/'source/repair-1.1.2-payload.json').write_text(json.dumps({'payload_sha256':phash,'files':changed,'runtime_base':'1.1.x, exact _internal hashes'},indent=2)+'\n')
shutil.copy2(R/'package_repair.py',P/'source/package_repair.py')
# Recompute final package manifest after adding the repair sources.
(P/'SHA256SUMS').write_text(''.join(sha(f)+'  '+str(f.relative_to(P))+'\n' for f in sorted(P.rglob('*')) if f.is_file() and f.name!='SHA256SUMS'))
full=O/'jipstats-linux-x86_64-1.1.2.zip'
with zipfile.ZipFile(full,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for f in sorted(P.rglob('*')):
  if not f.is_file():continue
  rel=str(f.relative_to(P.parent));i=zipfile.ZipInfo(rel,date_time=(2026,9,25,0,0,0));i.create_system=3
  i.external_attr=(stat.S_IFREG|(f.stat().st_mode&0o777))<<16;i.compress_type=zipfile.ZIP_DEFLATED
  z.writestr(i,f.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)
with zipfile.ZipFile(full) as z:assert z.testzip() is None
report['deliverables']=[{'name':f.name,'bytes':f.stat().st_size,'sha256':sha(f)} for f in [installer,full]]
(O/'jipstats-1.1.2-VERIFICATION.json').write_text(json.dumps(report,indent=2)+'\n')
(O/'jipstats-1.1.2-SHA256SUMS').write_text(''.join(sha(f)+'  '+f.name+'\n' for f in [installer,full]))
print(json.dumps(report,indent=2))
