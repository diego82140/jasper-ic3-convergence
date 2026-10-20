#!/bin/sh
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
[ "$actual" = '712459e786d2302ec41658e8278bc89730c9029e2b01c578e54f151177d39dc0' ] || {
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
[ "$actual" = '3d1994cdcb2e9de419f7322e7be795e3c239fac67e03512988dc356271afb26c' ] || { echo 'Repair download checksum mismatch; nothing changed.' >&2; exit 2; }
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
    "event_library_sha256=712459e786d2302ec41658e8278bc89730c9029e2b01c578e54f151177d39dc0" "library_unchanged=true" \
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
