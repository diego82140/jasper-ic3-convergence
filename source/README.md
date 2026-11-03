# jipstats 1.6.15-dev development sources

This local candidate supports four exact Cadence worker builds, including production September and September p001. Full disk/gzip telemetry and bounded-memory reading remain the default. Current runtime/reader/profile qualification passes all 32 native M/M4 baseline/preload proof/CEX checks. See [the finite CTI parity report](../references/2026-09-cti-agent-parity.md) for direct old/new information comparisons and exact receipts. Native convergence and end-to-end agent acceptance remain separate.

Build in an idle writable clone:

```bash
make release PYTHON=/path/to/python3.13 COMPAT_LIB=/compatible/Linux64/lib
make test
python3 ../tests/test_disk_transport.py
python3 ../tests/test_telemetry_db.py /path/to/closed/native/qualification/telemetry
```

The build embeds library/profile checksums and atomically replaces the portable launcher and DSO. Its runtime is bundled; full-detail qualification and offline indexing require standard Python 3 plus the packaged `tools/` directory. Display helpers also use installed X11/XTest and Xvnc. The optional rebuild-input archive supplies the patched Gum header/static library, license and checksums. Stock Gum 17.18 lacks the required restoration API and is insufficient. The exact upstream commit and patch are recorded in `third_party/frida-gum/ASSET.json` and `third_party/gum-native-unwind-17.18.0.patch`; [GUM_BUILD.md](GUM_BUILD.md) explains reproduction. Offline compilation with this SDK has been tested, independently of native qualification.

Slurm and development-launcher defaults are disk/full/gzip with `tuple_chunks_v2`. A direct launch prints a fresh working-directory capture path unless `--evidence-dir` is supplied. Console mode is explicit. Run every Jasper process on Formal. Evidence directories must be fresh; disk mode rejects `--live`. Qualification keys include the streaming reader and capture policy. The qualifier discards its verified temporary index after preserving size/hash receipts and does not create an uncompressed history mirror.

The exact worker adapters are original `b5006df1…`, June `e8cbfa93…`, production September `b3e7723c…`, and September p001 `e1b53cf5…`. The release adapter scripts validate full worker hashes and instruction guards before profile generation. `build_production_202609.py` regenerates the two production profiles; `build_e8cbfa93.py` regenerates June. Never guess or copy offsets for another release. Producer/runtime/reader/profile changes invalidate matching qualification; requalify changed components with native M/M4 baseline/preload checks.

The worker's solver, arguments, debug selectors and return values remain native. Records are observer-owned; their transport integrity is not a semantic proof certificate. Native validation observations and final proof status remain distinct from cube projections and suggested helpers. The prior 1.5.0 Dollar parity evidence applies only to its pinned build/configurations; it is not universal qualification of this June adapter.

Run seals finish a gzip member before manifest publication so cancellation after a seal does not rely on ELF destructors. `test_disk_transport.py` includes `_Exit` without destructors and verifies strict/incomplete/closed-subset semantics. A fixture PASS is separate from actual native parallel-engine cancellation and each exact worker requalification.

The large-frame storage regression uses `source/tests/frame_storage_fixture.c` compiled with `-DFIXTURE_MEMBERS=1048641` and the packaged Gum SDK. Run `python3 source/tests/check_large_frame_storage.py /path/to/fixture /fresh/shared/evidence` from the kit root. It checks every ordered raw tuple through the whole-snapshot selector, including duplicates, negative levels and more chunks than the native reuse cache; it retains canonical gzip/manifests and disposes of reconstructible oracle/index files with hashes. `tests/test_frame_membership_delta.py` checks set-delta semantics and failed-scan retry. These are producer fixtures, separate from native M/M4 qualification and convergence replay.
