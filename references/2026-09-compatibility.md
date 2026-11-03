# Production September compatibility

The production `2026.09` and `2026.09p001` workers are different stripped ELF
builds from the previously supported August prerelease. A release-name alias is
insufficient. The adapter pins the entire worker SHA256 and validates instruction
guards before installing any hooks. Native report callbacks, validation branches,
pending-invariant caller attribution and Formula node tables are build-specific.
No solver routine, configuration, operand or result is replaced.

| Installation | Worker SHA256 |
|---|---|
| `2026.0920260826065032` | `b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604` |
| `2026.06p002` | `e8cbfa93df42061662aaa530125f47d9255ff29b160aa3559d65c706bb24ce1d` |
| `2026.09` | `b3e7723c4335266b1cd1436277111d54ee7802944b8b4f7d6eaacaa28b7c84b4` |
| `2026.09p001` | `e1b53cf546e048df0f9996646afba34b0faf7b38095b22ed700a507b64cf4e7b` |

Existing event profiles and the frozen v1 package are unchanged. June retains its
documented full-payload/native-validation support and its existing named-display
limitation. September has the Dollar-compatible CTI, validation, obligation lens,
queue and focus displays, in addition to the complete canonical disk stream.

## What information parity means

Equal proof verdicts alone do not establish parity. The regression compares all
record fields and literal diagnostic text from both M and M4 on five pinned
models, with uninstrumented controls for each build. The normal strict streaming
reader must reconstruct every capture successfully first. This checks complete
cube bytes, names, predecessor pairs, frame membership, queue observations,
relative/SAT queries and native validation results, including field presence.
Native controls compare decoded verdicts, target IDs and CEX lengths; raw native
protocol traffic is retained but not claimed completely semantically equivalent.

Execution IDs, ASLR addresses, exact-build instruction addresses and durations
need explicit normalization. Address normalization preserves alias relationships;
code addresses map only to reviewed hook identities. Address identities retire
at observed queue-removal/obligation-destruction boundaries, so allocator reuse
does not fabricate a persistent alias. Durations must be finite,
nonnegative and retain their fields. Only the collector's unordered hash-table
membership-removal batch is sorted; every member, field and duplicate remains.
Native frame and queue entry order is preserved. No comparison takes a field intersection,
discards absent event families or truncates payloads. The comparator includes
negative controls for a missing field, a missing event and a modified literal
payload. Search differences, when present, must be reported, never erased to
obtain PASS. Finite regressions are not a universal equivalence proof for all
Jasper models or an assertion-correctness certificate.

The first full comparison caught a missing queue-dequeue event despite native
smoke qualification passing. The initial PLT mapping selected tree erasure; the
actual existing observer requires `std::__detail::_List_node_base::_M_unhook`.
The corrected mapping follows the original relocation's symbol identity on each
build. A missing canonical event must fail the comparison. The larger shared
model additionally exposed an existing delta-collector bug: a recycled list-node
address could hide removal of its previous obligation. The collector now compares
both node address and obligation identity. A native C regression exercises
recycling, unchanged membership and ordinary removal; reinstating the old
predicate deliberately fails that regression.

## Reproduce

Work in a maintainer clone; do not overwrite an installed or mapped library.
Rebuild with the pinned patched Gum SDK and a compatible producer sysroot, as
described in [GUM_BUILD.md](../source/GUM_BUILD.md). Regenerate each production
profile with:

```bash
python3 source/release_adapters/build_production_202609.py \
  /path/to/selected/Linux64/bin/jg_proof --output /shared/regenerated-profiles
```

For each installation, run `slurm/submit.sh check` in its own fresh directory,
with explicit resources, license configuration and the selected `JASPER` path.
Run them sequentially when limited to one application license. The qualification
receipt binds the actual worker, library, profile, launcher and reader identities.

The producer-only cross-release regression is:

```bash
python3 source/tests/parity/cross_release.py \
  --output /shared/fresh-information-parity \
  --models /shared/pinned-parity-models
```

Submit this work to Slurm Formal with one CPU and measured memory; do not run
workers on the submit host. The model directory contains `model.bs` under `xy`,
`and_predecessor`, `composite_property` and `delayed_bug`, paired with the existing
shared protocol model. Sources are in `source/tests/parity/models.py`; the
original Dollar regression records their generation and exact identities.
`INFORMATION-PARITY.json` records every model hash, result and normalization rule.
An interrupted or failing comparison is not parity evidence.

The repository's wider convergence-validation status remains separate from
release compatibility. See [validation.json](validation.json) for dispositions.
The [independent review and dispositions](2026-09-review.md) distinguish the
reviewed candidate mappings from the final executed checks and retained limits.
