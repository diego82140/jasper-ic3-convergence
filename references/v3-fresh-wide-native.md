# v3 fresh wide native CTI validation (2026-11-03)

This test produced fresh current-producer captures and read them with the v3 runtime and reader.
- Runtime: jipstats `a25a7385`, library `98d9f845`, reader `f81199d4`.
- Builds and engines: all four exact builds, each with M and M4.
- Qualification: the existing per-build native qualifications were reused from cache.

Evidence and fixture:
- [Machine-readable evidence](v3-fresh-wide-native.json).
- The exact tested fixture is in [examples/wide-cti](../examples/wide-cti/README.md).

The fixture is a two-stage, 6144-bit parity pipeline.
- A free `bug_en` input makes stage 1 shift instead of rotate, which is a deliberately reachable bug.
- No assumptions; synchronous active-low reset.

| Check | All 8 cells |
|---|---|
| Native result | `cex`/`cex`, 3-cycle trace; `visualize -confirm` true; every native trace step matches the RTL update |
| Capture | strict closed archive; 4 complete JIP cubes per cell |
| Largest cube | 6145-literal predecessor cube over `v0`, `c0` and `d0[6142:0]`; `d0[6143]` unknown; all names retained-inverted |
| Source meaning | Under `rstn=1`, `stall=0`, `bug_en=1` and `v0=1`, the next state violates the target **iff** parity(d0[6142:0]) ≠ c0. This holds independently of `d0[6143]` and of the current `v1`/`c1`/`d1`. |
| Comparison with June | same meaning and same raw payload; September adds only the documented configuration/named-display records |
| Resources | sampled Jasper process-tree RSS 1.04–1.24 GiB (guard samples; not a cap or unique physical memory); reader ≈25 MiB; archive ≈1.07 MB at gzip-9 |

The guards `rstn`, `stall` and `bug_en` come from the source and the observed trace. They are not a decoded native query formula; that query context is opaque.

**What the source dependence explains, and what it does not.**
- It explains why `d0[6143]` and the current stage-1 registers are not needed for the guarded next-step violation.
- It does not explain why or how the engine omitted them.

**Can a sound reachable-state helper exclude this cube? No.**
- The native trace's cycle-2 state is inside it. That trace supplies one reachable full completion, which has `d0[6143]=1`.
- This does not mean every completion with `d0[6143]=1` is reachable.
- The source-derived relation `c0 == ^d0` excludes only the `d0[6143]=0` part of the cube. That relation was not proved or used natively.

**Unresolved composites.** The two one-literal composite cubes stay unresolved, not zero.

**Stress run.** A four-stage variant on the original build, engine M, ended `undetermined` at its 600 s limit. That is not a CEX and not a non-inductiveness claim.
- Archive: 1.70 GB, 8,059,484 records.
- Strict full ingest: 5:25 at 32,548 KiB RSS.
- Contents: 26,145 complete JIP cubes, 121.6 M literal rows, maximum 6146.

**Scoped analysis.** One verified batch of 14 selected complete cubes decoded in 63 s at 28,560 KiB.
- Two captured predecessor pairs are stage projections consistent with the RTL update under the stated guards.
- They are not stitched concrete transition witnesses.
- No stall cause and no helper benefit is shown.

**Query scope.** Full ingest checks the whole capture. Analysis then decodes an explicitly selected, complete batch.
- An unnecessary whole-history text decode was cancelled after producing 9.9 GB of partial output.
- That was a validation-harness scope correction. The canonical data was not truncated or corrupted.

**Not claimed.** Page-walker/CHI target closure, the engine's causal history, helper proofs, matched speedup, universal solver or byte identity, memory bounds, hidden-formula coverage, and raw-SAT word semantics.
