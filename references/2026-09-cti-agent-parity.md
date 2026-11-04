# Direct CTI information parity (2026-11-03)

The local `1.6.15-dev` candidate passes the finite CTI-information checks for
production Jasper `2026.09` and `2026.09p001`, alongside the original September
prerelease. Original and June exact-worker frontend qualification also passes.
[Machine-readable results](2026-09-cti-agent-parity.json) bind the runtime, reader,
reports and resource receipts. This is a local candidate, with no remote publication.

## Executed evidence

- **32 native checks:** four exact builds, M/M4, baseline/preload, proof/CEX.
  Existing matching receipts are reused; no unchanged qualification was repeated.
- **Five pinned models, both engines, three September builds:** strict archive
  ingestion precedes comparison. The old references are the independent Dollar /
  producer1.5.0 corpus and fresh original-main/solver producer1.6.13 captures
  (Formal job `2509979`). Exact command bytes and effective configuration match.
- **Per five-model/two-engine suite:** 38 named CTIs, 2,159 complete cubes,
  10,721 raw literal words, 364 explicit predecessor pairs, 1,547 frame snapshots,
  25,923 ordered frame members and 2,581 query conclusions. Comparisons include
  empty frames, full frame order/duplicates, cube roles and generalization.
  Named CTI bytes match the independent old oracle. Every raw word is compared,
  including unqualified SAT atoms. Hashes alone are not the payload comparison.
- **Decoding:** 1,807 mapped JIP constrained-bit literals, 20 unresolved composite
  literals and 8,894 unqualified SAT-domain words. Retained-name inversion is
  preserved; unknown bits never become zero. An explicit predecessor pair has no
  invented query association or reachable-transition label.
- **Controls:** 203 prior automated tests are reused, 10 new comparison tests
  pass, and 12 mutations of actual native-derived views reject the intended
  information loss or false semantics. The two-Boolean `xy` source example
  checks initialization/consecution/target implication exhaustively; it is not
  CEQ closure or measured helper benefit.

Final comparison job `2519962` completed normally with sampled peak RSS
39,419,904 bytes (37.6 MiB). Supplementary raw-word comparison `2522891` completed
normally at 20,451,328 bytes (19.5 MiB). These are analysis-process samples, not
Jasper solver caps. Full compressed canonical telemetry stays on disk; derived
indexes are disposable.

## Boundaries and retained failures

Producer1.5.0 did not emit explicit predecessor pairs. Its original canonical
records remain unchanged; temporary reader framing reconstructs only the complete,
SHA-verified display payload already present as hex. It is a derived view, not a
new native run. The fresh1.6.13 comparison covers the explicit pair capability.

The earlier complete raw-pointer-history comparison still has a **FAIL** receipt:
allocator reuse histories differ. The finite direct CTI data checks do not need
those numeric-address histories to be identical and do not establish unobserved
native allocation lifetimes. Neither original failure receipts nor fields were
erased to obtain the new verdict.

The four earlier independent implementation reviews remain valid for their
recorded scopes. A new focused review request `d0ae36f9-3952-4c48-bfef-5b3e9746cc33`
failed before registration/Send with `TRANSPORT_CONTEXT_ERROR`; it supplies no
review acceptance and has not been retried.

These results certify only the stated finite compatibility/data tests. They do
not establish universal equivalence, full hidden solver formulas, CEQ closure,
end-to-end Claude behavior or a general bound on Jasper solving memory. June
retains its documented older named-display limitation.

## Reproduce the direct checks

Use a fresh output directory for each command, on Slurm Formal with measured
memory. All inputs below are preserved under
`/projects/diego1/jasper-202609-validation/direct-cti-agent-parity-20261103`.

```bash
python3 source/tests/parity/agent_cti_parity.py \
  --legacy /formal_shared/diego1/jipstats-linux-x86_64/evidence/results-1.5.0/parity \
  --captures /projects/diego1/jasper-202609-validation/information-parity-r7 \
  --output /shared/fresh-direct-check
python3 source/tests/parity/complete_agent_parity.py \
  --baseline /projects/diego1/jasper-202609-validation/direct-cti-agent-parity-20261103/producer-1.6.13 \
  --updated-views /shared/fresh-direct-check --output /shared/fresh-complete-check
python3 tests/test_agent_cti_parity.py
```

`raw_payload_parity.py` is the site-bound supplementary check: `--root` points to
the preserved task directory containing accepted `results-r3` and
`complete-results-r3` reports; `--output` is a fresh directory. Its results do not
replace the prerequisite strict archive/decoder checks.
