# Site profile

The method in `AGENTS.md` is design- and site-independent; the values below are the ones this
installation of the kit was qualified with. On another site replace them (and requalify with
`slurm/submit.sh check`), do not change the method.

| item | value here |
|---|---|
| Jasper releases | `/projects/external_ip/cadence/jasper_2026.0920260826065032` (default; qualified worker `b5006df1…`), `/projects/external_ip/cadence/jasper_2026.06p002` (`e8cbfa93…`) |
| Scheduler | Slurm, binaries in `/netbatch/bin` (`SLURM_BIN`); partitions `Formal`, `Formal_192G`; no accounting DB (`sacct` unavailable) |
| License | `LM_LICENSE_FILE` must be set per command (the site does not export it); batch needs `fpv`, the head checks out `jasper_papp` |
| Shared filesystem | run directories must be visible from the nodes (`/tmp` is not) |
| Authorization | which installations and projects an agent may run against is decided by the project owner, recorded in the task, never by this file |

Validation evidence recorded against these values is in `validation.json`; it is operational
evidence for this site, not a proof fact for any design.
