---
name: jasper-ic3-convergence
description: Use for Jasper (JasperGold) formal-verification tasks whose assertions do not converge (undetermined, stalled, slow): IC3/PDR inductiveness analysis with M/M4 telemetry from jipstats, counterexample-to-induction (CTI) families, sound helper invariants/lemmas, status-gated proof dependency graphs and cold-start replays, all run on Slurm. Also use whenever the user names jasper-ic3-convergence.
---

# Jasper IC3/PDR convergence

The root directory is `${CLAUDE_PLUGIN_ROOT}`. If that text was not replaced by a path, the root directory is the one two levels above this skill's base directory; it contains `AGENTS.md`, `jipstats`, `session/`, `slurm/`, `tools/` and `example/`.

Before doing anything else, read `${CLAUDE_PLUGIN_ROOT}/AGENTS.md` (the `AGENTS.md` in the root directory) completely and follow it exactly for the whole task. The user's project may have its own `AGENTS.md`, `CLAUDE.md`, scripts or a jipstats copy: those describe the project, not this method. Keep the project's conventions where they do not conflict; for the method, its soundness rules and its tools, only this kit applies, and tell the user about any conflict. It is the methodology and the contract: soundness rules, the Jasper/jipstats interface, Slurm execution, evidence interpretation, learning loops, the proof graph and reporting. Every path it names (`jipstats`, `session/`, `slurm/`, `tools/`) is relative to the root directory. The root directory is shared and read-only: never write into it; put run directories, session IO, captures and Jasper projects in the user's own directory on a filesystem the Slurm nodes see.
