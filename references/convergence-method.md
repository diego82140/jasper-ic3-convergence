# Convergence theory references

The complete operational method is in [AGENTS.md](../AGENTS.md): §3 interprets induction evidence and representation heuristics; §4 ranks families and targets; §5 defines the learning attempts and sample contracts; §6 defines certified support, conjunctions and cold replay. Use those sections as the authority. [inductiveness-method.md](inductiveness-method.md) is the design-agnostic recipe behind them: structural candidates (phase, single occupancy, held copy, no-early-event), base/step obligations, hazard covers for environment windows, and what each native result certifies. This file supplies primary sources for investigating a theorem or algorithm; reading it does not execute one.

- [Bradley, SAT-Based Model Checking Without Unrolling](https://theory.stanford.edu/~arbrad/papers/IC3.pdf): IC3 frames, relative induction and clause strengthening.
- [Feldman et al., Complexity and Information in Invariant Inference](https://arxiv.org/pdf/1910.12256): oracle distinctions and restricted complexity results. Check theorem premises before applying a bound to native proof search.
- [Invariant Inference With Provable Complexity From the Monotone Theory](https://www.cs.tau.ac.il/~sharonshoham/papers/sas22.pdf): representation and query assumptions, not a general Jasper convergence guarantee.
- [Horn-ICE Learning for Synthesizing Invariants and Contracts](https://arxiv.org/pdf/1712.09418): typed positive/negative/Horn samples and unsplit antecedents.
- [H-Houdini: Scalable Invariant Learning](https://cwfletcher.github.io/content/research/2025.asplos.hhoudini.paper.pdf): slicing, mining, abduction and memoization contracts. Ordinary support-first proving alone does not establish execution of this algorithm.

Use the selected installation's official command and engine-selection manuals for native `prove`, conversion, disabled properties, proof reuse and engine capabilities. Paper notation, captured samples and native reachable-state proofs have different certificate scopes; retain that distinction.
