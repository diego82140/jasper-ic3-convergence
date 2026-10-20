#!/usr/bin/env python3
"""Read-only report of memory limits for one of your own processes (default: self).

Distinguishes Slurm reservation (environment, own process only), kernel
cgroup v2 memory.max (hard limit: reclaim then OOM) from memory.high (throttle/
reclaim threshold, not a hard cap), rlimits from /proc/PID/limits (RLIMIT_RSS is
not enforced by modern Linux) and measured RAM. Never changes settings or
limits, sends no signals, reads no command lines, refuses other users' PIDs.
"""
import json
import os
import sys

CG_ROOT = "/sys/fs/cgroup"
RLIMITS = {"Max resident set": "rss", "Max address space": "as", "Max data size": "data"}
STATUS = ("VmRSS", "VmHWM", "VmSize", "Cpus_allowed_list")
SLURM_ENV = ("SLURM_JOB_ID", "SLURM_STEP_ID", "SLURM_MEM_PER_NODE",
             "SLURM_MEM_PER_CPU", "SLURM_CPUS_ON_NODE", "SLURM_JOB_PARTITION")
NOTES = {
    "memory.max": "hard limit: kernel reclaims then OOM-kills the cgroup",
    "memory.high": "throttle/reclaim threshold, NOT a hard cap; usage may exceed it",
    "rss": "RLIMIT_RSS is ignored by Linux >= 2.6 (getrlimit(2)); not a RAM cap",
    "scope": "only cgroup v2 memory.max/high and RLIMIT_AS/DATA are reported; other mechanisms are not checked",
}


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None
    except OSError:  # includes PermissionError
        return OSError


def cg_value(path):
    """'unlimited', int bytes, 'missing', or 'unknown' (unreadable/invalid)."""
    raw = _read(path)
    if raw is None:
        return "missing"
    if raw is OSError:
        return "unknown"
    raw = raw.strip()
    if raw == "max":
        return "unlimited"
    return int(raw) if raw.isdigit() else "unknown"


def effective(values):
    finite = [v for v in values if isinstance(v, int)]
    complete = bool(values) and all(isinstance(v, int) or v == "unlimited" for v in values)
    if complete:
        return {"value": min(finite) if finite else "unlimited", "chain_complete": True, "exact": True}
    # With unknown/missing levels a finite value is only a known upper bound.
    return {"value": "unknown", "known_upper_bound": min(finite) if finite else None,
            "chain_complete": False, "exact": False}


def cgroup_report(cgroup_text, root=CG_ROOT):
    if cgroup_text is None or cgroup_text is OSError:
        return {"mode": "unknown", "reason": "cgroup file unreadable"}
    lines = [l for l in cgroup_text.splitlines() if l]
    v2 = [l.split(":", 2)[2] for l in lines if l.startswith("0::")]
    if len(v2) != 1 or len(lines) != 1:
        return {"mode": "UNSUPPORTED", "reason": "cgroup v1 or hybrid hierarchy not implemented"}
    rel = v2[0].strip("/")
    parts = rel.split("/") if rel else []
    if any(p in (".", "..", "") for p in parts):
        return {"mode": "UNSUPPORTED", "reason": "dot-traversal cgroup path (namespace mismatch?)"}
    chain = []
    for i in range(len(parts), 0, -1):  # leaf to top-level child; the root has no memory.max
        d = os.path.join(root, *parts[:i])
        chain.append({"path": d, **{k: cg_value(os.path.join(d, k)) for k in
                      ("memory.max", "memory.high", "memory.current", "memory.peak")}})
    return {"mode": "v2", "chain": chain,
            "effective_memory.max": effective([c["memory.max"] for c in chain]),
            "effective_memory.high": effective([c["memory.high"] for c in chain])}


def rlimit_report(text):
    out = {k: "unknown" for k in RLIMITS.values()}
    if text is not None and text is not OSError:
        for line in text.splitlines():
            for label, key in RLIMITS.items():
                if line.startswith(label):
                    f = line[len(label):].split()
                    if len(f) >= 2:
                        out[key] = {"soft": f[0], "hard": f[1]}
    return out


def status_report(text):
    if text is None or text is OSError:
        return "unknown"
    return {l.split(":", 1)[0]: l.split(":", 1)[1].strip()
            for l in text.splitlines() if ":" in l and l.split(":", 1)[0] in STATUS}


def report(pid="self", proc="/proc", root=CG_ROOT, uid=None):
    base = os.path.join(proc, str(pid))
    try:
        owner = os.stat(base).st_uid
    except OSError:
        return {"pid": pid, "error": "process not found or not accessible"}
    if owner != (os.getuid() if uid is None else uid):
        return {"pid": pid, "error": "refused: process owned by another user"}
    rep = {"pid": pid, "kernel": os.uname().release, "notes": NOTES,
           "cgroup": cgroup_report(_read(os.path.join(base, "cgroup")), root),
           "rlimits": rlimit_report(_read(os.path.join(base, "limits"))),
           "status": status_report(_read(os.path.join(base, "status")))}
    if str(pid) in ("self", str(os.getpid())):
        rep["slurm_request_env"] = {k: os.environ.get(k) for k in SLURM_ENV}
        rep["slurm_note"] = "scheduling reservation only; a step may inherit the job value"
    return rep


if __name__ == "__main__":
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and not sys.argv[1].isdigit()):
        sys.exit("usage: memory_limits.py [PID]")
    rep = report(sys.argv[1] if len(sys.argv) == 2 else "self")
    print(json.dumps(rep, indent=2))
    sys.exit(2 if "error" in rep else 0)
