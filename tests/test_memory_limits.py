import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import memory_limits as ml  # noqa: E402

LIMITS = """Limit                     Soft Limit           Hard Limit           Units
Max data size             unlimited            unlimited            bytes
Max resident set          34359738368          34359738368          bytes
Max address space         unlimited            unlimited            bytes
"""


class MemoryLimitsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "cg")
        self.proc = os.path.join(self.tmp.name, "proc")
        os.makedirs(os.path.join(self.proc, "7"))
        self._w(os.path.join(self.proc, "7", "cgroup"), "0::/job/step/task\n")
        self._w(os.path.join(self.proc, "7", "limits"), LIMITS)
        self._w(os.path.join(self.proc, "7", "status"), "VmRSS:\t 6767800 kB\nCpus_allowed_list:\t0-31\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _w(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def _cg(self, max_by_level):
        for rel, val in max_by_level.items():
            self._w(os.path.join(self.root, rel, "memory.max"), val)
            self._w(os.path.join(self.root, rel, "memory.high"), "max\n")

    def _rep(self):
        return ml.report(7, self.proc, self.root)

    def test_finite_parent_despite_leaf_max(self):
        self._cg({"job": "1073741824\n", "job/step": "max\n", "job/step/task": "max\n"})
        eff = self._rep()["cgroup"]["effective_memory.max"]
        self.assertEqual(eff, {"value": 1073741824, "chain_complete": True, "exact": True})

    def test_all_max_is_unlimited(self):
        self._cg({"job": "max\n", "job/step": "max\n", "job/step/task": "max\n"})
        cg = self._rep()["cgroup"]
        self.assertEqual(cg["effective_memory.max"]["value"], "unlimited")
        self.assertEqual(len(cg["chain"]), 3)

    def test_high_is_labelled_not_a_hard_cap(self):
        self.assertIn("NOT a hard cap", ml.NOTES["memory.high"])
        self.assertIn("hard limit", ml.NOTES["memory.max"])

    def test_invalid_or_missing_is_unknown_not_unlimited(self):
        self._cg({"job": "garbage\n", "job/step": "max\n", "job/step/task": "max\n"})
        eff = self._rep()["cgroup"]["effective_memory.max"]
        self.assertEqual((eff["value"], eff["known_upper_bound"]), ("unknown", None))
        os.remove(os.path.join(self.root, "job", "memory.max"))
        cg = self._rep()["cgroup"]
        self.assertEqual(cg["chain"][-1]["memory.max"], "missing")
        self.assertFalse(cg["effective_memory.max"]["chain_complete"])

    def test_finite_plus_unknown_is_only_upper_bound(self):
        self._cg({"job": "garbage\n", "job/step": "2147483648\n", "job/step/task": "max\n"})
        eff = self._rep()["cgroup"]["effective_memory.max"]
        self.assertEqual(eff, {"value": "unknown", "known_upper_bound": 2147483648,
                               "chain_complete": False, "exact": False})

    def test_permission_error_is_unknown(self):
        self._cg({"job": "max\n", "job/step": "max\n", "job/step/task": "max\n"})
        real_open = open

        def fake_open(path, *a, **k):
            if str(path).endswith(os.path.join("step", "memory.max")) or str(path).endswith("limits"):
                raise PermissionError(path)
            return real_open(path, *a, **k)
        with mock.patch("builtins.open", fake_open):
            rep = self._rep()
        self.assertEqual(rep["cgroup"]["chain"][1]["memory.max"], "unknown")
        self.assertEqual(rep["cgroup"]["effective_memory.max"]["value"], "unknown")
        self.assertEqual(rep["rlimits"]["rss"], "unknown")

    def test_missing_pid_is_error(self):
        self.assertIn("error", ml.report(99, self.proc, self.root))

    def test_foreign_owner_refused(self):
        rep = ml.report(7, self.proc, self.root, uid=os.getuid() + 1)
        self.assertIn("another user", rep["error"])
        self.assertNotIn("cgroup", rep)

    def test_dot_traversal_rejected(self):
        self._w(os.path.join(self.proc, "7", "cgroup"), "0::/../../etc\n")
        cg = self._rep()["cgroup"]
        self.assertEqual(cg["mode"], "UNSUPPORTED")
        self.assertNotIn("chain", cg)

    def test_malformed_short_rlimit_is_unknown(self):
        self._w(os.path.join(self.proc, "7", "limits"), "Max resident set   \nMax address space 5\n")
        rl = self._rep()["rlimits"]
        self.assertEqual((rl["rss"], rl["as"], rl["data"]), ("unknown",) * 3)

    def test_rss_rlimit_is_not_a_ram_cap(self):
        self._cg({"job": "max\n", "job/step": "max\n", "job/step/task": "max\n"})
        rep = self._rep()
        self.assertEqual(rep["rlimits"]["rss"]["hard"], "34359738368")
        self.assertIn("ignored", rep["notes"]["rss"])
        self.assertEqual(rep["cgroup"]["effective_memory.max"]["value"], "unlimited")
        self.assertEqual(rep["status"]["Cpus_allowed_list"], "0-31")

    def test_v1_unsupported(self):
        self._w(os.path.join(self.proc, "7", "cgroup"), "4:memory:/job\n0::/job\n")
        self.assertEqual(self._rep()["cgroup"]["mode"], "UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
