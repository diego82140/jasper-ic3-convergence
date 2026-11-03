"""A scoped graph must reject wrong joins without equating allocator history."""
import copy, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'source/tests/parity'))
import cross_release as parity
import observer_equivalence as view
import test_association_contract as fixtures


class ObserverEquivalence(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AssociationContract()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.profile = Path(self.directory.name) / 'profile.events'
        self.profile.write_text('')

    def normalize(self, rows, semantic):
        numbered = [dict(row, event=str(i)) for i, row in enumerate(rows, 1)]
        if semantic:
            numbered, result = view.project(numbered, parity.POINTERS)
            self.assertEqual(result['status'], 'PASS')
        return parity.normalize(('IC3_STATS ' + ' '.join(k+'='+v for k, v in row.items())+'\n'
                                 for row in numbered), self.profile)

    def complete(self, rows):
        return rows + [self.fixture.row('invocation_return', activation=7, hook='block')]

    def test_reuse_after_observer_fences_is_not_raw_history_equality(self):
        f = self.fixture
        rows = f.base() + f.snapshot(1, [('a', 1)]) + f.snapshot(2, [], [('a', 1)])
        rows += [f.row('obligation_destroy', obligation_id=1, native_address='aaa'), f.po(2, 'bbb')]
        rows += f.snapshot(3, [('b', 2)]) + f.snapshot(4, [], [('b', 2)])
        rows = self.complete(rows)
        recycled = copy.deepcopy(rows)
        for row in recycled:
            if row.get('list_node') == 'b':
                row['list_node'] = 'a'
            if row.get('native_address') == 'bbb':
                row['native_address'] = 'aaa'
        self.assertFalse(parity.comparison(self.normalize(rows, False), self.normalize(recycled, False))['pass_'])
        self.assertTrue(parity.comparison(self.normalize(rows, True), self.normalize(recycled, True))['pass_'])

    def test_distinct_memberships_for_one_po_keep_order_and_identity(self):
        f = self.fixture
        rows = self.complete(f.base() + f.snapshot(1, [('a', 1), ('b', 1)]) +
                             f.snapshot(2, [('a', 1), ('b', 1)]))
        swapped = copy.deepcopy(rows)
        for row in swapped:
            if row['phase'] == 'queue_member' and row['snapshot'] == '2':
                row['list_node'] = 'b' if row['list_node'] == 'a' else 'a'
        self.assertFalse(parity.comparison(self.normalize(rows, True), self.normalize(swapped, True))['pass_'])
        projected, _ = view.project(rows, parity.POINTERS)
        nodes = [r['list_node'] for r in projected if r['phase'] == 'queue_member' and r['snapshot'] == '1']
        self.assertEqual(len(set(nodes)), 2)

    def test_fields_and_changed_payloads_are_not_removed(self):
        f = self.fixture
        rows = self.complete(f.base() + f.snapshot(1, [('a', 1)]))
        projected, _ = view.project(rows, parity.POINTERS)
        self.assertEqual([set(r) for r in rows], [set(r) for r in projected])
        for field in ('frame', 'extra_payload'):
            changed = copy.deepcopy(rows)
            changed[1][field] = 'DELIBERATE_MUTATION'
            self.assertFalse(parity.comparison(self.normalize(rows, True), self.normalize(changed, True))['pass_'])

    def test_unsupported_aliases_and_address_uses_fail_closed(self):
        f = self.fixture
        bad_cases = [f.base() + f.snapshot(1, [('aaa', 1)]),
                     f.base() + [dict(f.po(2, 'aaa'), run='2')],
                     f.base() + [f.row('unqualified', list_node='a')],
                     f.base() + [f.row('unqualified', native_address='aaa')],
                     f.base() + [f.row('unqualified', seq='0aaa')]]
        for rows in bad_cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.normalize(self.complete(rows), True)

    def test_wrong_member_join_cannot_be_relabelled_away(self):
        f = self.fixture
        rows = f.base() + f.snapshot(1, [('a', 1)])
        rows += [f.row('obligation_dequeue', list_node='a', obligation_id=2,
                       source='native_std_list_unhook', discharge='not_implied')]
        with self.assertRaises(ValueError):
            self.normalize(self.complete(rows), True)

    def test_cross_category_handoff_needs_an_explicit_reference_end(self):
        f = self.fixture
        prefix = f.base() + f.snapshot(1, [('a', 1)])
        with self.assertRaises(ValueError):
            self.normalize(self.complete(prefix + [f.po(2, 'a')]), True)
        ended = prefix + f.snapshot(2, [], [('a', 1)]) + [f.po(2, 'a')]
        # It is now another observer reference, with all raw values retained
        # in the source archive; no assertion about allocation death is made.
        self.normalize(self.complete(ended), True)

    def test_missing_epoch_cannot_silently_select_an_unqualified_view(self):
        rows = self.complete(self.fixture.base())
        del rows[1]['model_epoch']
        with self.assertRaisesRegex(ValueError, 'qualified epoch'):
            self.normalize(rows, True)

    def test_thread_local_archives_do_not_invent_global_overlap_order(self):
        f = self.fixture
        first = self.complete(f.base() + f.snapshot(1, [('a', 1)]))
        second = copy.deepcopy(first)
        for row in second:
            row['tid'] = '2'
            if 'native_address' in row:
                row['native_address'] = 'ccc'
            if 'list_node' in row:
                row['list_node'] = 'b'
        with self.assertRaisesRegex(ValueError, 'cross-thread'):
            self.normalize(first + second, True)


if __name__ == '__main__':
    unittest.main()
