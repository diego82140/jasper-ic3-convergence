"""Adversarial observer-join examples independent of the producer helpers."""
import copy, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'source/tests/parity'))
from associations import Associations


class AssociationContract(unittest.TestCase):
    def row(self, phase, **fields):
        return dict(capture='c', pid='1', tid='1', run='1', model_epoch='1', phase=phase,
                    **{k: str(v) for k, v in fields.items()})

    def po(self, ident=1, address='aaa', **fields):
        return self.row('obligation', obligation_id=ident, native_address=address,
                        parent_id=0, frame=2, **fields)

    def snapshot(self, number, members, removals=()):
        rows = [self.row('queues_begin', snapshot=number, manager_address='1000',
                        short_queue_address='1030', long_queue_address='1070',
                        owner_reference_activation=7, native_lifetime_certified=0,
                        short_queue=len(members), long_queue=0, cause='fixture', operation=8)]
        rows += [self.row('queue_member', snapshot=number, queue='short', index=i,
                          obligation_id=ident, list_node=node) for i, (node, ident) in enumerate(members)]
        rows += [self.row('queue_end', snapshot=number, queue=queue, observed=count,
                          native_count=count, complete=1) for queue, count in (('short', len(members)), ('long', 0))]
        rows += [self.row('queue_membership_remove', snapshot=number, list_node=node,
                          obligation_id=ident, cause='fixture', operation=8,
                          semantics='observed_membership_delta_not_discharge') for node, ident in removals]
        rows.append(self.row('queues_end', snapshot=number, complete=1))
        return rows

    def base(self):
        return [self.row('invocation_begin', activation=7, hook='block'), self.po()]

    def check(self, rows):
        check = Associations()
        for row in rows:
            check.feed(row)
        check.feed(self.row('invocation_return', activation=7, hook='block'))
        return check.finish()

    def test_distinct_nodes_one_po_and_exact_delta_are_preserved(self):
        rows = self.base() + self.snapshot(1, [('a', 1), ('b', 1)])
        rows += self.snapshot(2, [('b', 1)], [('a', 1)])
        result = self.check(rows)
        self.assertEqual(result['counts']['queue_occurrences'], 3)
        self.assertEqual(result['counts']['complete_queue_snapshots'], 2)
        for mutation in ([], [('b', 1)], [('a', 1), ('a', 1)]):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(self.base() + self.snapshot(1, [('a', 1), ('b', 1)]) +
                           self.snapshot(2, [('b', 1)], mutation))

    def test_duplicate_physical_nodes_and_count_mismatch_fail(self):
        with self.assertRaises(ValueError):
            self.check(self.base() + self.snapshot(1, [('a', 1), ('a', 1)]))
        rows = self.base() + self.snapshot(1, [('a', 1)])
        next(r for r in rows if r['phase'] == 'queue_end')['observed'] = '2'
        with self.assertRaises(ValueError):
            self.check(rows)

    def test_recycled_address_needs_observer_fence(self):
        rows = self.base()
        with self.assertRaises(ValueError):
            self.check(rows + [self.po(2)])
        rows += [self.row('obligation_destroy', obligation_id=1, native_address='aaa'), self.po(2)]
        self.assertEqual(self.check(rows)['counts']['obligation_definitions'], 2)
        rows[-2]['native_address'] = 'bbb'
        with self.assertRaises(ValueError):
            self.check(rows)

    def test_unlink_requires_current_cached_association(self):
        rows = self.base() + self.snapshot(1, [('a', 1)])
        unlink = self.row('obligation_dequeue', list_node='a', obligation_id=1,
                          source='native_std_list_unhook', discharge='not_implied')
        self.assertEqual(self.check(rows + [unlink])['counts']['qualified_unlinks'], 1)
        for field, value in (('list_node', 'b'), ('obligation_id', '2'), ('discharge', 'implied')):
            bad = dict(unlink, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(rows + [bad])

    def test_borrowed_owner_is_active_correct_and_stable(self):
        fields = dict(operation=8, obligation_id=1, queue_address='1030', manager_address='1000',
                      queue_role='short', owner_reference_activation=7,
                      owner_reference_scope='borrowed_call_interval', native_lifetime_certified=0)
        begin = self.row('obligation_enqueue_begin', native_count=0, **fields)
        end = self.row('obligation_enqueue_end', before=0, after=1, **fields)
        self.assertEqual(self.check(self.base() + [begin, end])['counts']['paired_enqueues'], 1)
        for field, value in (('owner_reference_activation', '99'), ('queue_role', 'long'),
                             ('manager_address', '2000'), ('queue_address', '1031')):
            bad = dict(end, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(self.base() + [begin, bad])
        # Unknown is retained as unknown; it never certifies a native lifetime.
        fields.update(manager_address='0', queue_role='unqualified', owner_reference_activation=0)
        result = self.check(self.base() + [self.row('obligation_enqueue_begin', native_count=0, **fields),
                                         self.row('obligation_enqueue_end', before=0, after=1, **fields)])
        self.assertEqual(result['counts']['explicitly_unqualified_enqueues'], 2)

    def test_wrong_owner_epoch_and_queue_subobject_fail(self):
        rows = self.base() + self.snapshot(1, [])
        for field, value in (('model_epoch', '2'), ('short_queue_address', '1070'),
                             ('native_lifetime_certified', '1')):
            changed = copy.deepcopy(rows)
            next(r for r in changed if r['phase'] == 'queues_begin')[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(changed)

    def test_aborted_enqueue_never_infers_a_native_return(self):
        fields = dict(operation=8, obligation_id=1, queue_address='1030', manager_address='1000',
                      queue_role='short', owner_reference_activation=7,
                      owner_reference_scope='borrowed_call_interval', native_lifetime_certified=0)
        rows = self.base() + [self.row('invocation_begin', activation=8, hook='queuepush', operation=8),
                             self.row('obligation_enqueue_begin', native_count=0, **fields),
                             self.row('invocation_abort', activation=8, hook='queuepush', operation=8)]
        result = self.check(rows)
        self.assertEqual(result['counts']['aborted_enqueues'], 1)
        self.assertNotIn('paired_enqueues', result['counts'])
        with self.assertRaises(ValueError):
            self.check(rows + [self.row('obligation_enqueue_end', before=0, after=1, **fields)])


if __name__ == '__main__':
    unittest.main()
