"""Replay observer joins independently of pointer renaming.

This checks emitted associations, not unobserved native allocation lifetimes.
Its premises are a strictly ingested archive and the exact-image hook ABI.
No address is discarded, retired at a membership delta, or declared freed.
"""
from collections import Counter


def require(ok, message):
    if not ok:
        raise ValueError('association contract: ' + message)


class Associations:
    def __init__(self):
        self.scopes = {}
        self.active = {}
        self.counts = Counter()

    def scope(self, row):
        key = tuple(row[k] for k in ('capture', 'pid', 'tid', 'run', 'model_epoch'))
        return self.scopes.setdefault(key, dict(pos={}, addresses={}, nodes={}, snapshot=None,
                                               enqueues={}, referenced=set(), owners={}))

    def owner(self, row, state, thread):
        token = row['owner_reference_activation']
        manager = int(row['manager_address'], 16)
        require(row['native_lifetime_certified'] == '0', 'unjustified native lifetime claim')
        if token == '0':
            return False
        active = self.active.get((thread, token))
        require(active is not None and active['hook'] in ('block', 'obligation'),
                'owner token has no active manager-borrowing invocation')
        require(all(active[k] == row[k] for k in ('capture', 'pid', 'tid', 'run', 'model_epoch')),
                'owner token belongs to another run/epoch')
        prior = state['owners'].setdefault(token, manager)
        require(manager and prior == manager, 'manager changed within borrowed call interval')
        self.counts['qualified_owner_uses'] += 1
        return True

    def feed(self, row):
        phase = row['phase']
        if 'model_epoch' not in row:
            return
        state = self.scope(row)
        thread = tuple(row[k] for k in ('capture', 'pid', 'tid'))
        if phase == 'invocation_begin':
            key = thread, row['activation']
            require(key not in self.active, 'duplicate live activation')
            self.active[key] = row
        elif phase in ('invocation_return', 'invocation_abort'):
            key = thread, row['activation']
            prior = self.active.pop(key, None)
            require(prior is not None and prior['hook'] == row['hook'], 'unmatched invocation end')
            if phase == 'invocation_abort' and row['hook'] == 'queuepush':
                if state['enqueues'].pop(row['operation'], None) is not None:
                    self.counts['aborted_enqueues'] += 1
        elif phase in ('obligation', 'obligation_update', 'obligation_destroy'):
            ident, address = row['obligation_id'], row['native_address']
            require(ident != '0' and int(address, 16) != 0, 'null obligation identity')
            if phase == 'obligation':
                require(ident not in state['pos'] and address not in state['addresses'],
                        'duplicate observer PO or live address association')
                state['pos'][ident] = dict(row)
                state['addresses'][address] = ident
                self.counts['obligation_definitions'] += 1
            else:
                prior = state['pos'].get(ident)
                require(prior is not None and prior['native_address'] == address and
                        state['addresses'].get(address) == ident, 'wrong PO/address join')
                if phase == 'obligation_update':
                    require(row['previous_frame'] == prior['frame'], 'wrong prior PO frame')
                    state['pos'][ident] = dict(row)
                else:
                    del state['addresses'][address]
                    # Historical references stay legal; this is an observer fence.
                    state['pos'][ident] = dict(prior, retired=True)
                    self.counts['obligation_retirements'] += 1
            if phase != 'obligation_destroy' and row.get('parent_id') != '0':
                state['referenced'].add(row['parent_id'])
        elif phase == 'queues_begin':
            require(state['snapshot'] is None, 'overlapping queue snapshots')
            manager = int(row['manager_address'], 16)
            require(manager and int(row['short_queue_address'], 16) == manager + 48 and
                    int(row['long_queue_address'], 16) == manager + 112, 'wrong queue subobject join')
            self.owner(row, state, thread)
            state['snapshot'] = dict(header=row, nodes={}, counts=Counter(), ends=set(), removals=Counter())
        elif phase in ('queue_member', 'queue_end', 'queue_membership_remove', 'queues_end'):
            snap = state['snapshot']
            require(snap is not None and snap['header']['snapshot'] == row['snapshot'],
                    'record outside its queue snapshot')
            if phase == 'queue_member':
                queue, node, ident = row['queue'], row['list_node'], row['obligation_id']
                require(queue in ('short', 'long') and queue not in snap['ends'], 'invalid queue order')
                require(row['index'] == str(snap['counts'][queue]), 'missing or reordered occurrence')
                require(int(node, 16) != 0 and node not in snap['nodes'], 'duplicate/null physical node')
                require(ident in state['pos'] and not state['pos'][ident].get('retired'),
                        'queue occurrence has no current observer PO')
                snap['nodes'][node] = ident
                snap['counts'][queue] += 1
                self.counts['queue_occurrences'] += 1
            elif phase == 'queue_end':
                queue = row['queue']
                require(queue in ('short', 'long') and queue not in snap['ends'], 'duplicate queue end')
                count = snap['counts'][queue]
                require(row['complete'] == '1' and int(row['observed']) == count and
                        int(row['native_count']) == count and int(snap['header'][queue + '_queue']) == count,
                        'queue count disagreement')
                snap['ends'].add(queue)
            elif phase == 'queue_membership_remove':
                require(row['semantics'] == 'observed_membership_delta_not_discharge' and
                        all(row[k] == snap['header'][k] for k in ('cause', 'operation')),
                        'wrong delta provenance')
                snap['removals'][(row['list_node'], row['obligation_id'])] += 1
            else:
                require(row['complete'] == '1' and snap['ends'] == {'short', 'long'},
                        'incomplete queue snapshot')
                expected = Counter((node, ident) for node, ident in state['nodes'].items()
                                   if snap['nodes'].get(node) != ident)
                require(expected == snap['removals'], 'missing/extra/wrong membership delta')
                state['nodes'] = snap['nodes']
                state['snapshot'] = None
                self.counts['complete_queue_snapshots'] += 1
        elif phase == 'obligation_dequeue':
            node, ident = row['list_node'], row['obligation_id']
            require(state['nodes'].get(node) == ident and ident in state['pos'] and
                    not state['pos'][ident].get('retired'), 'wrong current unlink association')
            require(row['source'] == 'native_std_list_unhook' and row['discharge'] == 'not_implied',
                    'wrong unlink semantics')
            del state['nodes'][node]
            self.counts['qualified_unlinks'] += 1
        elif phase in ('obligation_enqueue_begin', 'obligation_enqueue_end'):
            qualified = self.owner(row, state, thread)
            require(row['owner_reference_scope'] == 'borrowed_call_interval', 'wrong owner scope')
            if qualified:
                role = row['queue_role']
                require(role in ('short', 'long') and int(row['queue_address'], 16) ==
                        int(row['manager_address'], 16) + (48 if role == 'short' else 112),
                        'wrong enqueue owner/role join')
            else:
                require(row['queue_role'] == 'unqualified' and row['manager_address'] == '0',
                        'unknown owner presented as qualified')
                self.counts['explicitly_unqualified_enqueues'] += 1
            ident, operation = row['obligation_id'], row['operation']
            require(ident == '0' or (ident in state['pos'] and not state['pos'][ident].get('retired')),
                    'enqueue has no current observer PO')
            fields = ('obligation_id', 'queue_address', 'manager_address', 'queue_role',
                      'owner_reference_activation', 'owner_reference_scope', 'native_lifetime_certified')
            if phase.endswith('_begin'):
                require(operation not in state['enqueues'], 'duplicate enqueue begin')
                state['enqueues'][operation] = row
            else:
                prior = state['enqueues'].pop(operation, None)
                require(prior is not None and all(prior[k] == row[k] for k in fields),
                        'enqueue association changed before return')
                require(prior['native_count'] == row['before'], 'enqueue before count changed')
                self.counts['paired_enqueues'] += 1

    def finish(self):
        require(not self.active, 'live invocation at end of complete archive')
        for state in self.scopes.values():
            require(state['snapshot'] is None and not state['enqueues'], 'open association at end')
            require(state['referenced'] <= state['pos'].keys(), 'undefined parent PO')
        return dict(status='PASS', scope='emitted observer associations only; native allocation lifetime NOT certified',
                    counts=dict(self.counts))
