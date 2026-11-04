"""Scoped observer graph comparison; never equality of physical histories.

PO address references follow the emitted observer identity/fence. Membership
references follow retained (node, PO) occurrences until a checked unlink/delta.
This does NOT turn either boundary into a native allocation-death certificate.
All other addresses retain the conservative worker-wide alias comparison.
Cross-category reuse needs an explicit end of the old observer reference;
overlapping or unfenced reuse fails closed. Reference end is not memory free.
The original unprojected archives and strict comparison remain authoritative.
"""
import re
from associations import Associations, require


class ObserverGraph:
    def __init__(self, pointer_fields):
        self.associations = Associations()
        self.pointer_fields = pointer_fields
        self.scopes = {}
        self.address_scopes = {}
        self.worker_threads = {}

    def end_reference(self, scope, state, address, category):
        require(state['categories'].get(address) == category, 'reference end has no matching category')
        del state['categories'][address]
        key = scope[:2], address
        live = self.address_scopes[key]
        require(live.get(scope) == category, 'reference end has no matching scope')
        del live[scope]
        if not live:
            del self.address_scopes[key]

    def feed(self, original):
        row = dict(original)
        if 'model_epoch' not in row:
            require(row['phase'] == 'collector_diagnostic', 'observer view requires a qualified epoch envelope')
            return row
        scope = tuple(row[k] for k in ('capture', 'pid', 'tid', 'run', 'model_epoch'))
        observed_thread = self.worker_threads.setdefault(scope[:2], scope[2])
        require(observed_thread == scope[2], 'cross-thread observation ordering is not qualified by this view')
        state = self.scopes.setdefault(scope, dict(nodes={}, incoming=None, next_node=0, categories={}))
        phase = row['phase']
        # Preserve aliases between overlapping observer references. Ending a
        # membership edge retires that graph reference only; it never certifies
        # allocation death or erases the retained raw address history.
        for field in self.pointer_fields & row.keys():
            address = row[field]
            require(re.fullmatch(r'0|[1-9a-f][0-9a-f]*', address), 'noncanonical address spelling')
            if address == '0':
                continue
            category = 'po' if field == 'native_address' else 'membership' if field == 'list_node' else 'other'
            if category == 'po':
                require(phase in ('obligation', 'obligation_update', 'obligation_destroy'),
                        'unqualified PO-address use')
            elif category == 'membership':
                require(phase in ('queue_member', 'queue_membership_remove', 'obligation_dequeue'),
                        'unqualified membership-address use')
            prior = state['categories'].setdefault(address, category)
            require(prior == category, 'cross-category address alias requires a qualified joint lifetime model')
            live = self.address_scopes.setdefault((scope[:2], address), {})
            require(all(other == scope or kind == category == 'other' for other, kind in live.items()),
                    'overlapping observer scopes require a qualified joint alias model')
            live[scope] = category
        if phase in ('obligation', 'obligation_update', 'obligation_destroy'):
            # The independent replay checks both directions of the actual
            # address/observer-ID association and its explicit retirement.
            row['native_address'] = 'observer-po:' + ':'.join(scope[2:]) + ':' + row['obligation_id']
        if phase == 'queues_begin':
            state['incoming'] = {}
        elif phase == 'queue_member':
            address, ident = row['list_node'], row['obligation_id']
            previous = state['nodes'].get(address)
            if previous is not None and previous[0] == ident:
                member = previous
            else:
                state['next_node'] += 1
                member = ident, 'observer-membership:' + ':'.join(scope[2:]) + ':' + str(state['next_node'])
            require(state['incoming'] is not None, 'membership has no open snapshot')
            state['incoming'][address] = member
            row['list_node'] = member[1]
        elif phase in ('queue_membership_remove', 'obligation_dequeue'):
            member = state['nodes'].get(row['list_node'])
            require(member is not None and member[0] == row['obligation_id'], 'unjoined historical membership')
            row['list_node'] = member[1]
            if phase == 'obligation_dequeue':
                del state['nodes'][original['list_node']]
        # Validate the original address-bearing event, never the projection.
        self.associations.feed(original)
        if phase == 'queues_end':
            for address in state['nodes'].keys() - state['incoming'].keys():
                self.end_reference(scope, state, address, 'membership')
            state['nodes'] = state['incoming']
            state['incoming'] = None
        elif phase == 'obligation_dequeue':
            self.end_reference(scope, state, original['list_node'], 'membership')
        elif phase == 'obligation_destroy':
            self.end_reference(scope, state, original['native_address'], 'po')
        if phase in ('run_seal', 'run_abort_seal'):
            # A closed observation interval becomes history, not freed storage.
            for key, live in list(self.address_scopes.items()):
                for other in list(live):
                    if other[:4] == scope[:4]:
                        del live[other]
                if not live:
                    del self.address_scopes[key]
        return row

    def finish(self):
        return self.associations.finish()


def project(rows, pointer_fields):
    graph = ObserverGraph(pointer_fields)
    result = [graph.feed(row) for row in rows]
    return result, graph.finish()
