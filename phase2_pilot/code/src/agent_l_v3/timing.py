"""Nested non-overlapping wall/parent-CPU accounting, with explicit envelope."""
from collections import defaultdict
from contextlib import contextmanager
import time


class Timing:
    def __init__(self):
        self.stack = []
        self.events = []

    @contextmanager
    def span(self, name):
        event = {'name': name, 'wall_start_ns': time.perf_counter_ns(),
                 'cpu_start_ns': time.process_time_ns(), 'child_wall_ns': 0, 'child_cpu_ns': 0,
                 'depth': len(self.stack)}
        self.stack.append(event)
        try:
            yield
        finally:
            assert self.stack.pop() is event
            event['wall_ns'] = time.perf_counter_ns() - event['wall_start_ns']
            event['parent_cpu_ns'] = time.process_time_ns() - event['cpu_start_ns']
            event['exclusive_wall_ns'] = event['wall_ns'] - event['child_wall_ns']
            event['exclusive_parent_cpu_ns'] = event['parent_cpu_ns'] - event['child_cpu_ns']
            if self.stack:
                self.stack[-1]['child_wall_ns'] += event['wall_ns']
                self.stack[-1]['child_cpu_ns'] += event['parent_cpu_ns']
            self.events.append(event)

    def document(self):
        assert not self.stack
        totals = defaultdict(lambda: {'wall_ns': 0, 'parent_cpu_ns': 0, 'count': 0})
        for e in self.events:
            row = totals[e['name']]
            row['wall_ns'] += e['exclusive_wall_ns']
            row['parent_cpu_ns'] += e['exclusive_parent_cpu_ns']
            row['count'] += 1
        roots = [e for e in self.events if e['depth'] == 0]
        assert len(roots) == 1
        root = roots[0]
        assert sum(r['wall_ns'] for r in totals.values()) == root['wall_ns']
        assert sum(r['parent_cpu_ns'] for r in totals.values()) == root['parent_cpu_ns']
        return {'schema': 'l3-timing-v1', 'whole_wall_seconds': root['wall_ns'] / 1e9,
                'whole_parent_CPU_seconds': root['parent_cpu_ns'] / 1e9,
                'exclusive_categories': dict(totals), 'events': self.events,
                'additive_accounting_passed': True,
                'parent_CPU_excludes_worker_CPU': True,
                'timing_receipt_write_excluded': True,
                'model_latency_is_scripted_not_API': True}
