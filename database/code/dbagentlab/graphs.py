"""Blocking graph helpers shared by evidence verification, not hidden task truth."""


def root_blockers(rows, requester):
    graph = {r['session_id']: list(r.get('blocking_session_ids', []))
             if r.get('wait_event_type')=='Lock' else [] for r in rows}
    if requester not in graph or not graph[requester]:
        return set()
    roots = set()
    def walk(node, path):
        if node in path or node not in graph:
            return False
        if not graph[node]:
            roots.add(node)
            return True
        return all(walk(parent, path | {node}) for parent in graph[node])
    return roots if walk(requester, set()) else set()
