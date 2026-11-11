"""Shortest paths to high-value principals.

A path is a chain of rights and memberships already present in the export.
It is not a list of commands. High-value means domain admins and the other
groups that end an engagement, plus the domain object (replication rights)
and domain controllers.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from kerbside.models import Directory, Principal, bare_name

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Group names, compared after bare_name(). RID hints cover renamed groups.
_CRITICAL_GROUPS = frozenset(
    {
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "SCHEMA ADMINS",
        "ADMINISTRATORS",
    }
)
_HIGH_GROUPS = frozenset(
    {
        "BACKUP OPERATORS",
        "ACCOUNT OPERATORS",
        "SERVER OPERATORS",
        "PRINT OPERATORS",
        "DNSADMINS",
        "DNS ADMINS",
        "KEY ADMINS",
        "ENTERPRISE KEY ADMINS",
    }
)
_HV_GROUPS = _CRITICAL_GROUPS | _HIGH_GROUPS

_EXPLICIT_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
}
_DOMAIN_RIDS = {
    "512": "Domain Admins",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
}

_WELL_KNOWN_SIDS = {"S-1-1-0", "S-1-5-7", "S-1-5-11"}
_WELL_KNOWN_NAMES = {"EVERYONE", "AUTHENTICATED USERS", "ANONYMOUS", "ANONYMOUS LOGON"}


@dataclass
class AttackPath:
    nodes: list[str]
    relations: list[str]
    target_id: str
    also: list[str] = field(default_factory=list)
    severity: str = "medium"

    @property
    def length(self) -> int:
        return len(self.relations)


def prepare_directory(directory: Directory) -> None:
    """Mark domain controllers and anyone who sits in a high-value group."""
    mark_domain_controllers(directory)
    mark_privileged(directory)


def find_paths(
    directory: Directory,
    *,
    max_depth: int = 6,
    limit: int = 25,
    start_contains: str | None = None,
) -> list[AttackPath]:
    """Shortest route from each interesting principal to each high-value target.

    Paths that share a tail are collapsed: the first principal is the example,
    the rest are listed on ``also``. Calling this marks privileged objects.
    """
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    if limit < 1:
        raise ValueError("limit must be at least 1")

    prepare_directory(directory)
    targets = [p.object_id for p in directory.principals.values() if p.high_value]
    if not targets:
        return []

    reverse: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in directory.edges:
        reverse[edge.target].append((edge.source, edge.relation))
    for bucket in reverse.values():
        # Prefer a control edge over membership when both link the same pair.
        bucket.sort(key=lambda item: (item[1] == "MemberOf", item[1], item[0]))

    raw: list[AttackPath] = []
    for target in targets:
        raw.extend(_paths_to(directory, reverse, target, max_depth))

    merged = _collapse(directory, raw)
    needle = start_contains.lower().strip() if start_contains else ""
    if needle:
        merged = [_promote_match(directory, path, needle) for path in merged]
        merged = [path for path in merged if path is not None]
    merged.sort(
        key=lambda path: (
            SEVERITY_RANK.get(path.severity, 9),
            path.length,
            directory.label(path.nodes[0]).lower(),
        )
    )
    return merged[:limit]


def mark_domain_controllers(directory: Directory) -> None:
    groups = [
        principal.object_id
        for principal in directory.principals.values()
        if principal.kind == "group" and _names(principal) & {"DOMAIN CONTROLLERS"}
    ]
    if not groups:
        return
    wanted = set(groups)
    for edge in directory.edges:
        if edge.relation != "MemberOf" or edge.target not in wanted:
            continue
        member = directory.principals.get(edge.source)
        if member is not None and member.kind == "computer":
            member.is_dc = True


def mark_privileged(directory: Directory) -> None:
    reasons: dict[str, list[str]] = defaultdict(list)
    for principal in directory.principals.values():
        for reason in _root_reasons(principal):
            _add_reason(reasons, principal.object_id, reason)
            principal.high_value = True

    members: dict[str, list[str]] = defaultdict(list)
    for edge in directory.edges:
        if edge.relation == "MemberOf":
            members[edge.target].append(edge.source)

    queue: deque[str] = deque(oid for oid, found in reasons.items() if found)
    visited = set(queue)
    while queue:
        current = queue.popleft()
        for member_id in members.get(current, []):
            added = False
            for reason in reasons[current]:
                if _add_reason(reasons, member_id, reason):
                    added = True
            member = directory.principals.get(member_id)
            if member is not None:
                member.high_value = True
            if member_id not in visited:
                visited.add(member_id)
                queue.append(member_id)
            elif added:
                queue.append(member_id)

    for principal in directory.principals.values():
        found = list(reasons.get(principal.object_id, []))
        if principal.high_value and not found:
            found = ["marked high value"]
        principal.privileged_via = found


def rid_hint(object_id: str) -> str | None:
    """English name for a well-known group SID, so a renamed group still counts."""
    sid = object_id.upper()
    explicit = _EXPLICIT_SIDS.get(sid)
    if explicit:
        return explicit
    parts = sid.split("-")
    if len(parts) == 8 and parts[:4] == ["S", "1", "5", "21"]:
        return _DOMAIN_RIDS.get(parts[-1])
    return None


def _paths_to(
    directory: Directory,
    reverse: dict[str, list[tuple[str, str]]],
    target: str,
    max_depth: int,
) -> list[AttackPath]:
    parent: dict[str, tuple[str, str]] = {}
    depth = {target: 0}
    seen = {target}
    queue: deque[str] = deque([target])
    while queue:
        current = queue.popleft()
        if depth[current] >= max_depth:
            continue
        if current != target:
            principal = directory.principals.get(current)
            if principal is not None and principal.high_value:
                continue
        for source, relation in reverse.get(current, []):
            if source in seen or source == target:
                continue
            seen.add(source)
            depth[source] = depth[current] + 1
            parent[source] = (current, relation)
            if _is_well_known(directory, source):
                continue
            queue.append(source)

    found: list[AttackPath] = []
    for source in parent:
        if not _is_source(directory, source):
            continue
        nodes = [source]
        relations: list[str] = []
        cursor = source
        ok = True
        for _ in range(max_depth + 1):
            if cursor == target:
                break
            step = parent.get(cursor)
            if step is None:
                ok = False
                break
            nxt, relation = step
            relations.append(relation)
            nodes.append(nxt)
            cursor = nxt
        else:
            ok = cursor == target
        if ok and cursor == target and relations:
            found.append(AttackPath(nodes=nodes, relations=relations, target_id=target))
    return found


def _collapse(directory: Directory, paths: list[AttackPath]) -> list[AttackPath]:
    groups: dict[tuple, list[AttackPath]] = {}
    order: list[tuple] = []
    for path in paths:
        key = (tuple(path.nodes[1:]), tuple(path.relations))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(path)

    merged: list[AttackPath] = []
    for key in order:
        bundle = groups[key]
        bundle.sort(key=lambda path: directory.label(path.nodes[0]).lower())
        primary = bundle[0]
        primary.also = [path.nodes[0] for path in bundle[1:]]
        target = directory.principals.get(primary.target_id)
        primary.severity = _path_severity(target) if target is not None else "medium"
        merged.append(primary)
    return merged


def _promote_match(directory: Directory, path: AttackPath, needle: str) -> AttackPath | None:
    """Keep a collapsed path if the example or anyone sharing it matches."""
    labels = [directory.label(path.nodes[0])]
    labels.extend(directory.label(item) for item in path.also)
    if not any(needle in label.lower() for label in labels):
        return None
    if needle in labels[0].lower():
        return path
    for index, object_id in enumerate(path.also):
        if needle in directory.label(object_id).lower():
            path.also[index] = path.nodes[0]
            path.nodes = [object_id, *path.nodes[1:]]
            path.also.sort(key=lambda item: directory.label(item).lower())
            return path
    return path


def _path_severity(target: Principal) -> str:
    if target.kind == "domain" or target.is_dc:
        return "critical"
    markers = {bare_name(item) for item in target.privileged_via}
    markers.add(bare_name(target.name))
    if target.sam_account_name:
        markers.add(bare_name(target.sam_account_name))
    if markers & _CRITICAL_GROUPS or "DOMAIN OBJECT" in markers or "DOMAIN CONTROLLER" in markers:
        return "critical"
    if markers & _HIGH_GROUPS or target.high_value:
        return "high"
    return "medium"


def _root_reasons(principal: Principal) -> list[str]:
    reasons: list[str] = []
    if principal.kind == "domain":
        reasons.append("domain object")
    if principal.is_dc:
        reasons.append("domain controller")
    group_reason = _group_reason(principal)
    if group_reason and group_reason not in reasons:
        reasons.append(group_reason)
    return reasons


def _group_reason(principal: Principal) -> str | None:
    if principal.kind != "group":
        return None
    hint = rid_hint(principal.object_id)
    if _names(principal) & _HV_GROUPS:
        return principal.display
    if hint and bare_name(hint) in _HV_GROUPS:
        return hint
    if principal.high_value:
        return principal.display
    return None


def _names(principal: Principal) -> set[str]:
    found = {bare_name(principal.name)}
    if principal.sam_account_name:
        found.add(bare_name(principal.sam_account_name))
    hint = rid_hint(principal.object_id)
    if hint:
        found.add(bare_name(hint))
    return {name for name in found if name}


def _add_reason(reasons: dict[str, list[str]], object_id: str, reason: str) -> bool:
    if not reason or reason in reasons[object_id]:
        return False
    reasons[object_id].append(reason)
    return True


def _is_well_known(directory: Directory, object_id: str) -> bool:
    if object_id.upper() in _WELL_KNOWN_SIDS:
        return True
    principal = directory.principals.get(object_id)
    if principal is None:
        return False
    return bool(_names(principal) & _WELL_KNOWN_NAMES)


def _is_source(directory: Directory, object_id: str) -> bool:
    if _is_well_known(directory, object_id):
        principal = directory.principals.get(object_id)
        return principal is None or not principal.high_value
    principal = directory.principals.get(object_id)
    if principal is None:
        return False
    if not principal.enabled or principal.high_value:
        return False
    if principal.kind == "user":
        return True
    # A computer is a start only when it holds a right of its own.
    # Hosting a logon session is not the same thing as attacking from it.
    if principal.kind == "computer":
        return any(
            edge.source == object_id and edge.relation not in {"HasSession", "MemberOf"}
            for edge in directory.edges
        )
    return False
