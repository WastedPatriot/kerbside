"""Directory objects kerbside understands.

Parsers fill a Directory. Later stages mark high-value principals and walk edges.
Nothing in here opens a socket.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def bare_name(value: str) -> str:
    """'Domain Admins@northsea.local' -> 'DOMAIN ADMINS'."""
    base = (value or "").split("@", 1)[0]
    if base.endswith("$"):
        base = base[:-1]
    return base.strip().upper()


@dataclass
class Principal:
    object_id: str
    name: str
    kind: str
    domain: str = ""
    sam_account_name: str = ""
    enabled: bool = True
    high_value: bool = False
    is_dc: bool = False
    dont_req_preauth: bool = False
    has_spn: bool = False
    spns: list[str] = field(default_factory=list)
    unconstrained_delegation: bool = False
    trusted_to_auth: bool = False
    allowed_to_delegate: list[str] = field(default_factory=list)
    password_not_required: bool = False
    password_never_expires: bool = False
    admin_count: bool = False
    description: str = ""
    primary_group_sid: str = ""
    privileged_via: list[str] = field(default_factory=list)

    @property
    def display(self) -> str:
        if self.kind == "domain":
            return (self.domain or self.name).lower()
        if self.kind == "computer":
            return self.name.lower()
        if self.sam_account_name:
            if self.domain:
                return f"{self.sam_account_name}@{self.domain.lower()}"
            return self.sam_account_name
        return self.name

    def merge(self, other: Principal) -> None:
        """Fold a second sighting of the same object into this one."""
        if not self.name or self.name == self.object_id:
            self.name = other.name or self.name
        if not self.sam_account_name:
            self.sam_account_name = other.sam_account_name
        if not self.domain:
            self.domain = other.domain
        if not self.description:
            self.description = other.description
        if not self.primary_group_sid:
            self.primary_group_sid = other.primary_group_sid
        if other.kind and self.kind in {"object", "unknown"}:
            self.kind = other.kind
        self.enabled = self.enabled and other.enabled
        self.high_value = self.high_value or other.high_value
        self.is_dc = self.is_dc or other.is_dc
        self.dont_req_preauth = self.dont_req_preauth or other.dont_req_preauth
        self.has_spn = self.has_spn or other.has_spn
        self.unconstrained_delegation = (
            self.unconstrained_delegation or other.unconstrained_delegation
        )
        self.trusted_to_auth = self.trusted_to_auth or other.trusted_to_auth
        self.password_not_required = self.password_not_required or other.password_not_required
        self.password_never_expires = self.password_never_expires or other.password_never_expires
        self.admin_count = self.admin_count or other.admin_count
        for spn in other.spns:
            if spn not in self.spns:
                self.spns.append(spn)
        for token in other.allowed_to_delegate:
            if token not in self.allowed_to_delegate:
                self.allowed_to_delegate.append(token)


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: str
    inherited: bool = False


class Directory:
    """Principals and the edges between them, plus grumbles from the parser."""

    def __init__(self, source: str = "") -> None:
        self.source = source
        self.principals: dict[str, Principal] = {}
        self.edges: list[Edge] = []
        self.warnings: list[str] = []
        self._edge_index: dict[tuple[str, str, str], int] = {}

    def add_principal(self, principal: Principal) -> Principal:
        existing = self.principals.get(principal.object_id)
        if existing is None:
            self.principals[principal.object_id] = principal
            return principal
        existing.merge(principal)
        return existing

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        *,
        inherited: bool = False,
    ) -> None:
        if not source or not target or source == target or not relation:
            return
        key = (source, relation, target)
        current = self._edge_index.get(key)
        edge = Edge(source, target, relation, inherited)
        if current is None:
            self._edge_index[key] = len(self.edges)
            self.edges.append(edge)
            return
        # An explicit ACE is more interesting than the inherited copy.
        if self.edges[current].inherited and not inherited:
            self.edges[current] = edge

    def label(self, object_id: str) -> str:
        principal = self.principals.get(object_id)
        if principal is not None:
            return principal.display
        known = _WELL_KNOWN_SIDS.get(object_id.upper())
        if known:
            return known
        return object_id

    def kinds(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for principal in self.principals.values():
            counts[principal.kind] = counts.get(principal.kind, 0) + 1
        return dict(sorted(counts.items()))


# SIDs we may see on an ACE without a full object in the export.
_WELL_KNOWN_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
}
