"""Small helpers shared by the BloodHound, LDIF, and CSV parsers."""

from __future__ import annotations

from kerbside.models import Directory


def build_index(directory: Directory) -> dict[str, str]:
    """Map the names an export might use onto object ids."""
    index: dict[str, str] = {}
    for principal in directory.principals.values():
        index[principal.object_id.lower()] = principal.object_id
        if principal.name:
            index[principal.name.lower()] = principal.object_id
        if principal.sam_account_name:
            sam = principal.sam_account_name.lower()
            index[sam] = principal.object_id
            if sam.endswith("$"):
                index[sam[:-1]] = principal.object_id
            if principal.domain:
                index[f"{sam}@{principal.domain.lower()}"] = principal.object_id
        if principal.kind == "computer" and principal.name:
            index[principal.name.split(".")[0].lower()] = principal.object_id
    return index


def resolve_token(token: str, index: dict[str, str]) -> str | None:
    """Turn a SID, a name, or an SPN into an object id when we can."""
    text = token.strip()
    if not text:
        return None
    if text.upper().startswith("S-1-"):
        return index.get(text.lower(), text)
    direct = index.get(text.lower())
    if direct:
        return direct
    host = text
    if "/" in host:
        host = host.split("/", 1)[1]
    host = host.split(":", 1)[0].split("\\")[-1]
    found = index.get(host.lower())
    if found:
        return found
    short = host.split(".")[0].lower()
    return index.get(short)


def add_resolved_edges(
    directory: Directory,
    pending: list[tuple[str, str, str]],
) -> None:
    """pending entries are (source id, relation, token)."""
    if not pending:
        return
    index = build_index(directory)
    for source, relation, token in pending:
        target = resolve_token(token, index)
        if not target:
            directory.warnings.append(
                f"Could not resolve {relation} target {token!r} from {source}"
            )
            continue
        directory.add_edge(source, target, relation)


def remember_delegate(directory: Directory, source: str, token: str) -> None:
    principal = directory.principals.get(source)
    if principal is None:
        return
    if token not in principal.allowed_to_delegate:
        principal.allowed_to_delegate.append(token)

