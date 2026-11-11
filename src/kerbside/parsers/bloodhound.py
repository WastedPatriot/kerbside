"""SharpHound / BloodHound JSON collections.

Accepts a single file or a directory of them. meta.type says what is inside.
Older files that are a bare list are accepted when the filename gives it away.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from kerbside.models import Directory, Principal
from kerbside.parsers.common import add_resolved_edges, remember_delegate

# Rights that change who can reach whom. The rest (GenericRead and friends)
# are recorded by BloodHound and ignored here on purpose.
_ACTIONABLE = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "ForceChangePassword",
        "AddMember",
        "AllExtendedRights",
        "ReadLAPSPassword",
        "WriteSPN",
        "AddKeyCredentialLink",
        "AddSelf",
        "ReadGMSAPassword",
        "SQLAdmin",
    }
)

_KIND_BY_META = {
    "users": "user",
    "groups": "group",
    "computers": "computer",
    "domains": "domain",
    "gpos": "gpo",
    "ous": "ou",
    "containers": "container",
}

_LOCAL_GROUPS = {
    "LocalAdmins": "AdminTo",
    "RemoteDesktopUsers": "CanRDP",
    "DcomUsers": "ExecuteDCOM",
    "PSRemoteUsers": "CanPSRemote",
}


def load_bloodhound(path: Path) -> Directory:
    directory = Directory(source=str(path))
    files = _json_files(path)
    if not files:
        directory.warnings.append(f"No JSON files in {path}")
        return directory

    pending: list[tuple[str, str, str]] = []
    for file in files:
        try:
            payload = json.loads(file.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            directory.warnings.append(f"{file.name}: not JSON ({exc.lineno}:{exc.colno})")
            continue
        kind, rows = _unwrap(payload, file)
        if kind is None:
            directory.warnings.append(f"{file.name}: not a BloodHound collection, skipped")
            continue
        for row in rows:
            if isinstance(row, dict):
                _ingest(directory, row, kind, pending)

    _membership_from_primary_groups(directory)
    add_resolved_edges(directory, pending)
    return directory


def _json_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*.json") if p.is_file())


def _unwrap(payload: Any, file: Path) -> tuple[str | None, list[Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        meta = payload.get("meta") or {}
        kind = _KIND_BY_META.get(str(meta.get("type", "")).lower())
        if kind is None:
            kind = _kind_from_name(file.name)
        return kind, payload["data"]
    if isinstance(payload, list):
        return _kind_from_name(file.name), payload
    return None, []


def _kind_from_name(name: str) -> str | None:
    lowered = name.lower()
    for key, kind in _KIND_BY_META.items():
        if key in lowered:
            return kind
    return None


def _ingest(
    directory: Directory,
    row: dict[str, Any],
    kind: str,
    pending: list[tuple[str, str, str]],
) -> None:
    object_id = str(row.get("ObjectIdentifier") or "").strip()
    if not object_id:
        directory.warnings.append("Skipped an object with no ObjectIdentifier")
        return
    props = row.get("Properties") or {}
    if not isinstance(props, dict):
        props = {}

    domain = str(props.get("domain") or "").lower()
    sam = str(props.get("samaccountname") or "")
    name = str(props.get("name") or sam or object_id)
    spns = [str(item) for item in (props.get("serviceprincipalnames") or []) if item]
    primary = str(row.get("PrimaryGroupSID") or props.get("primarygroupsid") or "")
    enabled = _enabled(props, kind)

    principal = Principal(
        object_id=object_id,
        name=name,
        kind=kind,
        domain=domain,
        sam_account_name=sam,
        enabled=enabled,
        high_value=bool(props.get("highvalue")),
        is_dc=_primary_is_dc(primary),
        dont_req_preauth=bool(props.get("dontreqpreauth")),
        has_spn=bool(props.get("hasspn")) or bool(spns),
        spns=spns,
        unconstrained_delegation=bool(props.get("unconstraineddelegation")),
        trusted_to_auth=bool(props.get("trustedtoauth")),
        password_not_required=_truthy_prop(
            props, "passwordnotreqd", "pwdnotreqd", "passwdnotreqd"
        ),
        password_never_expires=bool(props.get("pwdneverexpires")),
        admin_count=bool(props.get("admincount")),
        description=_text(props.get("description")),
        primary_group_sid=primary,
    )
    directory.add_principal(principal)

    if kind == "group":
        for member in row.get("Members") or []:
            member_id = _object_id(member)
            if member_id:
                directory.add_edge(member_id, object_id, "MemberOf")

    _aces(directory, object_id, row.get("Aces") or [])

    if kind == "computer":
        _sessions(directory, object_id, row.get("Sessions"))
        _sessions(directory, object_id, row.get("PrivilegedSessions"))
        for block_name, relation in _LOCAL_GROUPS.items():
            _local_group(directory, object_id, row.get(block_name), relation)
        for entry in row.get("AllowedToAct") or []:
            actor = _object_id(entry)
            if actor:
                directory.add_edge(actor, object_id, "AllowedToAct")

    for token in _delegate_tokens(row, props):
        remember_delegate(directory, object_id, token)
        pending.append((object_id, "AllowedToDelegate", token))


def _aces(directory: Directory, object_id: str, aces: Any) -> None:
    if not isinstance(aces, list):
        return
    rights: dict[str, set[str]] = defaultdict(set)
    inherited: dict[tuple[str, str], bool] = {}
    for ace in aces:
        if not isinstance(ace, dict):
            continue
        ace_type = str(ace.get("AceType") or "AccessAllowed")
        if ace_type not in {"AccessAllowed", ""}:
            continue
        principal = str(ace.get("PrincipalSID") or "").strip()
        right = str(ace.get("RightName") or "").strip()
        if not principal or not right:
            continue
        rights[principal].add(right)
        if ace.get("IsInherited"):
            inherited[(principal, right)] = True

    for principal, held in rights.items():
        if "GetChangesAll" in held:
            directory.add_edge(
                principal,
                object_id,
                "DCSync",
                inherited=inherited.get((principal, "GetChangesAll"), False),
            )
        for right in sorted(held):
            if right in {"GetChanges", "GetChangesAll"}:
                continue
            if right not in _ACTIONABLE:
                continue
            directory.add_edge(
                principal,
                object_id,
                right,
                inherited=inherited.get((principal, right), False),
            )


def _sessions(directory: Directory, computer_id: str, block: Any) -> None:
    for row in _results(block):
        user = str(row.get("UserSID") or row.get("ObjectIdentifier") or "").strip()
        if user:
            directory.add_edge(computer_id, user, "HasSession")


def _local_group(directory: Directory, computer_id: str, block: Any, relation: str) -> None:
    for row in _results(block):
        member = _object_id(row)
        if member:
            directory.add_edge(member, computer_id, relation)


def _results(block: Any) -> list[dict[str, Any]]:
    if not isinstance(block, dict):
        return []
    rows = block.get("Results") or []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _delegate_tokens(row: dict[str, Any], props: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    raw = row.get("AllowedToDelegate")
    if raw is None:
        raw = props.get("allowedtodelegate") or []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return tokens
    for item in raw:
        if isinstance(item, str) and item.strip():
            tokens.append(item.strip())
        elif isinstance(item, dict):
            ident = str(item.get("ObjectIdentifier") or item.get("name") or "").strip()
            if ident:
                tokens.append(ident)
    return tokens


def _object_id(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("ObjectIdentifier") or "").strip()
    return ""


def _membership_from_primary_groups(directory: Directory) -> None:
    known = set(directory.principals)
    for principal in directory.principals.values():
        primary = principal.primary_group_sid
        if primary and primary in known:
            directory.add_edge(principal.object_id, primary, "MemberOf")


def _primary_is_dc(primary_group_sid: str) -> bool:
    parts = primary_group_sid.split("-")
    # Domain principal SID: S-1-5-21-A-B-C-RID (8 pieces). RID 516 is Domain Controllers.
    return len(parts) == 8 and parts[-1] == "516"


def _enabled(props: dict[str, Any], kind: str) -> bool:
    if "enabled" in props:
        return bool(props.get("enabled"))
    if kind in {"group", "domain", "ou", "gpo", "container"}:
        return True
    return True


def _truthy_prop(props: dict[str, Any], *keys: str) -> bool:
    return any(bool(props.get(key)) for key in keys)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
