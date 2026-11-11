"""ldapsearch-style LDIF.

Line folding (a leading space) and simple base64 values are understood.
objectSid blobs are not; use the DN as the object id, which is what ldapsearch
gives you without asking for binary.
"""

from __future__ import annotations

import base64
from pathlib import Path

from kerbside.models import Directory, Principal
from kerbside.parsers.common import add_resolved_edges, remember_delegate

# userAccountControl bits we care about. The rest can stay in the directory.
_UAC_ACCOUNTDISABLE = 0x0002
_UAC_PASSWD_NOTREQD = 0x0020
_UAC_SERVER_TRUST = 0x2000  # domain controller
_UAC_DONT_EXPIRE_PASSWD = 0x10000
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_UAC_DONT_REQ_PREAUTH = 0x400000
_UAC_TRUSTED_TO_AUTH = 0x1000000


def load_ldif(path: Path) -> Directory:
    directory = Directory(source=str(path))
    seen = _ldif_files(path)
    if not seen:
        directory.warnings.append(f"No LDIF files in {path}")
        return directory

    entries: list[dict[str, list[str]]] = []
    for file in seen:
        text = file.read_text(encoding="utf-8-sig", errors="replace")
        entries.extend(_parse_ldif(text))

    pending: list[tuple[str, str, str]] = []
    member_links: list[tuple[str, str]] = []
    for entry in entries:
        _ingest_entry(directory, entry, pending, member_links)

    for group_dn, member_dn in member_links:
        directory.add_edge(member_dn, group_dn, "MemberOf")

    add_resolved_edges(directory, pending)
    return directory


def _ldif_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    found = list(path.rglob("*.ldif")) + list(path.rglob("*.ldf"))
    unique = {item.resolve() for item in found if item.is_file()}
    return sorted(unique)


def _parse_ldif(text: str) -> list[dict[str, list[str]]]:
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    last_key: str | None = None

    def finish() -> None:
        nonlocal current, last_key
        if current:
            entries.append(current)
        current = {}
        last_key = None

    for raw in text.splitlines():
        if not raw.strip():
            finish()
            continue
        if raw.startswith("#"):
            continue
        if raw.startswith(" ") and last_key and current.get(last_key):
            current[last_key][-1] += raw[1:]
            continue
        if ":" not in raw:
            continue
        name, value = _split_value(raw)
        if value is None:
            continue
        key = name.strip().lower()
        current.setdefault(key, []).append(value)
        last_key = key
    finish()
    return entries


def _split_value(line: str) -> tuple[str, str | None]:
    name, rest = line.split(":", 1)
    if rest.startswith(":"):
        encoded = rest[1:].strip()
        try:
            blob = base64.b64decode(encoded, validate=False)
        except ValueError:
            return name, None
        try:
            return name, blob.decode("utf-8")
        except UnicodeDecodeError:
            return name, None
    return name, rest.lstrip(" ")


def _ingest_entry(
    directory: Directory,
    entry: dict[str, list[str]],
    pending: list[tuple[str, str, str]],
    member_links: list[tuple[str, str]],
) -> None:
    dn = _first(entry, "dn")
    if not dn:
        return
    classes = {item.lower() for item in entry.get("objectclass", [])}
    kind = _kind(classes)
    if kind is None:
        return

    domain = _domain_from_dn(dn)
    sam = _first(entry, "samaccountname")
    cn = _first(entry, "cn") or _first(entry, "dc") or dn
    name = _object_name(kind, sam, cn, domain)
    uac = _uac(entry)
    spns = list(entry.get("serviceprincipalname", []))
    description = " ".join(part.strip() for part in entry.get("description", []) if part.strip())

    enabled = True
    if uac is not None and kind in {"user", "computer"}:
        enabled = not bool(uac & _UAC_ACCOUNTDISABLE)

    principal = Principal(
        object_id=dn,
        name=name,
        kind=kind,
        domain=domain,
        sam_account_name=sam,
        enabled=enabled,
        is_dc=bool(uac is not None and uac & _UAC_SERVER_TRUST),
        dont_req_preauth=bool(uac is not None and uac & _UAC_DONT_REQ_PREAUTH),
        has_spn=bool(spns),
        spns=spns,
        unconstrained_delegation=bool(uac is not None and uac & _UAC_TRUSTED_FOR_DELEGATION),
        trusted_to_auth=bool(uac is not None and uac & _UAC_TRUSTED_TO_AUTH),
        password_not_required=bool(uac is not None and uac & _UAC_PASSWD_NOTREQD),
        password_never_expires=bool(uac is not None and uac & _UAC_DONT_EXPIRE_PASSWD),
        description=description,
    )
    directory.add_principal(principal)

    for group_dn in entry.get("memberof", []):
        member_links.append((group_dn, dn))
    if kind == "group":
        for member_dn in entry.get("member", []):
            member_links.append((dn, member_dn))

    for token in entry.get("msds-allowedtodelegateto", []):
        remember_delegate(directory, dn, token)
        pending.append((dn, "AllowedToDelegate", token))


def _kind(classes: set[str]) -> str | None:
    if "computer" in classes:
        return "computer"
    if "group" in classes:
        return "group"
    if "user" in classes or "person" in classes:
        return "user"
    if "domain" in classes or "domaindns" in classes:
        return "domain"
    if "organizationalunit" in classes:
        return "ou"
    return None


def _object_name(kind: str, sam: str, cn: str, domain: str) -> str:
    if kind == "domain":
        return domain or cn
    if kind == "computer" and sam.endswith("$") and domain:
        return f"{sam[:-1]}.{domain}"
    if sam and domain and kind in {"user", "group"}:
        return f"{sam}@{domain}"
    return sam or cn


def _domain_from_dn(dn: str) -> str:
    parts: list[str] = []
    for rdn in dn.split(","):
        name, sep, value = rdn.strip().partition("=")
        if sep and name.lower() == "dc" and value:
            parts.append(value)
    return ".".join(parts).lower()


def _uac(entry: dict[str, list[str]]) -> int | None:
    raw = _first(entry, "useraccountcontrol")
    if not raw:
        return None
    try:
        return int(raw, 10)
    except ValueError:
        return None


def _first(entry: dict[str, list[str]], key: str) -> str:
    values = entry.get(key) or []
    return values[0].strip() if values else ""
