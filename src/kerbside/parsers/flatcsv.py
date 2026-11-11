"""Flat CSV, the sort of thing you get after Export-Csv and a tidy-up.

Two shapes, told apart by the header:

* objects: object_id, type, name, and the flags
* edges: source, relation, target

member_of, spns, and delegate_to are pipe-separated when a cell holds several.
"""

from __future__ import annotations

import csv
from pathlib import Path

from kerbside.models import Directory, Principal
from kerbside.parsers.common import add_resolved_edges, remember_delegate


def load_csv(path: Path) -> Directory:
    directory = Directory(source=str(path))
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*.csv") if p.is_file())
    if not files:
        directory.warnings.append(f"No CSV files in {path}")
        return directory

    object_rows: list[dict[str, str]] = []
    edge_rows: list[dict[str, str]] = []
    for file in files:
        try:
            rows, kind = _read(file)
        except ValueError as exc:
            directory.warnings.append(f"{file.name}: {exc}")
            continue
        if kind == "edges":
            edge_rows.extend(rows)
        else:
            object_rows.extend(rows)

    pending: list[tuple[str, str, str]] = []
    for row in object_rows:
        _ingest_object(directory, row, pending)
    for row in edge_rows:
        inherited = _as_bool(row.get("inherited"), default=False)
        directory.add_edge(
            row.get("source", "").strip(),
            row.get("target", "").strip(),
            row.get("relation", "").strip(),
            inherited=inherited,
        )
    add_resolved_edges(directory, pending)
    return directory


def _read(path: Path) -> tuple[list[dict[str, str]], str]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("missing header")
        fields = {(name or "").strip().lower() for name in reader.fieldnames}
        if {"source", "relation", "target"} <= fields:
            kind = "edges"
        elif "object_id" in fields or "type" in fields:
            kind = "objects"
        else:
            raise ValueError("header is neither objects nor edges")
        rows: list[dict[str, str]] = []
        for raw in reader:
            cleaned: dict[str, str] = {}
            for key, value in raw.items():
                if not key:
                    continue
                if isinstance(value, list):
                    value = "|".join(item for item in value if item)
                cleaned[key.strip().lower()] = (value or "").strip()
            rows.append(cleaned)
        return rows, kind


def _ingest_object(
    directory: Directory,
    row: dict[str, str],
    pending: list[tuple[str, str, str]],
) -> None:
    object_id = row.get("object_id", "").strip()
    if not object_id:
        directory.warnings.append("Skipped a CSV row with no object_id")
        return
    kind = (row.get("type") or row.get("kind") or "user").strip().lower()
    domain = (row.get("domain") or "").lower()
    sam = row.get("sam") or row.get("samaccountname") or ""
    name = row.get("name") or sam or object_id
    spns = _pipes(row.get("spns") or row.get("spn") or "")
    delegates = _pipes(row.get("delegate_to") or "")

    principal = Principal(
        object_id=object_id,
        name=name,
        kind=kind,
        domain=domain,
        sam_account_name=sam,
        enabled=_as_bool(row.get("enabled"), default=True),
        high_value=_as_bool(row.get("high_value"), default=False),
        is_dc=_as_bool(row.get("is_dc"), default=False),
        dont_req_preauth=_as_bool(row.get("dont_req_preauth"), default=False),
        has_spn=bool(spns),
        spns=spns,
        unconstrained_delegation=_as_bool(row.get("unconstrained"), default=False),
        trusted_to_auth=_as_bool(row.get("trusted_to_auth"), default=False),
        password_not_required=_as_bool(row.get("password_not_required"), default=False),
        description=row.get("description") or "",
    )
    directory.add_principal(principal)
    for group_id in _pipes(row.get("member_of") or ""):
        directory.add_edge(object_id, group_id, "MemberOf")
    for token in delegates:
        remember_delegate(directory, object_id, token)
        pending.append((object_id, "AllowedToDelegate", token))


def _pipes(value: str) -> list[str]:
    return [part.strip() for part in value.split("|") if part.strip()]


def _as_bool(value: str | None, *, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y"}
