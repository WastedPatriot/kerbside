"""Load a collection from disk. The format is a guess unless you say otherwise."""

from __future__ import annotations

from pathlib import Path

from kerbside.models import Directory
from kerbside.parsers.bloodhound import load_bloodhound
from kerbside.parsers.flatcsv import load_csv
from kerbside.parsers.ldif import load_ldif

_FORMATS = {"auto", "bloodhound", "ldif", "csv"}


def load(path: str | Path, fmt: str = "auto") -> Directory:
    target = Path(path)
    if fmt not in _FORMATS:
        raise ValueError(f"Unknown format {fmt!r}. Use auto, bloodhound, ldif, or csv.")
    if target.suffix.lower() == ".zip":
        raise ValueError(
            "SharpHound zips are on the roadmap. "
            "Unzip the collection and point kerbside at the folder."
        )
    if not target.exists():
        raise FileNotFoundError(target)

    chosen = detect_format(target) if fmt == "auto" else fmt
    if chosen == "bloodhound":
        return load_bloodhound(target)
    if chosen == "ldif":
        return load_ldif(target)
    if chosen == "csv":
        return load_csv(target)
    raise ValueError(f"Could not tell what {target} is. Pass --format.")


def detect_format(path: Path) -> str:
    if path.is_file():
        return _sniff_file(path)
    files = [item for item in path.rglob("*") if item.is_file()]
    suffixes = {item.suffix.lower() for item in files}
    if ".json" in suffixes:
        return "bloodhound"
    if ".ldif" in suffixes or ".ldf" in suffixes:
        return "ldif"
    if ".csv" in suffixes:
        return "csv"
    raise ValueError(
        f"Nothing in {path} looks like BloodHound JSON, LDIF, or CSV."
    )


def _sniff_file(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "bloodhound"
    if suffix in {".ldif", ".ldf", ".ldi"}:
        return "ldif"
    if suffix == ".csv":
        return "csv"
    head = path.read_text(encoding="utf-8", errors="replace")[:800].lstrip()
    if head.startswith("{") or head.startswith("["):
        return "bloodhound"
    if head.lower().startswith("dn:") or "objectclass:" in head.lower():
        return "ldif"
    if "," in head.splitlines()[0]:
        return "csv"
    raise ValueError(f"Could not tell what {path.name} is. Pass --format.")
