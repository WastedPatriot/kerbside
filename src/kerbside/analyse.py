"""One pass over a directory: who is privileged, what reaches them, what is flagged."""

from __future__ import annotations

from dataclasses import dataclass

from kerbside.findings import Finding, collect_findings
from kerbside.models import Directory
from kerbside.paths import SEVERITY_RANK, AttackPath, find_paths


@dataclass
class Analysis:
    directory: Directory
    paths: list[AttackPath]
    findings: list[Finding]

    def finding_counts(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {name: count for name, count in counts.items() if count}

    @property
    def domains(self) -> list[str]:
        found: list[str] = []
        for principal in self.directory.principals.values():
            if principal.domain and principal.domain not in found:
                found.append(principal.domain)
        return found


def analyse(
    directory: Directory,
    *,
    max_depth: int = 6,
    limit: int = 25,
    start_contains: str | None = None,
) -> Analysis:
    paths = find_paths(
        directory,
        max_depth=max_depth,
        limit=limit,
        start_contains=start_contains,
    )
    findings = collect_findings(directory)
    return Analysis(directory=directory, paths=paths, findings=findings)
