"""Markdown and a single HTML file. No CDN, no JavaScript, no phone-home."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path

from kerbside import __version__
from kerbside.analyse import Analysis
from kerbside.paths import AttackPath

NO_PATHS = (
    "No path to the high-value lot. "
    "Either this directory is curiously tidy, or the juicy ACL "
    "is still in someone's head. Both happen. Put the kettle on anyway."
)

NO_FINDINGS = (
    "No Kerberos flags of the sort kerbside looks for. "
    "Suspicious in its own way, but here we are."
)

_BLURB = {
    "MemberOf": "Group membership. The principal picks up whatever this group can do.",
    "GenericAll": "Full control of the target object.",
    "GenericWrite": "Can rewrite most attributes on the target.",
    "WriteDacl": "Can rewrite the target's permissions.",
    "WriteOwner": "Can take ownership of the target.",
    "Owns": "Owns the object.",
    "ForceChangePassword": "Can reset the account password without knowing the current one.",
    "AllExtendedRights": (
        "Holds every extended right on the target, including password resets on users."
    ),
    "AddMember": "Can add members to the group.",
    "AddSelf": "Can add itself to the group.",
    "AdminTo": "Local administrator on the computer.",
    "HasSession": "The export records a logon session for the account on this computer.",
    "DCSync": "Domain replication rights (GetChangesAll). Enough to copy the password database.",
    "ReadLAPSPassword": "Can read the LAPS local administrator password.",
    "AllowedToDelegate": "Constrained delegation to a service on the target.",
    "AllowedToAct": "Listed for resource-based constrained delegation on the computer.",
    "CanRDP": "Permitted to open a remote desktop session.",
    "CanPSRemote": "Permitted to open a PowerShell remoting session.",
    "ExecuteDCOM": "Permitted to launch DCOM on the computer.",
    "WriteSPN": "Can write service principal names on the target.",
    "AddKeyCredentialLink": "Can write a key credential link on the target.",
    "ReadGMSAPassword": "Can read a group managed service account password.",
    "SQLAdmin": "SQL administrator on the target.",
}

_READING = (
    "A path is a chain of rights and memberships already present in the export. "
    "It is not a set of commands. kerbside did not contact a domain controller."
)


def write_reports(
    analysis: Analysis,
    outdir: str | Path,
    *,
    source_label: str,
    generated: datetime | None = None,
) -> tuple[Path, Path]:
    moment = generated or datetime.now(UTC)
    folder = Path(outdir)
    folder.mkdir(parents=True, exist_ok=True)
    markdown_path = folder / "report.md"
    html_path = folder / "report.html"
    markdown_path.write_text(
        render_markdown(analysis, source_label=source_label, generated=moment),
        encoding="utf-8",
    )
    html_path.write_text(
        render_html(analysis, source_label=source_label, generated=moment),
        encoding="utf-8",
    )
    return markdown_path, html_path


def render_markdown(analysis: Analysis, *, source_label: str, generated: datetime) -> str:
    directory = analysis.directory
    lines: list[str] = [
        "# kerbside report",
        "",
        f"Offline reading of `{source_label}`.",
        f"Generated { _stamp(generated) } by kerbside {__version__}.",
        "",
        _READING,
        "",
        "## Summary",
        "",
        "| | |",
        "| --- | --- |",
        f"| Domain | {_cell(_domains(analysis))} |",
        f"| Principals | {len(directory.principals)} |",
        f"| Edges | {len(directory.edges)} |",
        f"| Paths | {len(analysis.paths)} |",
        f"| Findings | {len(analysis.findings)} |",
    ]
    kinds = directory.kinds()
    if kinds:
        kind_text = ", ".join(f"{count} {name}" for name, count in kinds.items())
        lines.append(f"| By kind | {_cell(kind_text)} |")
    lines.extend(["", "## Attack paths", ""])
    if not analysis.paths:
        lines.extend([NO_PATHS, ""])
    else:
        for index, path in enumerate(analysis.paths, start=1):
            lines.extend(_markdown_path(directory, index, path))
    lines.extend(["## Kerberos and delegation", ""])
    if not analysis.findings:
        lines.extend([NO_FINDINGS, ""])
    else:
        for finding in analysis.findings:
            lines.extend(
                [
                    f"### {finding.severity} — {finding.title}",
                    "",
                    f"**{finding.principal_name}**",
                    "",
                    finding.detail,
                    "",
                    f"*Fix:* {finding.remediation}",
                    "",
                ]
            )
    if directory.warnings:
        lines.extend(["## Parser notes", ""])
        for warning in directory.warnings:
            lines.append(f"- {warning}")
        lines.append("")
    lines.extend(
        [
            "---",
            "",
            "Authorised labs and signed engagements only. "
            "kerbside reads files. It does not talk to a domain.",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(analysis: Analysis, *, source_label: str, generated: datetime) -> str:
    directory = analysis.directory
    kinds = directory.kinds()
    kind_text = ", ".join(f"{count} {name}" for name, count in kinds.items()) or "none"
    paths_html = (
        f"<p class='empty'>{esc(NO_PATHS)}</p>"
        if not analysis.paths
        else "\n".join(
            _html_path(directory, index, path) for index, path in enumerate(analysis.paths, start=1)
        )
    )
    if analysis.findings:
        findings_html = "\n".join(_html_finding(item) for item in analysis.findings)
    else:
        findings_html = f"<p class='empty'>{esc(NO_FINDINGS)}</p>"
    warnings_html = ""
    if directory.warnings:
        items = "\n".join(f"<li>{esc(item)}</li>" for item in directory.warnings)
        warnings_html = f"<h2>Parser notes</h2><ul>{items}</ul>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>kerbside report</title>
<style>
:root {{
  --paper: #f3efe4;
  --card: #fffdf8;
  --ink: #1e1a14;
  --muted: #5e584e;
  --line: #d9d0c0;
  --critical: #8d2f2a;
  --high: #8a4b08;
  --medium: #1f5c4d;
  --low: #2c4d73;
  --info: #5e584e;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 17px/1.5 Palatino, "Palatino Linotype", "Iowan Old Style", Georgia, serif;
}}
.kerb {{
  height: 12px;
  background: repeating-linear-gradient(90deg, #e2b431 0 16px, #1e1a14 16px 26px);
}}
main {{ max-width: 46rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
h1 {{ font-size: 2.1rem; font-weight: 600; letter-spacing: -0.03em; margin: 0 0 0.2rem; }}
h2 {{ margin-top: 2rem; font-size: 1.35rem; }}
.meta, .blurb, footer, .empty {{ color: var(--muted); }}
.cards {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.7rem;
  margin: 1.2rem 0;
}}
.card {{
  background: var(--card);
  border: 1px solid var(--line);
  padding: 0.7rem 0.8rem;
}}
.card span {{
  display: block;
  color: var(--muted);
  font-size: 0.78rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}}
.card b {{ font-size: 1.35rem; font-variant-numeric: tabular-nums; }}
.path, .finding {{
  background: var(--card);
  border: 1px solid var(--line);
  padding: 0.85rem 1rem;
  margin: 0.75rem 0;
}}
.sev {{ font-size: 0.75rem; letter-spacing: 0.08em; text-transform: uppercase; font-weight: 700; }}
.sev.critical {{ color: var(--critical); }}
.sev.high {{ color: var(--high); }}
.sev.medium {{ color: var(--medium); }}
.sev.low {{ color: var(--low); }}
.sev.info {{ color: var(--info); }}
ol {{ margin: 0.4rem 0 0.2rem; padding-left: 1.2rem; }}
.blurb {{ display: block; font-size: 0.92rem; }}
details {{ margin: 1rem 0; }}
summary {{ cursor: pointer; }}
footer {{ margin-top: 2.5rem; font-size: 0.92rem; }}
@media (max-width: 700px) {{ .cards {{ grid-template-columns: 1fr 1fr; }} }}
@media print {{
  body {{ background: white; }}
  .path, .finding, .card {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="kerb"></div>
<main>
<h1>kerbside</h1>
<p class="meta">Offline reading of {esc(source_label)}.<br>
Generated {esc(_stamp(generated))} · kerbside {esc(__version__)}</p>
<details>
<summary>How to read this</summary>
<p>{esc(_READING)}</p>
</details>
<section class="cards">
<div class="card"><span>Principals</span><b>{len(directory.principals)}</b></div>
<div class="card"><span>Edges</span><b>{len(directory.edges)}</b></div>
<div class="card"><span>Paths</span><b>{len(analysis.paths)}</b></div>
<div class="card"><span>Findings</span><b>{len(analysis.findings)}</b></div>
</section>
<p class="meta">Domain: {esc(_domains(analysis))}. {esc(kind_text)}.</p>
<h2>Attack paths</h2>
{paths_html}
<h2>Kerberos and delegation</h2>
{findings_html}
{warnings_html}
<footer>
Authorised labs and signed engagements only.
kerbside reads files. It does not talk to a domain.
</footer>
</main>
</body>
</html>
"""


def _markdown_path(directory, index: int, path: AttackPath) -> list[str]:
    names = [directory.label(node) for node in path.nodes]
    target = directory.principals.get(path.target_id)
    why = ", ".join(target.privileged_via) if target and target.privileged_via else "high value"
    lines = [
        f"### {index}. {names[0]} → {names[-1]}",
        "",
        f"- **Severity:** {path.severity}",
        f"- **Hops:** {path.length}",
        f"- **Why the target matters:** {why}",
    ]
    also = _also_text(directory, path)
    if also:
        lines.append(f"- **Same route for:** {also}")
    lines.extend(["", f"1. `{names[0]}`"])
    for step, (relation, name) in enumerate(zip(path.relations, names[1:], strict=True), start=2):
        blurb = _BLURB.get(relation, "Recorded in the export.")
        lines.append(f"{step}. **{relation}** → `{name}`  ")
        lines.append(f"   {blurb}")
    lines.append("")
    return lines


def _html_path(directory, index: int, path: AttackPath) -> str:
    names = [directory.label(node) for node in path.nodes]
    target = directory.principals.get(path.target_id)
    why = ", ".join(target.privileged_via) if target and target.privileged_via else "high value"
    steps = [f"<li><code>{esc(names[0])}</code></li>"]
    for relation, name in zip(path.relations, names[1:], strict=True):
        blurb = _BLURB.get(relation, "Recorded in the export.")
        steps.append(
            "<li><strong>"
            + esc(relation)
            + "</strong> → <code>"
            + esc(name)
            + "</code><span class='blurb'>"
            + esc(blurb)
            + "</span></li>"
        )
    also = _also_text(directory, path)
    also_html = f"<p class='meta'>Same route for {esc(also)}.</p>" if also else ""
    return (
        "<article class='path'>"
        f"<p class='sev {esc(path.severity)}'>{esc(path.severity)} · {path.length} hops</p>"
        f"<h3>{index}. {esc(names[0])} → {esc(names[-1])}</h3>"
        f"<p class='meta'>Why the target matters: {esc(why)}</p>"
        f"{also_html}"
        f"<ol>{''.join(steps)}</ol>"
        "</article>"
    )


def _html_finding(finding) -> str:
    return (
        "<article class='finding'>"
        f"<p class='sev {esc(finding.severity)}'>{esc(finding.severity)}</p>"
        f"<h3>{esc(finding.title)}</h3>"
        f"<p><strong>{esc(finding.principal_name)}</strong></p>"
        f"<p>{esc(finding.detail)}</p>"
        f"<p class='blurb'>Fix: {esc(finding.remediation)}</p>"
        "</article>"
    )


def _also_text(directory, path: AttackPath) -> str:
    labels = [directory.label(item) for item in path.also]
    if not labels:
        return ""
    shown = labels[:8]
    text = ", ".join(shown)
    extra = len(labels) - len(shown)
    if extra:
        text += f" (+{extra} more)"
    return text


def _domains(analysis: Analysis) -> str:
    if not analysis.domains:
        return "not named in the export"
    return ", ".join(analysis.domains)


def _stamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%d %b %Y %H:%M UTC")


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)
