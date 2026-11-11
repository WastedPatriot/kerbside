"""The kerbside command. Offline on purpose."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from kerbside import __version__
from kerbside.analyse import analyse
from kerbside.data import northsea_dir
from kerbside.parsers import load
from kerbside.report import NO_FINDINGS, NO_PATHS, write_reports

console = Console(highlight=False, emoji=False)
err = Console(highlight=False, emoji=False, stderr=True)

_SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_SEV_BORDER = {
    "critical": "red",
    "high": "yellow",
    "medium": "cyan",
    "low": "blue",
    "info": "white",
}


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "scan":
        return _scan(args)
    parser.print_help()
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kerbside",
        description=(
            "Offline Active Directory enumeration for authorised labs. "
            "Reads BloodHound JSON, ldapsearch LDIF, or a flat CSV. Talks to nobody."
        ),
    )
    parser.add_argument("--version", action="version", version=f"kerbside {__version__}")
    commands = parser.add_subparsers(dest="command")

    scan = commands.add_parser(
        "scan",
        help="Read an export, find paths, write a report",
    )
    scan.add_argument(
        "-i",
        "--input",
        help="File or directory of BloodHound JSON, LDIF, or CSV",
    )
    scan.add_argument(
        "-o",
        "--output",
        default="kerbside-out",
        help="Directory for report.md and report.html (default: kerbside-out)",
    )
    scan.add_argument(
        "--format",
        choices=("auto", "bloodhound", "ldif", "csv"),
        default="auto",
        help="What the input is. Default: have a guess",
    )
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Use the bundled Northsea fixture. No domain required",
    )
    scan.add_argument(
        "--depth",
        type=int,
        default=6,
        help="How many hops to follow (default: 6)",
    )
    scan.add_argument(
        "--limit",
        type=int,
        default=25,
        help="How many paths to keep (default: 25)",
    )
    scan.add_argument(
        "--from",
        dest="start_contains",
        metavar="NAME",
        help="Only paths involving a principal whose name contains this text",
    )
    return parser


def _scan(args: argparse.Namespace) -> int:
    if args.depth < 1 or args.limit < 1:
        err.print("Depth and limit have to be at least 1.")
        return 2

    if args.dry_run:
        source: Path = northsea_dir()
        label = "bundled Northsea fixture (dry run)"
        fmt = "bloodhound"
        if args.input:
            console.print("[dim]--input ignored. A dry run only reads the fixture.[/]")
    elif not args.input:
        err.print("Pass --input, or --dry-run if you just want to see the sample.")
        return 2
    else:
        source = Path(args.input)
        label = str(source)
        fmt = args.format

    try:
        directory = load(source, fmt)
    except FileNotFoundError:
        err.print(f"Nothing at {source}. kerbside cannot read a folder you imagined.")
        return 2
    except ValueError as exc:
        err.print(str(exc))
        return 1

    if not directory.principals:
        err.print("Those files did not yield a single principal.")
        for warning in directory.warnings[:8]:
            err.print(f"  {warning}")
        return 1

    try:
        analysis = analyse(
            directory,
            max_depth=args.depth,
            limit=args.limit,
            start_contains=args.start_contains,
        )
    except ValueError as exc:
        err.print(str(exc))
        return 2

    markdown_path, html_path = write_reports(analysis, args.output, source_label=label)
    _show(analysis, label, markdown_path, html_path, dry_run=args.dry_run)
    return 0


def _show(analysis, label: str, markdown_path: Path, html_path: Path, *, dry_run: bool) -> None:
    subtitle = "Stands on the kerb. Reads the bags you already packed."
    console.print(
        Panel.fit(
            f"[bold]kerbside[/]  {__version__}\n[dim]{subtitle}[/]",
            border_style="yellow",
        )
    )
    if dry_run:
        console.print(
            "[dim]Dry run. The borough of Northsea is fictional. "
            "No directory was contacted, which is the whole idea.[/]"
        )

    summary = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    summary.add_column(style="dim")
    summary.add_column()
    domains = ", ".join(analysis.domains) or "not named in the export"
    summary.add_row("source", escape(label))
    summary.add_row("domain", escape(domains))
    summary.add_row("principals", str(len(analysis.directory.principals)))
    summary.add_row("edges", str(len(analysis.directory.edges)))
    summary.add_row("paths", str(len(analysis.paths)))
    counts = analysis.finding_counts()
    count_text = ", ".join(f"{count} {name}" for name, count in counts.items()) or "none"
    summary.add_row("findings", count_text)
    console.print(summary)

    for warning in analysis.directory.warnings[:6]:
        console.print(f"[yellow]note[/] {escape(warning)}")
    leftover = len(analysis.directory.warnings) - 6
    if leftover > 0:
        console.print(f"[dim]{leftover} more parser notes in the report.[/]")

    console.print()
    if not analysis.paths:
        console.print(Panel(NO_PATHS, title="Paths", border_style="green"))
    else:
        shown = analysis.paths[:6]
        for index, path in enumerate(shown, start=1):
            console.print(_path_panel(analysis.directory, index, path))
        extra = len(analysis.paths) - len(shown)
        if extra:
            console.print(f"[dim]{extra} more paths in the report.[/]")

    console.print()
    if not analysis.findings:
        console.print(Panel(NO_FINDINGS, title="Kerberos and delegation", border_style="green"))
    else:
        table = Table(title="Kerberos and delegation", box=box.SIMPLE_HEAD)
        table.add_column("Sev")
        table.add_column("Account")
        table.add_column("What")
        for finding in analysis.findings[:12]:
            style = _SEV_STYLE.get(finding.severity, "white")
            table.add_row(
                f"[{style}]{escape(finding.severity)}[/]",
                escape(finding.principal_name),
                escape(finding.title),
            )
        console.print(table)
        extra = len(analysis.findings) - 12
        if extra > 0:
            console.print(f"[dim]{extra} more findings in the report.[/]")
        console.print("[dim]Particulars, and the fix, are in the report.[/]")

    console.print()
    console.print(f"wrote [bold]{escape(str(markdown_path))}[/]")
    console.print(f"wrote [bold]{escape(str(html_path))}[/]")


def _path_panel(directory, index: int, path) -> Panel:
    names = [escape(directory.label(node)) for node in path.nodes]
    lines = [f"[bold]{names[0]}[/]"]
    for relation, name in zip(path.relations, names[1:], strict=True):
        lines.append(f"  [yellow]{escape(relation)}[/] → {name}")
    also_labels = [escape(directory.label(item)) for item in path.also[:6]]
    subtitle = f"{path.severity} · {path.length} hops"
    if also_labels:
        extra = len(path.also) - len(also_labels)
        also_text = ", ".join(also_labels)
        if extra:
            also_text += f" +{extra}"
        subtitle += f" · also {also_text}"
    style = _SEV_BORDER.get(path.severity, "white")
    return Panel(
        "\n".join(lines),
        title=f"Path {index}",
        subtitle=subtitle,
        border_style=style,
    )


if __name__ == "__main__":
    raise SystemExit(main())
