import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from kerbside import __version__
from kerbside.analyse import analyse
from kerbside.data import northsea_dir
from kerbside.models import Directory, Principal
from kerbside.parsers import load
from kerbside.report import NO_FINDINGS, NO_PATHS, render_html, render_markdown, write_reports


def test_northsea_report_names_the_path_and_the_fix():
    moment = datetime(2026, 11, 11, 12, 40, tzinfo=UTC)
    analysis = analyse(load(northsea_dir()))
    markdown = render_markdown(analysis, source_label="northsea", generated=moment)
    page = render_html(analysis, source_label="northsea", generated=moment)

    assert "11 Nov 2026 12:40 UTC" in markdown
    assert "sync.svc@northsea.local" in markdown
    assert "DCSync" in markdown
    assert "ed.marsh@northsea.local" in markdown
    assert "Turn pre-authentication back on" in markdown
    assert NO_PATHS not in markdown

    assert "<html" in page.lower()
    assert "<style>" in page
    assert "<script" not in page.lower()
    assert "<link" not in page.lower()
    assert "src=" not in page.lower()
    assert 'class="kerb"' in page


def test_empty_directory_gets_the_kettle():
    moment = datetime(2026, 11, 11, tzinfo=UTC)
    analysis = analyse(Directory())
    markdown = render_markdown(analysis, source_label="empty", generated=moment)
    assert NO_PATHS in markdown
    assert NO_FINDINGS in markdown


def test_html_escapes_names():
    moment = datetime(2026, 11, 11, tzinfo=UTC)
    directory = Directory()
    directory.add_principal(
        Principal(
            "U",
            "sneaky",
            "user",
            domain="lab.local",
            sam_account_name="a<b",
            dont_req_preauth=True,
            description="password is <script>alert(1)</script>",
        )
    )
    page = render_html(analyse(directory), source_label="<img src=x>", generated=moment)
    assert "<img" not in page
    assert "<script>" not in page
    assert "alert(1)" not in page
    assert "&lt;img" in page
    assert "&lt;script&gt;" not in page


# Planted in the Northsea fixture description. It must stay in the export
# and stay out of every report.
_PLANTED_SECRET = "NorthseaSticky#8841"


def test_planted_description_secret_never_reaches_output(tmp_path: Path):
    directory = load(northsea_dir())
    sql = next(
        principal
        for principal in directory.principals.values()
        if principal.sam_account_name == "sql.svc"
    )
    assert _PLANTED_SECRET in sql.description

    moment = datetime(2026, 11, 11, 12, 40, tzinfo=UTC)
    analysis = analyse(directory)
    finding = next(item for item in analysis.findings if item.category == "description")
    assert str(len(sql.description)) in finding.detail
    assert "not copied" in finding.detail

    markdown = render_markdown(analysis, source_label="northsea", generated=moment)
    page = render_html(analysis, source_label="northsea", generated=moment)
    payload = json.dumps([asdict(item) for item in analysis.findings])
    json_path = tmp_path / "findings.json"
    json_path.write_text(payload, encoding="utf-8")
    markdown_path, html_path = write_reports(
        analysis,
        tmp_path,
        source_label="northsea",
        generated=moment,
    )

    rendered = "\n".join(
        [
            markdown,
            page,
            payload,
            json_path.read_text(encoding="utf-8"),
            markdown_path.read_text(encoding="utf-8"),
            html_path.read_text(encoding="utf-8"),
        ]
    )
    assert _PLANTED_SECRET not in rendered


def test_write_reports_creates_both_files(tmp_path: Path):
    analysis = analyse(load(northsea_dir()))
    markdown, page = write_reports(
        analysis,
        tmp_path,
        source_label="northsea",
        generated=datetime(2026, 11, 11, tzinfo=UTC),
    )
    assert markdown.name == "report.md"
    assert page.name == "report.html"
    assert "kerbside" in markdown.read_text(encoding="utf-8")


def test_package_version_matches_pyproject():
    root = Path(__file__).resolve().parents[1]
    text = root.joinpath("pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in text
