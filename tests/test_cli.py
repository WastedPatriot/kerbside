from kerbside.cli import main


def test_help_mentions_scan(capsys):
    try:
        code = main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
        code = 0
    assert code == 0
    assert "scan" in capsys.readouterr().out


def test_scan_help_mentions_dry_run(capsys):
    try:
        main(["scan", "--help"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "--dry-run" in capsys.readouterr().out


def test_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "kerbside 0.1.0" in capsys.readouterr().out


def test_dry_run_writes_a_report(tmp_path, capsys):
    code = main(["scan", "--dry-run", "-o", str(tmp_path)])
    assert code == 0
    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "sync.svc@northsea.local" in markdown
    assert "carol.wicks@northsea.local" in markdown
    assert "<script" not in page.lower()
    captured = capsys.readouterr()
    assert "Dry run" in captured.out
    assert captured.err == ""


def test_from_filter_limits_paths(tmp_path):
    code = main(["scan", "--dry-run", "--from", "nora", "-o", str(tmp_path)])
    assert code == 0
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "nora.quay@northsea.local" in text
    assert "DCSync" not in text


def test_missing_input_is_a_usage_error(capsys):
    code = main(["scan", "-i", "/tmp/kerbside-missing-on-purpose"])
    assert code == 2
    assert "imagined" in capsys.readouterr().err


def test_scan_without_input(capsys):
    code = main(["scan"])
    assert code == 2
    assert "dry-run" in capsys.readouterr().err


def test_roast_is_a_joke_about_potatoes(capsys):
    code = main(["roast"])
    assert code == 0
    out = capsys.readouterr().out.lower()
    assert "potato" in out
    assert "ticket" in out
    for banned in ("impacket", "rubeus", "hashcat", "secretsdump", "mimikatz", "getuserspns"):
        assert banned not in out


def test_empty_directory(tmp_path, capsys):
    code = main(["scan", "-i", str(tmp_path), "-o", str(tmp_path / "out")])
    assert code == 1
    assert capsys.readouterr().err
