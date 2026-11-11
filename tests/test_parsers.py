from pathlib import Path

import pytest

from kerbside.data import fixtures_dir, northsea_dir
from kerbside.parsers import load


def test_northsea_collection_has_the_edges_that_matter():
    directory = load(northsea_dir())
    assert len(directory.principals) == 25
    assert directory.warnings == []
    relations = {edge.relation for edge in directory.edges}
    assert {"DCSync", "HasSession", "AdminTo", "GenericAll", "AllowedToDelegate"} <= relations
    assert "GenericRead" not in relations

    by_sam = {principal.sam_account_name: principal for principal in directory.principals.values()}
    bob = by_sam["bob.haddock"]
    alice = by_sam["alice.pence"]
    denied = [
        edge
        for edge in directory.edges
        if edge.source == bob.object_id and edge.target == alice.object_id
    ]
    assert denied == []
    assert not any(edge.source == edge.target for edge in directory.edges)
    assert by_sam["carol.wicks"].dont_req_preauth
    assert by_sam["DC01$"].is_dc
    assert by_sam["WEB01$"].unconstrained_delegation
    assert not by_sam["WEB01$"].is_dc
    assert "MSSQLSvc/db01.northsea.local:1433" in by_sam["sql.svc"].spns


def test_ldif_reads_flags_folding_and_delegation():
    directory = load(fixtures_dir() / "tideline.ldif")
    by_sam = {principal.sam_account_name: principal for principal in directory.principals.values()}

    carol = by_sam["carol.wicks"]
    assert carol.enabled and carol.dont_req_preauth
    assert "cannot do pre-authentication" in carol.description

    assert by_sam["sql.svc"].spns == ["HTTP/intranet.tideline.local", "HTTP/intranet"]
    assert by_sam["temp.admin"].password_not_required
    assert by_sam["temp.admin"].description == "kept in a drawer"
    assert not by_sam["old.contractor"].enabled
    assert by_sam["WEB01$"].unconstrained_delegation and not by_sam["WEB01$"].is_dc
    assert by_sam["DC01$"].is_dc

    memberof = [edge for edge in directory.edges if edge.relation == "MemberOf"]
    assert len(memberof) == 1
    delegation = [edge for edge in directory.edges if edge.relation == "AllowedToDelegate"]
    assert len(delegation) == 1
    assert directory.label(delegation[0].target) == "fs01.tideline.local"


def test_csv_round_trip_into_a_directory():
    directory = load(fixtures_dir() / "lampeter")
    assert any(
        edge.relation == "GenericAll" and directory.label(edge.source).startswith("mira")
        for edge in directory.edges
    )
    sql = next(
        principal
        for principal in directory.principals.values()
        if principal.sam_account_name == "sql"
    )
    assert len(sql.spns) == 2


def test_zip_is_refused(tmp_path: Path):
    archive = tmp_path / "sharp.zip"
    archive.write_text("not really a zip", encoding="utf-8")
    with pytest.raises(ValueError, match="roadmap"):
        load(archive)


def test_unknown_format_is_a_clear_error(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="BloodHound"):
        load(empty)


def test_bad_json_is_a_warning_not_a_crash(tmp_path: Path):
    (tmp_path / "users.json").write_text("{this is not json", encoding="utf-8")
    directory = load(tmp_path)
    assert directory.principals == {}
    assert directory.warnings
