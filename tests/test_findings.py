from kerbside.analyse import analyse
from kerbside.data import northsea_dir
from kerbside.parsers import load

_BANNED = ("impacket", "rubeus", "hashcat", "secretsdump", "mimikatz", "getuserspns")


def test_northsea_kerberos_flags():
    analysis = analyse(load(northsea_dir()))
    by_key = {(item.category, item.principal_name): item for item in analysis.findings}

    carol = by_key[("asrep", "carol.wicks@northsea.local")]
    assert carol.severity == "high"

    retired = by_key[("asrep", "old.contractor@northsea.local")]
    assert retired.severity == "info"

    sql = by_key[("kerberoast", "sql.svc@northsea.local")]
    assert sql.severity == "medium"
    assert "never to expire" in sql.detail

    assert ("kerberoast", "krbtgt@northsea.local") not in by_key
    assert ("asrep", "krbtgt@northsea.local") not in by_key

    web = by_key[("unconstrained", "web01.northsea.local")]
    assert web.severity == "high"
    dc = by_key[("unconstrained", "dc01.northsea.local")]
    assert dc.severity == "info"

    delegation = by_key[("delegation", "print.svc@northsea.local")]
    assert delegation.severity == "high"
    assert "fs01.northsea.local" in delegation.detail

    assert ("description", "sql.svc@northsea.local") in by_key


def test_wording_stays_away_from_exploit_tools():
    analysis = analyse(load(northsea_dir()))
    blob = " ".join(
        f"{item.title} {item.detail} {item.remediation}" for item in analysis.findings
    ).lower()
    for banned in _BANNED:
        assert banned not in blob
