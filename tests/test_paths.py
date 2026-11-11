from kerbside.data import northsea_dir
from kerbside.models import Directory, Principal
from kerbside.parsers import load
from kerbside.paths import find_paths


def test_northsea_paths_reach_the_right_people():
    directory = load(northsea_dir())
    paths = find_paths(directory)
    starts = [directory.label(path.nodes[0]) for path in paths]

    sync = next(path for path in paths if directory.label(path.nodes[0]).startswith("sync.svc"))
    assert sync.relations == ["DCSync"]
    bob = next(path for path in paths if directory.label(path.nodes[0]).startswith("bob.haddock"))
    assert bob.severity == "critical"
    assert bob.relations == ["MemberOf", "GenericAll", "AdminTo", "HasSession"]
    assert any(directory.label(item).startswith("ed.marsh") for item in bob.also)

    nora = next(path for path in paths if directory.label(path.nodes[0]).startswith("nora.quay"))
    assert nora.severity == "high"
    assert nora.relations == ["ForceChangePassword"]

    assert not any(name.startswith("alice.pence") for name in starts)
    assert not any(name.startswith("carol.wicks") for name in starts)
    assert not any(name.startswith("fs01") for name in starts)


def test_depth_limit_drops_the_long_way_round():
    directory = load(northsea_dir())
    short = find_paths(directory, max_depth=3)
    starts = [directory.label(path.nodes[0]) for path in short]
    assert any(name.startswith("sync.svc") for name in starts)
    assert not any(name.startswith("bob.haddock") for name in starts)

    bob = find_paths(directory, start_contains="ed.marsh")
    assert len(bob) == 1
    assert directory.label(bob[0].nodes[0]).startswith("ed.marsh")
    assert any("bob.haddock" in directory.label(item) for item in bob[0].also)


def test_everyone_is_one_start_not_every_user():
    directory = Directory()
    directory.add_principal(
        Principal(
            "DA",
            "Domain Admins@lab.local",
            "group",
            domain="lab.local",
            sam_account_name="Domain Admins",
            high_value=True,
        )
    )
    directory.add_edge("S-1-1-0", "DA", "GenericAll")
    paths = find_paths(directory)
    assert len(paths) == 1
    assert paths[0].relations == ["GenericAll"]
    assert directory.label(paths[0].nodes[0]) == "Everyone"


def test_renamed_domain_admins_still_count_by_rid():
    directory = Directory()
    directory.add_principal(
        Principal(
            "S-1-5-21-9-9-9-512",
            "Domänen-Admins@lab.local",
            "group",
            domain="lab.local",
            sam_account_name="Domänen-Admins",
        )
    )
    directory.add_principal(
        Principal("U", "mira@lab.local", "user", domain="lab.local", sam_account_name="mira")
    )
    directory.add_edge("U", "S-1-5-21-9-9-9-512", "GenericAll")
    paths = find_paths(directory)
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert "Domain Admins" in directory.principals["S-1-5-21-9-9-9-512"].privileged_via


def test_a_long_chain_respects_max_depth():
    directory = Directory()
    directory.add_principal(
        Principal("T", "Domain Admins", "group", sam_account_name="Domain Admins", high_value=True)
    )
    current = "T"
    for index in range(3):
        group_id = f"G{index}"
        directory.add_principal(
            Principal(group_id, f"Nest{index}", "group", sam_account_name=f"Nest{index}")
        )
        directory.add_edge(group_id, current, "GenericAll")
        current = group_id
    directory.add_principal(Principal("U", "ada", "user", sam_account_name="ada"))
    directory.add_edge("U", current, "GenericAll")

    assert find_paths(directory, max_depth=3) == []
    found = find_paths(directory, max_depth=4)
    assert len(found) == 1
    assert found[0].length == 4
