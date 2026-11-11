"""Command line entry. The real commands arrive with the rest of the tool."""

from __future__ import annotations

import argparse

from kerbside import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kerbside",
        description="Offline Active Directory enumeration helper for authorised labs.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"kerbside {__version__}",
    )
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
