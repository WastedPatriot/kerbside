"""Kerberos and delegation flags worth saying out loud.

Names and impact only. The report says what is wrong and what to change.
It does not say how to abuse it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from kerbside.models import Directory, Principal, bare_name
from kerbside.paths import SEVERITY_RANK, prepare_directory

_SECRET_WORDS = re.compile(r"\b(password|passwd|pwd|secret)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    principal_id: str
    principal_name: str
    detail: str
    remediation: str


def collect_findings(directory: Directory) -> list[Finding]:
    prepare_directory(directory)
    found: list[Finding] = []
    for principal in directory.principals.values():
        found.extend(_principal_findings(directory, principal))
    found.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item.severity, 9),
            item.category,
            item.principal_name.lower(),
        )
    )
    return found


def _principal_findings(directory: Directory, principal: Principal) -> list[Finding]:
    if principal.kind not in {"user", "computer"}:
        return []
    found: list[Finding] = []
    if not _is_krbtgt(principal):
        found.extend(_asrep(principal))
        found.extend(_kerberoast(principal))
    found.extend(_unconstrained(principal))
    found.extend(_delegation(directory, principal))
    if principal.kind == "user" and not _is_krbtgt(principal):
        found.extend(_password_not_required(principal))
        found.extend(_admin_count(principal))
    found.extend(_description(principal))
    return found


def _asrep(principal: Principal) -> list[Finding]:
    if principal.kind != "user" or not principal.dont_req_preauth:
        return []
    if not principal.enabled:
        return [
            _make(
                principal,
                "info",
                "asrep",
                "AS-REP roastable, but disabled",
                "Pre-authentication is disabled. It does nothing while the account is "
                "disabled, and it will matter again the moment someone enables it.",
                "Clear the flag before anyone turns the account back on.",
            )
        ]
    severity = "critical" if principal.high_value else "high"
    detail = (
        "Kerberos will issue an AS-REP for this account without proving the caller "
        "knows the password first. Offline guessing gets a lot cheaper."
    )
    if principal.high_value:
        detail += " " + _via_sentence(principal)
    return [
        _make(
            principal,
            severity,
            "asrep",
            "AS-REP roastable account",
            detail,
            "Turn pre-authentication back on. If a legacy application genuinely cannot "
            "cope, that application is the finding.",
        )
    ]


def _kerberoast(principal: Principal) -> list[Finding]:
    if principal.kind != "user" or _is_machine(principal):
        return []
    if not principal.has_spn and not principal.spns:
        return []
    spns = _join(principal.spns) or "an SPN is set, but the export did not list it"
    if not principal.enabled:
        return [
            _make(
                principal,
                "info",
                "kerberoast",
                "Kerberoastable, but disabled",
                f"SPNs on a disabled account: {spns}.",
                "Remove SPNs that are no longer in use before anyone re-enables the account.",
            )
        ]
    severity = "critical" if principal.high_value else "medium"
    detail = (
        f"SPNs: {spns}. Any authenticated user can ask for a service ticket for this "
        "account, and that ticket is encrypted to the account's password."
    )
    if principal.password_never_expires:
        detail += " The password is also set never to expire."
    if principal.high_value:
        detail += " " + _via_sentence(principal)
    return [
        _make(
            principal,
            severity,
            "kerberoast",
            "Kerberoastable account",
            detail,
            "Prefer a group managed service account. Otherwise set a long random password "
            "and remove SPNs that no longer point at a real service.",
        )
    ]


def _unconstrained(principal: Principal) -> list[Finding]:
    if not principal.unconstrained_delegation:
        return []
    if principal.is_dc:
        return [
            _make(
                principal,
                "info",
                "unconstrained",
                "Unconstrained delegation on a domain controller",
                "Domain controllers are unconstrained by design. Noted so a member server "
                "with the same flag does not hide in the list.",
                "Leave the domain controllers to it. Do not copy the setting onto anything else.",
            )
        ]
    if not principal.enabled:
        return [
            _make(
                principal,
                "info",
                "unconstrained",
                "Unconstrained delegation on a disabled account",
                "The flag is set, and the account is disabled. It becomes interesting again "
                "if someone enables it.",
                "Remove unconstrained delegation before the account is reused.",
            )
        ]
    return [
        _make(
            principal,
            "high",
            "unconstrained",
            "Unconstrained delegation",
            "This account may impersonate users who authenticate to it. That is normal for "
            "a domain controller and a bad habit everywhere else.",
            "Remove unconstrained delegation. If a service truly needs to delegate, "
            "constrain it to the services it actually uses.",
        )
    ]


def _delegation(directory: Directory, principal: Principal) -> list[Finding]:
    targets = _delegate_labels(directory, principal)
    if not targets and not principal.trusted_to_auth:
        return []
    listed = _join(targets) if targets else "no targets were listed in this export"
    if principal.trusted_to_auth and targets:
        title = "Constrained delegation with protocol transition"
        detail = (
            f"TrustedToAuthForDelegation is set, and the account may delegate to {listed}. "
            "Protocol transition lets it request tickets on behalf of other users."
        )
        remediation = (
            "Turn off protocol transition unless a specific service needs it, "
            "and keep the allowed list short."
        )
        severity = "high"
    elif principal.trusted_to_auth:
        title = "Protocol transition enabled"
        detail = (
            "TrustedToAuthForDelegation is set. The flag lets the account request "
            f"tickets on behalf of other users. Delegation targets: {listed}."
        )
        remediation = "Turn it off unless a documented service needs protocol transition."
        severity = "high"
    else:
        title = "Constrained delegation"
        detail = f"The account may delegate to {listed}."
        remediation = (
            "Keep the allowed services list specific, and review it when the host changes job."
        )
        severity = "medium"
    if not principal.enabled:
        severity = "info"
        title += " (disabled account)"
    return [_make(principal, severity, "delegation", title, detail, remediation)]


def _password_not_required(principal: Principal) -> list[Finding]:
    if not principal.password_not_required:
        return []
    if not principal.enabled:
        return [
            _make(
                principal,
                "info",
                "password_not_required",
                "Password-not-required on a disabled account",
                "PASSWD_NOTREQD is set. Harmless only for as long as the account stays disabled.",
                "Clear the flag before the account is reused.",
            )
        ]
    return [
        _make(
            principal,
            "medium",
            "password_not_required",
            "Password not required",
            "PASSWD_NOTREQD is set, so this account is allowed to have an empty password.",
            "Clear the flag and set a real password.",
        )
    ]


def _admin_count(principal: Principal) -> list[Finding]:
    if not principal.admin_count or principal.high_value:
        return []
    return [
        _make(
            principal,
            "info",
            "admin_count",
            "adminCount set on an ordinary account",
            "adminCount stays set after an account leaves a protected group. "
            "AdminSDHolder may still be stamping a privileged ACL onto it.",
            "Confirm the account is meant to be ordinary. "
            "If it is, clear adminCount and check the ACL.",
        )
    ]


def _description(principal: Principal) -> list[Finding]:
    text = (principal.description or "").strip()
    if not text or not _SECRET_WORDS.search(text):
        return []
    excerpt = text if len(text) <= 240 else text[:237] + "..."
    return [
        _make(
            principal,
            "low",
            "description",
            "Description mentions a secret",
            f"The description field is carrying something it should not: {excerpt}",
            "Move the secret out of the directory. Then change it. "
            "Directories and their backups both have long memories.",
        )
    ]


def _make(
    principal: Principal,
    severity: str,
    category: str,
    title: str,
    detail: str,
    remediation: str,
) -> Finding:
    return Finding(
        severity=severity,
        category=category,
        title=title,
        principal_id=principal.object_id,
        principal_name=principal.display,
        detail=detail,
        remediation=remediation,
    )


def _delegate_labels(directory: Directory, principal: Principal) -> list[str]:
    labels: list[str] = []
    for token in principal.allowed_to_delegate:
        label = directory.label(token)
        if label not in labels:
            labels.append(label)
    return labels


def _via_sentence(principal: Principal) -> str:
    if not principal.privileged_via:
        return "The account is marked high value."
    return "The account is high value via " + _join(principal.privileged_via) + "."


def _join(items: list[str]) -> str:
    shown = items[:6]
    text = ", ".join(shown)
    extra = len(items) - len(shown)
    if extra > 0:
        text += f" (+{extra} more)"
    return text


def _is_krbtgt(principal: Principal) -> bool:
    names = {bare_name(principal.sam_account_name), bare_name(principal.name)}
    return "KRBTGT" in names


def _is_machine(principal: Principal) -> bool:
    sam = principal.sam_account_name or ""
    return principal.kind == "computer" or sam.endswith("$") or principal.name.endswith("$")
