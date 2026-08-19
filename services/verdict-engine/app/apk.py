"""APK static analysis. [Phase 5, point-of-attack]

The Indian fake-loan-app pattern, in one paragraph: an app promises instant
cash, asks for contacts and SMS on install, uploads both, disburses a small
amount, then threatens to message the victim's entire contact list. The
extortion is built into the permission set, which means it is visible before
the app is ever opened -- and a permission list is a fact, not an opinion, so
it fits the deterministic rule exactly.

Runs fully offline with a pure-Python parser. MobSF is optional enrichment
(see `mobsf_findings`) and is never required: a 2 GB container must not stand
between a victim and a verdict.
"""

import hashlib
import json
import os
from pathlib import Path

import httpx
from pyaxmlparser import APK
from verdict import Signal

# Permissions that carry real fraud weight, and why. The `why` text is shown
# to the user, so it says what the permission enables, not what it is called.
DANGEROUS = {
    "android.permission.READ_SMS": (35, "can read your SMS, including bank OTPs"),
    "android.permission.RECEIVE_SMS": (30, "can intercept incoming SMS as they arrive"),
    "android.permission.READ_CONTACTS": (35, "can copy your whole contact list"),
    "android.permission.READ_CALL_LOG": (25, "can read who you call and when"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (30, "can install further apps"),
    "android.permission.SYSTEM_ALERT_WINDOW": (25, "can draw over other apps, including your bank's"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (40, "can read and control the whole screen"),
    "android.permission.READ_EXTERNAL_STORAGE": (15, "can read your photos and files"),
    "android.permission.RECORD_AUDIO": (20, "can record audio"),
    "android.permission.CAMERA": (15, "can use the camera"),
    "android.permission.ACCESS_FINE_LOCATION": (15, "can track your precise location"),
}

# The extortion kit. Either pairing is the fake-loan-app signature, and is
# worth more together than the sum of its parts.
COMBINATIONS = [
    (
        {"android.permission.READ_CONTACTS", "android.permission.READ_SMS"},
        45,
        "requests contacts AND SMS together -- the combination used to harvest a "
        "contact list and intercept bank OTPs, which is the fake-loan-app pattern",
    ),
    (
        {"android.permission.READ_CONTACTS", "android.permission.REQUEST_INSTALL_PACKAGES"},
        30,
        "can read your contacts and install more apps without the Play Store",
    ),
]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mobsf_findings(path: Path) -> list[Signal]:
    """Optional MobSF enrichment. Returns [] unless MOBSF_URL and a key are set.

    Deliberately never required: the offline permission analysis above already
    produces a citable verdict, and the demo must not depend on a container.
    """
    from .enrich import is_offline

    base, key = os.getenv("MOBSF_URL"), os.getenv("MOBSF_API_KEY")
    if not base or not key or is_offline():
        return []

    try:
        with path.open("rb") as handle:
            upload = httpx.post(
                f"{base.rstrip('/')}/api/v1/upload",
                headers={"Authorization": key},
                files={"file": (path.name, handle, "application/vnd.android.package-archive")},
                timeout=120.0,
            )
        upload.raise_for_status()
        scan_hash = upload.json()["hash"]

        report = httpx.post(
            f"{base.rstrip('/')}/api/v1/report_json",
            headers={"Authorization": key},
            data={"hash": scan_hash},
            timeout=300.0,
        )
        report.raise_for_status()
        data = report.json()
    except (httpx.HTTPError, KeyError, json.JSONDecodeError):
        return []

    score = data.get("appsec", {}).get("security_score")
    if score is None:
        return []
    return [
        Signal(
            id="mobsf_security_score",
            source="MobSF static analysis",
            value=f"MobSF security score {score}/100",
            weight=30 if score < 40 else 0,
        )
    ]


def analyze(path: str | Path) -> tuple[list[Signal], dict]:
    """Static analysis of one APK. Returns (signals, metadata)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"no such APK: {path}")

    file_hash = sha256_of(path)
    signals: list[Signal] = [
        Signal(
            id="apk_sha256",
            source="SHA-256 of the file as supplied",
            value=file_hash,
            weight=0,  # identity, not evidence of wrongdoing
        )
    ]

    try:
        apk = APK(str(path))
        package, version = apk.package, apk.version_name
        permissions = set(apk.permissions)
    except Exception as exc:  # noqa: BLE001 - a malformed APK is itself a finding
        signals.append(
            Signal(
                id="apk_unparseable",
                source="pyaxmlparser (static manifest parse)",
                value=f"the manifest could not be parsed: {type(exc).__name__}",
                weight=30,
            )
        )
        return signals, {"sha256": file_hash, "package": None, "permissions": []}

    signals.append(
        Signal(
            id="apk_identity",
            source="APK manifest (static parse, app not installed or run)",
            value=f"package {package}, version {version}",
            weight=0,
        )
    )

    for permission in sorted(permissions):
        if permission in DANGEROUS:
            weight, why = DANGEROUS[permission]
            signals.append(
                Signal(
                    id=f"apk_permission:{permission.rsplit('.', 1)[-1].lower()}",
                    source="APK manifest declared permissions",
                    value=f"{permission.rsplit('.', 1)[-1]} -- {why}",
                    weight=weight,
                )
            )

    for required, weight, why in COMBINATIONS:
        if required.issubset(permissions):
            signals.append(
                Signal(
                    id="apk_permission_combination",
                    source="APK manifest declared permissions (combination)",
                    value=why,
                    weight=weight,
                )
            )

    signals += mobsf_findings(path)
    return signals, {
        "sha256": file_hash,
        "package": package,
        "version": version,
        "permissions": sorted(permissions),
        "dangerous_count": sum(1 for p in permissions if p in DANGEROUS),
    }
