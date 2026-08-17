"""Replace the seed blocklist snapshots in fixtures/ with live upstream feeds.

Run this when you have network. Veris never calls it at verdict time -- the
whole point of the local snapshots is that a demo works with the wifi off.

    python scripts/refresh_blocklists.py

Some feeds now require a free account key (abuse.ch moved to authenticated
downloads, and PhishTank issues per-application keys). Where a key is missing
or the download looks wrong, the existing snapshot is LEFT ALONE rather than
overwritten with an error page -- a corrupted blocklist would silently break
every verdict.
"""

import os
import sys
from pathlib import Path

import httpx

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "blocklists"

FEEDS = {
    "openphish.txt": ("https://openphish.com/feed.txt", None),
    "urlhaus.txt": ("https://urlhaus.abuse.ch/downloads/text_online/", "ABUSE_CH_AUTH_KEY"),
    "phishtank.txt": ("http://data.phishtank.com/data/online-valid.csv", "PHISHTANK_APP_KEY"),
}

# Below this, the response is almost certainly an error page or a login wall.
MIN_PLAUSIBLE_LINES = 20


def looks_like_a_feed(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    return len(lines) >= MIN_PLAUSIBLE_LINES and "<html" not in text[:2000].lower()


def refresh(filename: str, url: str, key_env: str | None) -> bool:
    headers = {}
    if key_env:
        key = os.getenv(key_env)
        if not key:
            print(f"  SKIP {filename}: set {key_env} to refresh this feed")
            return False
        headers["Auth-Key"] = key

    try:
        response = httpx.get(url, headers=headers, timeout=60.0, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"  FAIL {filename}: {exc}")
        return False

    if not looks_like_a_feed(response.text):
        print(f"  FAIL {filename}: response did not look like a feed; snapshot kept")
        return False

    target = FIXTURES / filename
    header = f"# Refreshed from {url}\n"
    target.write_text(header + response.text, encoding="utf-8")
    print(f"  OK   {filename}: {len(response.text.splitlines())} lines")
    return True


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    print(f"Refreshing blocklists into {FIXTURES}")
    results = [refresh(name, url, key) for name, (url, key) in FEEDS.items()]
    print(f"\n{sum(results)}/{len(results)} feeds refreshed.")
    # Not an error: the seed snapshots still work offline, which is the point.
    return 0


if __name__ == "__main__":
    sys.exit(main())
