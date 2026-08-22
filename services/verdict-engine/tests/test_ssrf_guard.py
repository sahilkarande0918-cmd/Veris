"""SSRF guard on URL/domain enrichment (pentest finding F1).

The engine connects to a subject's host to read its TLS cert. The host is
attacker-supplied, so it must refuse private/loopback/link-local/reserved
addresses before opening a socket.
"""

from app.enrich import _safe_ip, tls_certificate

INTERNAL = [
    "127.0.0.1",       # loopback
    "10.0.0.1",        # private
    "192.168.1.5",     # private
    "169.254.169.254", # link-local / cloud metadata
    "192.0.2.1",       # TEST-NET (non-routable)
    "::1",             # IPv6 loopback
    "0.0.0.0",         # unspecified
]


def test_internal_addresses_are_refused():
    for host in INTERNAL:
        assert _safe_ip(host) is None, host


def test_public_addresses_pass_and_are_pinned():
    # IP literals resolve locally (no DNS), so this is offline-safe.
    assert _safe_ip("8.8.8.8") == "8.8.8.8"
    assert _safe_ip("1.1.1.1") == "1.1.1.1"


def test_unresolvable_host_is_refused():
    assert _safe_ip("no-such-host.invalid") is None


def test_tls_certificate_skips_internal_without_connecting(monkeypatch):
    monkeypatch.delenv("VERIS_OFFLINE", raising=False)
    # An internal host returns no signal and must not raise or hang.
    assert tls_certificate("127.0.0.1") == []
    assert tls_certificate("169.254.169.254") == []
