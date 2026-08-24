"""Graph-based campaign / threat-actor correlation [SIH26106 KC4 / #8].

Given several analyzed emails, correlate them by shared infrastructure artifacts
(originating IP, ASN, X-Mailer, reply-to drop, sending relay, return-path) using
a networkx graph, cluster into campaigns (connected components), and attach a
confidence-based attribution (compromised account vs spoofed domain vs anonymized
infrastructure vs direct actor). Deterministic; the LLM is not involved.
"""

from __future__ import annotations

import re

import networkx as nx

from .email_forensics import _domain_of, originating_ip, parse_eml
from .geo import geolocate, is_tor_exit

_XMAILER = re.compile(r"^X-Mailer:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_RELAY = re.compile(r"from\s+([A-Za-z0-9._-]+)", re.IGNORECASE)
_FREEMAIL = {"gmail.com", "gmail-support.info", "yahoo.com", "outlook.com", "hotmail.com", "proton.me"}
# The artifacts strong enough that sharing one links two emails to a campaign.
_STRONG = ("originating_ip", "asn", "xmailer", "reply_to", "relay_host", "return_path")


def artifacts(raw: str | bytes) -> dict:
    """Infrastructure fingerprint of one email, for correlation."""
    msg = parse_eml(raw)
    received = msg.get_all("Received", [])
    ip = originating_ip(received)
    relay = ""
    if received:
        m = _RELAY.search(received[-1])
        relay = m.group(1).lower() if m else ""
    xm = _XMAILER.search(str(msg)) if not msg["X-Mailer"] else None
    return {
        "message_id": str(msg["Message-ID"] or "").strip("<>"),
        "from_domain": _domain_of(msg["From"]),
        "originating_ip": ip,
        "asn": (geolocate(ip) or {}).get("asn", "") if ip else "",
        "xmailer": (msg["X-Mailer"] or (xm.group(1) if xm else "")).strip(),
        "reply_to": _domain_of(msg["Reply-To"]),
        "return_path": _domain_of(msg["Return-Path"]),
        "relay_host": relay,
    }


def _attribution(shared: dict) -> tuple[str, str]:
    """(attribution_type, rationale) from the artifacts a cluster shares."""
    ip = shared.get("originating_ip")
    if ip and is_tor_exit(ip):
        return "anonymized_infrastructure", "shared TOR-exit / anonymized origin across the cluster"
    asn_org = (shared.get("asn") or "").lower()
    if any(h in asn_org for h in ("hosting", "cloud", "bulletproof")):
        return "anonymized_infrastructure", "shared bulletproof/cloud sending infrastructure"
    if shared.get("reply_to") in _FREEMAIL:
        return "spoofed_domain", "different spoofed sender domains funnelling replies to one free-mail drop"
    if shared.get("relay_host") or shared.get("return_path") or shared.get("originating_ip"):
        return "direct_actor", "reused sending infrastructure across differing spoofed senders"
    return "correlated", "shared indicators suggest a single campaign"


def correlate(raw_emails: list[str | bytes]) -> dict:
    """Cluster emails into campaigns with shared artifacts + attribution."""
    items = [artifacts(r) for r in raw_emails]

    graph = nx.Graph()
    for idx, art in enumerate(items):
        eid = ("email", art["message_id"] or f"email-{idx}")
        graph.add_node(eid, kind="email")
        for key in _STRONG:
            val = art.get(key)
            if val:
                anode = (key, val)
                graph.add_node(anode, kind="artifact")
                graph.add_edge(eid, anode)

    campaigns = []
    for comp in nx.connected_components(graph):
        emails = sorted(n[1] for n in comp if n[0] == "email")
        # artifacts that actually link >=2 emails in this component
        shared = {
            n[0]: n[1]
            for n in comp
            if n[0] != "email" and sum(1 for nb in graph.neighbors(n) if nb[0] == "email") >= 2
        }
        if len(emails) < 2:
            campaigns.append({"emails": emails, "size": len(emails), "shared_artifacts": {}, "attribution": "singleton", "rationale": "no shared infrastructure with other emails", "confidence": 0.0})
            continue
        attribution, rationale = _attribution(shared)
        # confidence grows with the number of distinct strong artifacts shared.
        confidence = round(min(0.99, 0.45 + 0.13 * len(shared)), 2)
        campaigns.append(
            {
                "emails": emails,
                "size": len(emails),
                "shared_artifacts": shared,
                "attribution": attribution,
                "rationale": rationale,
                "confidence": confidence,
            }
        )

    campaigns.sort(key=lambda c: -c["size"])
    return {
        "email_count": len(items),
        "campaign_count": sum(1 for c in campaigns if c["size"] >= 2),
        "campaigns": campaigns,
    }
