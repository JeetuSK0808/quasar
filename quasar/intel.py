"""Threat-intel correlation.

v0 is OFFLINE by default and sends nothing anywhere. A privacy-safe online mode can be added
later: it would look up the sample's *hash* and its network *IOCs* against free abuse.ch feeds
(MalwareBazaar / ThreatFox) — sending only a hash or an indicator, never the sample itself.
That mode needs a free abuse.ch account/key, which is the operator's to create, so it stays
unwired here rather than shipping a disabled network call.
"""
from __future__ import annotations
import os


def lookup(sha256: str, iocs: dict, enabled: bool = False) -> dict:
    if not enabled:
        return {"mode": "offline",
                "note": "No external lookups performed (privacy-safe default)."}
    if not os.environ.get("QUASAR_ABUSECH_KEY"):
        return {"mode": "online-unconfigured",
                "note": "Set QUASAR_ABUSECH_KEY (free abuse.ch account) to enable hash/IOC lookups."}
    # Reserved for the online implementation (hash + IOC reputation via abuse.ch).
    return {"mode": "online", "note": "Online intel lookups not yet implemented in this build."}
