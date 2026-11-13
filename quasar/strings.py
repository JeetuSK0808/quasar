"""String + indicator-of-compromise (IOC) extraction. Pure parsing, no network, no execution."""
from __future__ import annotations
import re

_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

# IOC patterns. Each is (name, compiled regex). Matched against decoded strings only.
_IOC_PATTERNS = {
    "urls": re.compile(r"\bhttps?://[^\s\"'<>\\)]{4,}", re.I),
    "ips": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "emails": re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    "domains": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|info|biz|io|xyz|top|club|online|site|top|su|tk|ml|ga|cf|gq|pw)\b", re.I),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"']{3,}", re.I),
    "win_paths": re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|*?]{3,}"),
    "env_paths": re.compile(r"%[A-Za-z_]+%\\?[^\s\"'<>|*?]*"),
    "bitcoin": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
}

# Domains that are almost always benign noise in binaries (reduce false IOCs).
_DOMAIN_NOISE = re.compile(r"(microsoft\.com|windows\.com|w3\.org|schemas\.|verisign\.com|digicert\.com|example\.com|symantec\.com|msn\.com)$", re.I)

_CAP = 60  # max IOCs kept per category


def extract_strings(data: bytes) -> list[str]:
    out = []
    for m in _ASCII.finditer(data):
        out.append(m.group().decode("latin-1", "replace"))
    for m in _UTF16.finditer(data):
        out.append(m.group().decode("utf-16-le", "replace"))
    return out


def extract_iocs(strings_text: str) -> dict[str, list[str]]:
    iocs: dict[str, list[str]] = {}
    for name, rx in _IOC_PATTERNS.items():
        seen, found = set(), []
        for m in rx.finditer(strings_text):
            val = m.group(0).rstrip(".,);]")
            if name == "ips":
                a = val.split(".")[0]
                if a in ("0", "127", "255") or val.startswith(("1.0.", "0.")):
                    continue  # drop obvious non-C2 noise
            if name == "domains" and _DOMAIN_NOISE.search(val):
                continue
            key = val.lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(val)
            if len(found) >= _CAP:
                break
        if found:
            iocs[name] = found
    return iocs
