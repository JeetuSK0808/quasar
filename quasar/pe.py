"""Static PE parsing for Quasar. Reads structure only — never executes the sample."""
from __future__ import annotations
import math
from collections import Counter

try:
    import pefile
except ImportError:  # pragma: no cover - dependency guard
    pefile = None

RWX = 0x20000000 | 0x40000000 | 0x80000000  # EXECUTE | READ | WRITE section flags


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). High (>7.2) suggests packing/encryption."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def file_type(data: bytes) -> str:
    """Cheap magic-byte file-type guess (deep analysis in v0 is PE-focused)."""
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:2] == b"PK":
        return "zip/office"
    if data[:4] == b"\xd0\xcf\x11\xe0":
        return "ole/office"
    if data[:2] == b"#!":
        return "script"
    return "unknown"


def parse_pe(data: bytes) -> dict | None:
    """Parse a PE image. Returns a structured dict, or None if it isn't a parseable PE."""
    if pefile is None or data[:2] != b"MZ":
        return None
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception:
        return None

    info: dict = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "subsystem": int(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)),
        "entry_point": hex(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)),
        "imphash": "",
        "sections": [],
        "imports": [],          # ["KERNEL32.dll!VirtualAllocEx", ...]
        "import_names": [],      # bare function names for capability matching
        "exports": [],
        "has_tls_callbacks": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
        "signed": hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
                  and bool(getattr(pe, "DIRECTORY_ENTRY_SECURITY", None)),
    }

    try:
        info["imphash"] = pe.get_imphash()
    except Exception:
        info["imphash"] = ""

    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        info["sections"].append({
            "name": name,
            "vsize": int(s.Misc_VirtualSize),
            "rawsize": int(s.SizeOfRawData),
            "entropy": round(s.get_entropy(), 2),
            "rwx": bool((s.Characteristics & RWX) == RWX),
            "executable": bool(s.Characteristics & 0x20000000),
        })

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b"").decode("latin-1", "replace")
            for imp in entry.imports:
                fn = imp.name.decode("latin-1", "replace") if imp.name else f"ordinal_{imp.ordinal}"
                info["imports"].append(f"{dll}!{fn}")
                info["import_names"].append(fn)

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                info["exports"].append(exp.name.decode("latin-1", "replace"))

    pe.close()
    return info
