"""Smoke tests for Quasar. No real malware involved — a crafted strings blob exercises the generic
path, synthetic import lists exercise the capability engine, and a hand-built minimal PE exercises
the PE parser."""
import struct
import tempfile
import os

from quasar import analyze
from quasar import capabilities, pe as pe_mod


def _minimal_pe() -> bytes:
    """A minimal but valid PE32 (DOS header + PE + optional header + one .text section)."""
    # DOS header: 'MZ', e_lfanew at 0x3C -> 0x40
    dos = b"MZ" + b"\x00" * 58
    dos = dos[:0x3C] + struct.pack("<I", 0x40) + dos[0x40:]
    dos = dos.ljust(0x40, b"\x00")

    pe_sig = b"PE\x00\x00"
    file_hdr = struct.pack("<HHIIIHH",
                           0x14C,   # Machine i386
                           1,       # NumberOfSections
                           0, 0, 0, # TimeDateStamp, PtrToSymTab, NumSyms
                           0xE0,    # SizeOfOptionalHeader (224)
                           0x102)   # Characteristics: EXECUTABLE | 32BIT

    opt_fixed = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,        # Magic PE32
        0, 0,         # linker versions
        0x200, 0, 0,  # SizeOfCode, InitData, UninitData
        0x1000,       # AddressOfEntryPoint
        0x1000, 0x2000,   # BaseOfCode, BaseOfData
        0x400000,     # ImageBase
        0x1000, 0x200,    # Section/File alignment
        4, 0, 0, 0, 4, 0, # OS/Image/Subsystem versions
        0,            # Win32VersionValue
        0x3000,       # SizeOfImage
        0x200,        # SizeOfHeaders
        0,            # CheckSum
        3, 0,         # Subsystem CONSOLE, DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,  # stack/heap
        0,            # LoaderFlags
        16)           # NumberOfRvaAndSizes
    opt = opt_fixed + b"\x00" * (16 * 8)  # 16 empty data directories

    section = struct.pack("<8sIIIIIIHHI",
                          b".text\x00\x00\x00",
                          0x200,       # VirtualSize
                          0x1000,      # VirtualAddress
                          0x200,       # SizeOfRawData
                          0x200,       # PointerToRawData
                          0, 0, 0, 0,  # relocs/linenums
                          0x60000020)  # CODE | EXECUTE | READ

    headers = dos + pe_sig + file_hdr + opt + section
    headers = headers.ljust(0x200, b"\x00")
    body = b"\x90" * 0x200  # NOP-filled .text
    return headers + body


def test_minimal_pe_parses():
    info = pe_mod.parse_pe(_minimal_pe())
    assert info is not None, "minimal PE should parse"
    assert any(s["name"].startswith(".text") for s in info["sections"])
    assert "imphash" in info


def test_capability_engine_on_synthetic_imports():
    imports = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
               "IsDebuggerPresent", "InternetOpenA", "HttpSendRequestA"]
    caps = capabilities.evaluate(imports, "")
    ids = {c["id"] for c in caps}
    assert "proc-injection" in ids
    assert "anti-debug" in ids
    assert "c2-network" in ids
    inj = next(c for c in caps if c["id"] == "proc-injection")
    assert inj["attck_id"] == "T1055"
    assert inj["evidence"], "capability must carry evidence"


def test_analyze_generic_file():
    blob = (b"this program cannot be run in dos mode\n"
            b"http://evil.example.ru/gate.php\n"
            b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            b"powershell -enc ZQBj\n"
            b"your files have been encrypted, send bitcoin\n"
            b"C:\\Windows\\Temp\\payload.exe\n") * 3
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as fh:
        fh.write(blob)
        path = fh.name
    try:
        rep = analyze(path)
        assert rep["file"]["sha256"]
        assert rep["iocs"].get("urls")
        assert rep["iocs"].get("registry")
        ids = {c["id"] for c in rep["capabilities"]}
        assert "exec-shell" in ids       # powershell
        assert "ransom-crypto" in ids    # encrypted + bitcoin
        assert rep["score"]["score"] > 0
        assert rep["summary"]
    finally:
        os.unlink(path)
