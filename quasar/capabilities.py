"""Capability detection: map imports + strings to behaviors, each tied to a MITRE ATT&CK
technique. This is Quasar's "insight" layer — every hit carries the concrete evidence that
produced it, so nothing is a black-box guess.

A rule fires when enough of its import names are present OR any of its string patterns match.
Weights feed the transparent score in score.py.
"""
from __future__ import annotations
import re

# id, name, (ATT&CK id, name), weight, imports[], min_imports, strings[](regex), description
RULES = [
    dict(id="proc-injection", name="Process injection", attck=("T1055", "Process Injection"),
         weight=22, min_imports=2,
         imports=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
                  "QueueUserAPC", "NtWriteVirtualMemory", "RtlCreateUserThread", "SetThreadContext"],
         strings=[],
         desc="Allocates and writes code into another process and runs it there."),
    dict(id="dynamic-api", name="Dynamic API resolution", attck=("T1027", "Obfuscated Files or Information"),
         weight=10, min_imports=2, imports=["LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll"],
         strings=[], desc="Resolves API calls at runtime to hide its intentions from static tools."),
    dict(id="persist-run", name="Persistence (registry Run key)", attck=("T1547.001", "Registry Run Keys"),
         weight=18, min_imports=1, imports=["RegSetValueEx", "RegCreateKeyEx"],
         strings=[r"\\CurrentVersion\\Run", r"\\CurrentVersion\\RunOnce"],
         desc="Installs itself to auto-start via a registry Run key."),
    dict(id="persist-service", name="Persistence (service)", attck=("T1543.003", "Windows Service"),
         weight=16, min_imports=2, imports=["OpenSCManager", "CreateService", "StartService", "ChangeServiceConfig"],
         strings=[], desc="Installs or alters a Windows service to persist."),
    dict(id="persist-schtask", name="Persistence (scheduled task)", attck=("T1053.005", "Scheduled Task"),
         weight=14, min_imports=1, imports=["ITaskScheduler", "ITaskService"],
         strings=[r"\bschtasks\b", r"\\Tasks\\"], desc="Creates a scheduled task to persist or run later."),
    dict(id="anti-debug", name="Anti-debugging", attck=("T1622", "Debugger Evasion"),
         weight=10, min_imports=1,
         imports=["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString"],
         strings=[], desc="Checks whether it is being debugged and may change behavior to evade analysis."),
    dict(id="anti-vm", name="Anti-VM / sandbox evasion", attck=("T1497", "Virtualization/Sandbox Evasion"),
         weight=12, min_imports=0, imports=[],
         strings=[r"\bVBox", r"VMware", r"vmtoolsd", r"\bqemu\b", r"SbieDll", r"\bwine_get"],
         desc="Looks for virtual-machine or sandbox artifacts to avoid running under analysis."),
    dict(id="keylog", name="Keylogging", attck=("T1056.001", "Keylogging"),
         weight=20, min_imports=1, imports=["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState"],
         strings=[], desc="Captures keystrokes."),
    dict(id="screen-capture", name="Screen capture", attck=("T1113", "Screen Capture"),
         weight=12, min_imports=2, imports=["BitBlt", "GetDC", "CreateCompatibleBitmap", "GetDesktopWindow"],
         strings=[], desc="Captures the screen."),
    dict(id="clipboard", name="Clipboard access", attck=("T1115", "Clipboard Data"),
         weight=8, min_imports=1, imports=["GetClipboardData", "OpenClipboard"],
         strings=[], desc="Reads clipboard contents (often to steal wallet addresses / credentials)."),
    dict(id="cred-lsass", name="Credential access (LSASS)", attck=("T1003.001", "LSASS Memory"),
         weight=24, min_imports=1, imports=["MiniDumpWriteDump"],
         strings=[r"\blsass(?:\.exe)?\b", r"\bsekurlsa\b", r"\bmimikatz\b"],
         desc="Targets LSASS or known credential-dumping tooling to steal credentials."),
    dict(id="token-priv", name="Privilege / token manipulation", attck=("T1134", "Access Token Manipulation"),
         weight=12, min_imports=1, imports=["AdjustTokenPrivileges", "OpenProcessToken", "DuplicateTokenEx"],
         strings=[r"SeDebugPrivilege"], desc="Adjusts process privileges or steals access tokens."),
    dict(id="exec-shell", name="Command / script execution", attck=("T1059", "Command and Scripting Interpreter"),
         weight=14, min_imports=1, imports=["ShellExecuteA", "ShellExecuteW", "WinExec", "CreateProcess"],
         strings=[r"cmd(?:\.exe)?\s*/c", r"powershell", r"WScript\.Shell", r"\bwscript\b", r"\bcscript\b"],
         desc="Launches a shell, PowerShell, or another process to run commands."),
    dict(id="c2-network", name="Network / C2 communication", attck=("T1071", "Application Layer Protocol"),
         weight=16, min_imports=2,
         imports=["InternetOpen", "InternetConnect", "HttpSendRequest", "HttpOpenRequest", "WinHttpOpen",
                  "WinHttpConnect", "connect", "send", "recv", "WSAStartup", "getaddrinfo"],
         strings=[r"User-Agent:", r"\bPOST\b\s+/", r"\.onion\b"],
         desc="Communicates over the network, consistent with command-and-control or exfiltration."),
    dict(id="download-exec", name="Download & execute", attck=("T1105", "Ingress Tool Transfer"),
         weight=18, min_imports=1, imports=["URLDownloadToFile", "URLDownloadToCacheFile"],
         strings=[], desc="Downloads a payload from the network and runs it."),
    dict(id="ransom-crypto", name="Bulk encryption (ransomware-like)", attck=("T1486", "Data Encrypted for Impact"),
         weight=22, min_imports=2,
         imports=["CryptEncrypt", "CryptGenKey", "CryptAcquireContext", "CryptImportKey", "BCryptEncrypt"],
         strings=[r"\.locked\b", r"\bransom", r"your files (?:have been|are) encrypted", r"README.*DECRYPT"],
         desc="Encrypts files in bulk, consistent with ransomware."),
    dict(id="file-discovery", name="File / directory discovery", attck=("T1083", "File and Directory Discovery"),
         weight=6, min_imports=2, imports=["FindFirstFile", "FindNextFile", "GetLogicalDrives"],
         strings=[], desc="Enumerates files and directories, often to find targets or data."),
    dict(id="rwx-shellcode", name="Executable memory allocation", attck=("T1055", "Process Injection"),
         weight=10, min_imports=2, imports=["VirtualAlloc", "VirtualProtect"],
         strings=[], desc="Allocates/flips memory to executable, typical of unpacking or shellcode."),
]


def evaluate(import_names: list[str], strings_text: str) -> list[dict]:
    imps = [i.lower() for i in import_names]
    out = []
    for r in RULES:
        ev_imports, ev_strings = [], []
        for name in r["imports"]:
            if any(name.lower() in imp for imp in imps):
                ev_imports.append(name)
        for pat in r["strings"]:
            m = re.search(pat, strings_text, re.I)
            if m:
                ev_strings.append(m.group(0)[:80].strip())
        imp_ok = bool(r["imports"]) and len(ev_imports) >= r["min_imports"]
        str_ok = bool(r["strings"]) and len(ev_strings) >= 1
        if imp_ok or str_ok:
            evidence = [f"import:{e}" for e in ev_imports] + [f"string:{e!r}" for e in ev_strings]
            out.append({
                "id": r["id"], "name": r["name"], "attck_id": r["attck"][0], "attck_name": r["attck"][1],
                "weight": r["weight"], "description": r["desc"], "evidence": evidence[:6],
            })
    return out
