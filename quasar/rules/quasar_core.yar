/*
 * Quasar core YARA rules — original, generic malware-indicator signatures.
 * The Quintessential Gate. Point QUASAR_YARA_RULES at an external rule repo for broader coverage.
 */

rule Process_Injection_APIs
{
    meta:
        description = "API set consistent with process injection (alloc + write + remote thread)"
        author = "The Quintessential Gate"
    strings:
        $a1 = "VirtualAllocEx" ascii
        $a2 = "WriteProcessMemory" ascii
        $a3 = "CreateRemoteThread" ascii
        $a4 = "NtUnmapViewOfSection" ascii
        $a5 = "QueueUserAPC" ascii
    condition:
        3 of ($a*)
}

rule Credential_Dumping_Indicators
{
    meta:
        description = "Strings associated with LSASS credential dumping or mimikatz"
        author = "The Quintessential Gate"
    strings:
        $s1 = "sekurlsa" ascii nocase
        $s2 = "mimikatz" ascii nocase
        $s3 = "MiniDumpWriteDump" ascii
        $s4 = "lsass.exe" ascii nocase
    condition:
        2 of them
}

rule Ransomware_Note_Markers
{
    meta:
        description = "Text commonly found in ransomware ransom notes"
        author = "The Quintessential Gate"
    strings:
        $r1 = "files have been encrypted" ascii nocase
        $r2 = "pay the ransom" ascii nocase
        $r3 = "decrypt your files" ascii nocase
        $r4 = ".locked" ascii
        $r5 = "READ_ME" ascii nocase
    condition:
        2 of them
}

rule Anti_VM_Sandbox_Checks
{
    meta:
        description = "Looks for virtual-machine or sandbox artifacts (analysis evasion)"
        author = "The Quintessential Gate"
    strings:
        $v1 = "VBoxGuest" ascii nocase
        $v2 = "VMware" ascii nocase
        $v3 = "vmtoolsd" ascii nocase
        $v4 = "SbieDll" ascii nocase
        $v5 = "qemu" ascii nocase
    condition:
        2 of them
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute cradle patterns"
        author = "The Quintessential Gate"
    strings:
        $p1 = "DownloadString" ascii nocase
        $p2 = "FromBase64String" ascii nocase
        $p3 = "Invoke-Expression" ascii nocase
        $p4 = "-nop -w hidden" ascii nocase
        $p5 = "-enc " ascii nocase
    condition:
        2 of them
}

rule UPX_Packed
{
    meta:
        description = "UPX packer section markers"
        author = "The Quintessential Gate"
    strings:
        $u1 = "UPX0" ascii
        $u2 = "UPX1" ascii
        $u3 = "UPX!" ascii
    condition:
        2 of them
}
