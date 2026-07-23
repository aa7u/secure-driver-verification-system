rule Suspicious_Kernel_Imports
{
    meta:
        description = "Detects driver importing sensitive or rarely used kernel APIs often associated with rootkits or exploitation."
        author = "SDVS Team"
        severity = "HIGH"

    strings:
        $a1 = "ZwOpenProcess" ascii wide
        $a2 = "KeInsertQueueApc" ascii wide
        $a3 = "MmMapIoSpace" ascii wide
        $a4 = "PsSetCreateProcessNotifyRoutine" ascii wide

    condition:
        2 of ($a*)
}

rule Suspicious_PDB_Path
{
    meta:
        description = "Detects PDB debugging paths associated with hacktools or exploit frameworks."
        author = "SDVS Team"
        severity = "CRITICAL"

    strings:
        $p1 = "c:\\users\\public\\" ascii nocase
        $p2 = "exploit" ascii nocase
        $p3 = "bypass" ascii nocase
        $p4 = "cheat" ascii nocase

    condition:
        any of ($p*)
}