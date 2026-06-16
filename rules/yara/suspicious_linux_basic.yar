rule Suspicious_Linux_Shell_Dropper
{
    meta:
        description = "Basic suspicious Linux shell/dropper strings"
        author = "OTX-Sec"
        severity = "medium"

    strings:
        $s1 = "/bin/sh" ascii nocase
        $s2 = "/bin/bash" ascii nocase
        $s3 = "chmod +x" ascii nocase
        $s4 = "wget " ascii nocase
        $s5 = "curl " ascii nocase
        $s6 = "base64" ascii nocase

    condition:
        3 of them
}
