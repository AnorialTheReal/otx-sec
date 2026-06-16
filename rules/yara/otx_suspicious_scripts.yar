rule OTX_Suspicious_Shell_Loader
{
    meta:
        description = "Detects suspicious shell loader patterns"
        author = "OTX-Sec"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"

    strings:
        $sh1 = "/bin/sh"
        $sh2 = "chmod +x"
        $sh3 = "curl "
        $sh4 = "wget "
        $sh5 = "base64"
        $sh6 = "eval "

    condition:
        3 of them
}

rule OTX_Reverse_Shell_Indicators
{
    meta:
        description = "Detects common reverse shell indicators"
        author = "OTX-Sec"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"

    strings:
        $a = "bash -i"
        $b = "/dev/tcp/"
        $c = "nc -e"
        $d = "ncat"
        $e = "python -c"
        $f = "socket"

    condition:
        2 of them
}

rule OTX_PowerShell_Loader
{
    meta:
        description = "Detects suspicious PowerShell loader behavior"
        author = "OTX-Sec"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"

    strings:
        $p1 = "powershell"
        $p2 = "-enc"
        $p3 = "FromBase64String"
        $p4 = "IEX"
        $p5 = "DownloadString"

    condition:
        2 of them
}
