rule OTX_Base64_Execution_Linux
{
    meta:
        description = "Detects Linux base64 decode and execution behavior"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "base64 -d"
        $b = "base64 --decode"
        $c = "eval "
        $d = "eval("
        $e = "bash -c"
        $f = "sh -c"

    condition:
        2 of them
}

rule OTX_Linux_Persistence_Cron
{
    meta:
        description = "Detects Linux cron based persistence indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "medium"

    strings:
        $a = "crontab"
        $b = "/etc/cron"
        $c = "@reboot"
        $d = "systemctl enable"
        $e = ".bashrc"
        $f = ".profile"

    condition:
        2 of them
}

rule OTX_Linux_Reverse_Shell
{
    meta:
        description = "Detects Linux reverse shell indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "bash -i"
        $b = "/dev/tcp/"
        $c = "nc -e"
        $d = "ncat"
        $e = "/bin/sh"
        $f = "python -c"

    condition:
        2 of them
}

rule OTX_LD_PRELOAD_Hijack
{
    meta:
        description = "Detects LD_PRELOAD hijacking indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "LD_PRELOAD"
        $b = "/etc/ld.so.preload"
        $c = ".so"
        $d = "__attribute__((constructor))"

    condition:
        2 of them
}

rule OTX_Suspicious_Linux_Downloader
{
    meta:
        description = "Detects suspicious Linux downloader behavior"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "medium"

    strings:
        $a = "curl "
        $b = "wget "
        $c = "chmod +x"
        $d = "/tmp/"
        $e = "bash"

    condition:
        3 of them
}
