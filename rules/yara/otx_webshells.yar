rule OTX_Linux_Webshell_PHP
{
    meta:
        description = "Detects common PHP webshell execution patterns"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "base64_decode("
        $b = "shell_exec("
        $c = "passthru("
        $d = "system("
        $e = "eval("
        $f = "$_POST"
        $g = "$_GET"

    condition:
        3 of them
}

rule OTX_Linux_Webshell_Command_Exec
{
    meta:
        description = "Detects generic webshell command execution indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "cmd="
        $b = "exec("
        $c = "system("
        $d = "shell_exec("
        $e = "whoami"
        $f = "uname -a"

    condition:
        3 of them
}
