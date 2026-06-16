rule OTX_Linux_Credential_Dumping
{
    meta:
        description = "Detects Linux credential dumping indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "/etc/shadow"
        $b = "/etc/passwd"
        $c = "unshadow"
        $d = "john "
        $e = "hashcat"
        $f = "id_rsa"
        $g = ".ssh/"

    condition:
        2 of them
}

rule OTX_Linux_SSH_Key_Harvesting
{
    meta:
        description = "Detects SSH key harvesting indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "id_rsa"
        $b = "id_ed25519"
        $c = "known_hosts"
        $d = ".ssh/config"
        $e = ".ssh/authorized_keys"

    condition:
        2 of them
}
