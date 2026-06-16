rule OTX_Linux_SSH_Backdoor
{
    meta:
        description = "Detects suspicious SSH backdoor and authorized_keys manipulation indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = ".ssh/authorized_keys"
        $b = "ssh-rsa"
        $c = "PermitRootLogin"
        $d = "PasswordAuthentication yes"
        $e = "/etc/ssh/sshd_config"

    condition:
        2 of them
}

rule OTX_Linux_Credential_Access
{
    meta:
        description = "Detects Linux credential access indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "/etc/shadow"
        $b = "/etc/passwd"
        $c = ".bash_history"
        $d = "id_rsa"
        $e = "known_hosts"
        $f = "sudo -l"

    condition:
        2 of them
}

rule OTX_Linux_Crypto_Miner_Indicators
{
    meta:
        description = "Detects common Linux crypto miner indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "stratum+tcp"
        $b = "xmr"
        $c = "monero"
        $d = "xmrig"
        $e = "minerd"
        $f = "cryptonight"

    condition:
        2 of them
}

rule OTX_Linux_Tmp_Dropper
{
    meta:
        description = "Detects suspicious Linux temporary directory dropper behavior"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "medium"

    strings:
        $a = "/tmp/"
        $b = "/dev/shm/"
        $c = "chmod +x"
        $d = "curl "
        $e = "wget "
        $f = "bash"

    condition:
        3 of them
}

rule OTX_Linux_Systemd_Persistence
{
    meta:
        description = "Detects suspicious Linux systemd persistence indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "[Service]"
        $b = "ExecStart="
        $c = "WantedBy=multi-user.target"
        $d = "systemctl enable"
        $e = "/etc/systemd/system/"

    condition:
        3 of them
}

rule OTX_Linux_History_Cleanup
{
    meta:
        description = "Detects Linux shell history cleanup indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "medium"

    strings:
        $a = "history -c"
        $b = "unset HISTFILE"
        $c = "rm ~/.bash_history"
        $d = "cat /dev/null > ~/.bash_history"

    condition:
        1 of them
}
