rule OTX_Linux_Lateral_Movement_Tools
{
    meta:
        description = "Detects Linux lateral movement tool usage"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "medium"

    strings:
        $a = "sshpass"
        $b = "scp "
        $c = "rsync "
        $d = "proxychains"
        $e = "socat"
        $f = "chisel"

    condition:
        2 of them
}

rule OTX_Linux_Tunnel_Proxy_Indicators
{
    meta:
        description = "Detects Linux tunneling and proxy indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "medium"

    strings:
        $a = "socks5"
        $b = "reverse tunnel"
        $c = "-D 1080"
        $d = "ssh -R"
        $e = "ssh -L"
        $f = "proxychains"

    condition:
        2 of them
}
