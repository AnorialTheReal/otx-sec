rule OTX_Linux_Ransomware_Indicators
{
    meta:
        description = "Detects generic Linux ransomware behavior indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "encrypt_file"
        $b = "decrypt"
        $c = "ransom"
        $d = "bitcoin"
        $e = "monero"
        $f = "payment"
        $g = "ChaCha20"
        $h = "AES"

    condition:
        3 of them
}
