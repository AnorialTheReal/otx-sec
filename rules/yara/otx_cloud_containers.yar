rule OTX_Linux_Docker_Socket_Abuse
{
    meta:
        description = "Detects Docker socket abuse and container escape indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "high"

    strings:
        $a = "/var/run/docker.sock"
        $b = "docker.sock"
        $c = "--privileged"
        $d = "--pid=host"
        $e = "--net=host"
        $f = "nsenter"

    condition:
        2 of them
}

rule OTX_Linux_Kubernetes_Abuse
{
    meta:
        description = "Detects Kubernetes abuse indicators"
        author = "Anorial"
        engine = "otx-native-yara"
        version = "0.1.1-alpha"
        severity = "medium"

    strings:
        $a = "kubectl exec"
        $b = "kubectl get secrets"
        $c = "serviceaccount"
        $d = "/var/run/secrets/kubernetes.io"
        $e = "hostPID"
        $f = "hostNetwork"

    condition:
        2 of them
}
