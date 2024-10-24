<?php
require("Scanengine.php");

$scan = new Scanengine();
$scanInterval = 5;

do {

    $scan->getApacheStatus();
    $scan->checkRequests();
    sleep($scanInterval);
} while (true);
