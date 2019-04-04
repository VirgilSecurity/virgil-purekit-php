<?php

$extension = 'vsce_phe_php';

$result = [
    'EXTENSION_NAME' => $extension,
    'OS' => PHP_OS,
    'PHP' => PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION,
    'PATH_TO_EXTENSION_DIR' => PHP_EXTENSION_DIR,
    'PATH_TO_PHP.INI' => php_ini_loaded_file(),
    'IS_EXTENSION_LOADED' => extension_loaded($extension),
];

var_dump($result);
exit();
