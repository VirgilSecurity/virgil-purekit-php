<?php

$vsce_phe_php = 'vsce_phe_php';
$vscf_foundation_php = 'vscf_foundation_php';

$result = [
    'VSCE_PHE_PHP_EXTENSION' => $vsce_phe_php,
    'IS_VSCE_PHE_PHP_EXTENSION_LOADED' => extension_loaded($vsce_phe_php),
    'VSCF_FOUNDATION_PHP_EXTENSION' => $vscf_foundation_php,
    'IS_VSCF_FOUNDATION_PHP_EXTENSION_LOADED' => extension_loaded($vscf_foundation_php),
    'OS' => PHP_OS,
    'PHP' => PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION,
    'PATH_TO_EXTENSIONS_DIR' => PHP_EXTENSION_DIR,
    'PATH_TO_PHP.INI' => php_ini_loaded_file(),
];

var_dump($result);
exit();