<?php

const VSCF_FOUNDATION_PHP = "vscf_foundation_php";
const VSCE_PHE_PHP = "vsce_phe_php";
const VSCP_PYTHIA_PHP = "vscp_pythia_php";
const VSCR_RATCHET_PHP = "vscr_ratchet_php";

const EXT_LIST = [VSCF_FOUNDATION_PHP, VSCE_PHE_PHP, VSCP_PYTHIA_PHP, VSCR_RATCHET_PHP];

function getScannedIniDir()
{

    $res = null;
    $rawData = php_ini_scanned_files();

    if ($rawData)
        $res = explode(",", $rawData);

    return pathinfo($res[0], PATHINFO_DIRNAME);
}

$extArr = [];

foreach (EXT_LIST as $ext) {
    $extArr[] = [
        'name' => $ext,
        'version' => phpversion($ext),
        'is_extension_loaded' => extension_loaded($ext),
    ];
}

$config = [
    'OS' => PHP_OS,
    'PHP_VERSION' => PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION,
    'PATH_TO_EXTENSIONS_DIR' => PHP_EXTENSION_DIR,
    'PATH_TO_MAIN_PHP.INI' => php_ini_loaded_file(),
    'PATH_TO_ADDITIONAL_INI_FILES' => getScannedIniDir(),
];

echo '<pre>', var_dump($extArr, $config), '</pre>';

exit(1);