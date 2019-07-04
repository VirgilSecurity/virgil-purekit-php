<?php

require_once 'vendor/autoload.php';

use Dotenv\Dotenv;
use Virgil\CryptoImpl\VirgilCrypto;
use Virgil\PureKit\Protocol\Protocol;
use Virgil\PureKit\Protocol\ProtocolContext;
use Virgil\PureKit\Core\PHE;

try {
    printf("Starting enroll...\n");

    // MAIN CONFIGURATION

    $userTableExample = 'user_table.json';
    $mainTableExample = 'main_table.json';

    $recoveryPrivateKeyFile = "recovery_private_key.pem";

    $virgilCrypto = new VirgilCrypto();
    $phe = new PHE();

    // INITIALIZE PUREKIT

    // Set here your PureKit credentials
    $env = (new Dotenv(".", ".env"))->load();

    $context = (new ProtocolContext)->create([
        'appSecretKey' => $_ENV['APP_SECRET_KEY'],
        'appToken' => $_ENV['APP_TOKEN'],
        'servicePublicKey' => $_ENV['SERVICE_PUBLIC_KEY'],
        'updateToken' => '' // needs to be empty
    ]);

    $protocol = new Protocol($context);

    // LOAD DATABASE

    $userTableString = file_get_contents($userTableExample);
    $userTable = json_decode($userTableString);

    $mainTableString = file_get_contents($mainTableExample);
    $mainTable = json_decode($mainTableString);

    // GENERATE AND STORE RECOVERY KEYS

    printf("Generating Recovery Keys\n");

    // This part should be done only once -->
    $keyPair = $virgilCrypto->generateKeys();
    $privateKey = $keyPair->getPrivateKey();
    $publicKey = $keyPair->getPublicKey();

    // Store exported keys:
    $privateKeyExported = $virgilCrypto->exportPrivateKey($privateKey);
    $publicKeyExported = $virgilCrypto->exportPublicKey($publicKey);
    // <-- This part should be done only once

    // Convert to PEM only for this sample
    $privateKeyPEM = VirgilKeyPair::privateKeyToPEM($privateKeyExported);

    printf("Storing Recovery Private Key to the $recoveryPrivateKeyFile file\n");

    $fp = fopen('recovery_private_key.pem', 'w');
    fwrite($fp, $privateKeyPEM);
    fclose($fp);

    printf("Storing Recovery Public Key to the main_table.json\n");
    $publicKeyPEM = VirgilKeyPair::publicKeyToPEM($publicKeyExported);

    $mainTable[0]->recovery_public_key = $publicKeyPEM;

    // ENROLL AND ENCRYPT USER ACCOUNTS

    foreach ($userTable as $user) {
        printf("Enrolling user '%s'\n", $user->username);

        // Ideally, you'll ask for users to create a new password, but
        // for this guide, we'll use existing password in DB
        $enroll = $protocol->enrollAccount($user->passwordHash);

        // Save record to database
        $user->record = base64_encode($enroll[0]);

        // Use encryptionKey for protecting user data & save in database
        $encryptionKey = $enroll[1];
        $user->ssn = base64_encode($phe->encrypt($user->ssn, $encryptionKey));

        // Import keys:
        $publicKeyImported = $virgilCrypto->importPublicKey($publicKeyPEM);

        $encrypted = $virgilCrypto->encrypt($user->passwordHash, [$publicKeyImported]);
        $user->encrypted = base64_encode($encrypted);

        // Deprecate existing user password field & save in database
        $user->passwordHash = "";

        print_r($user);
        printf("\n");
    }

    // SAVE TO DATABASE

    $database = [
        $userTableExample => $userTable,
        $mainTableExample => $mainTable,
    ];

    foreach ($database as $table => $file) {
        $fp = fopen($table, 'w');
        fwrite($fp, json_encode($file));
        fclose($fp);
    }

    // VERIFY PASSWORD

    $password = "80815C001";
    $record = base64_decode($userTable[0]->record);

    $encryptionKey = $protocol->verifyPassword($password, $record);

    // ENCRYPT AND DECRYPT DATA

    $homeAddress = "1600 Pennsylvania Ave NW, Washington, DC 20500, USA";
    // Use encryption key for encrypting user data
    $encryptedAddress = $phe->encrypt($homeAddress, $encryptionKey);
    printf("'%s's encrypted home address:\n%s\n", $userTable[0]->username, base64_encode($encryptedAddress));

    // Use encryption key for decrypting user data
    $decryptedAddress = $phe->decrypt($encryptedAddress, $encryptionKey);
    printf("'%s's home address:\n%s\n", $userTable[0]->username, $decryptedAddress);

    printf("Finished.\n");

} catch (\Exception $e) {
    printf("\n\nERROR!\n%s\nCode:%s\n%s\n", $e->getMessage(), $e->getCode(), "Finished.\n");
    die;
}
