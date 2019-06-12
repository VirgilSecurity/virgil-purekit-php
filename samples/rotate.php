<?php

require __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use Virgil\CryptoImpl\VirgilCrypto;
use Virgil\PureKit\Protocol\Protocol;
use Virgil\PureKit\Protocol\ProtocolContext;
use Virgil\PureKit\Protocol\RecordUpdater;

try {
    // MAIN CONFIGURATION

    $userTableExample = 'user_table.json';
    $virgilCrypto = new VirgilCrypto();

    // INITIALIZE PUREKIT FOR UPDATE

    // Set here your PureKit credentials
    $env = (new Dotenv(".", ".env"))->load();

    $context = (new ProtocolContext)->create([
        'appSecretKey' => $_ENV['APP_SECRET_KEY'],
        'appToken' => $_ENV['APP_TOKEN'],
        'servicePublicKey' => $_ENV['SERVICE_PUBLIC_KEY'],
        'updateToken' => $_ENV['UPDATE_TOKEN'] // set your UPDATE TOKEN
    ]);

    $protocol = new Protocol($context);

    // LOAD DATABASE

    $userTableString = file_get_contents($userTableExample);
    $userTable = json_decode($userTableString);

    // ROTATE USER RECORDS

    $recordUpdater = new RecordUpdater($_ENV['SAMPLE_UPDATE_TOKEN']);

    foreach ($userTable as $user) {
        printf("Rotating '%s's record:\n", $user->username);

        // Get new record for user
        $oldRecord = base64_decode($user->record);
        $newRecord = $recordUpdater->update($oldRecord);

        if (is_null($newRecord)) {
            // User record is already updated, don't save
            print("User record is already migrated\n");
            break;
        }

        // Save record to database
        $user->record = base64_encode($newRecord);

        printf("\n");
        print_r($user);
        printf("\n");
    }

    // SAVE TO DATABASE

    $fp = fopen($userTableExample, 'w');
    fwrite($fp, json_encode($userTable));
    fclose($fp);

    printf("Finished.\n");

} catch (\Exception $e) {
    printf("\n\nERROR!\n%s\nCode:%s\n%s\n", $e->getMessage(), $e->getCode(), "Finished.\n");
    die;
}