<?php

require __DIR__ . '/vendor/autoload.php';

use Virgil\PureKit\Protocol\Protocol;
use Virgil\PureKit\Protocol\ProtocolContext;
use Virgil\PureKit\Core\PHE;
use Virgil\PureKit\Core\PHEClient;
use Virgil\PureKit\Protocol\RecordUpdater;

############################
#      LOAD DATABASE       #
############################

$userTableString = file_get_contents('user_table.json');
$userTable = json_decode($userTableString);

############################
#  INITIALIZE FOR UPDATE   #
############################

// Set your updateToken
$updateToken = 'UT.2.CiBn6z2if/onG6fZY7/vpUwP8k28cQbnXgV06Z74f2zjIhIgXE9GKd4x7NypIzf0esPe2yC4Epf+IvkMjE8HRVICyn4=';

try {
    // Set here your PureKit credentials, now with updateToken
    $context = (new ProtocolContext)->create([
        'appToken' => 'AT.lkDXnQp0u1xl5urxIHIJlxnHHJdoXXV4',
        'appSecretKey' => 'SK.1.I1xFwFk1OR9ipFY84jecxA1O0rC3IkG16SX+AyvWOZo=',
        'servicePublicKey' => 'PK.1.BLy3NeLlwhcpsvyH6ojpJhlXaZ6cbcrMW7VSvLrwAE9Q0aEg1BeDgzgxu8lktYtSOAVKn3/SjqPBcjNoBKTBUtA=',
        'updateToken' => $updateToken
    ]);

    $protocol = new Protocol($context);
}
catch(\Exception $e) {
    var_dump($e);
    die;
}

############################
#   ROTATE USER RECORDS    #
############################

$recordUpdater = new RecordUpdater($updateToken);

foreach($userTable as $user) {
    try {
        printf("Rotating '%s's record: ", $user->username);

        // Get new record for user
        $oldRecord = base64_decode($user->record);
        $newRecord = $recordUpdater->update($oldRecord);

        if($newRecord == null) {
            // User record is already updated, don't save
            print("User record is already migrated\n");
            break;
        }

        // Save record to database
        $user->record = base64_encode($newRecord); 

        var_export($user);
    }
    catch(\Exception $e) {
        var_dump($e);
        die;
    }
}

############################
#     SAVE TO DATABASE     #
############################

$fp = fopen('user_table.json', 'w');
fwrite($fp, json_encode($userTable));
fclose($fp);