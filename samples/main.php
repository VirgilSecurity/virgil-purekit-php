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
#    INITIALIZE PUREKIT    #
############################

try {
    // Set here your PureKit credentials
    $context = (new ProtocolContext)->create([
        'appToken' => 'AT.lkDXnQp0u1xl5urxIHIJlxnHHJdoXXV4',
        'appSecretKey' => 'SK.1.I1xFwFk1OR9ipFY84jecxA1O0rC3IkG16SX+AyvWOZo=',
        'servicePublicKey' => 'PK.1.BLy3NeLlwhcpsvyH6ojpJhlXaZ6cbcrMW7VSvLrwAE9Q0aEg1BeDgzgxu8lktYtSOAVKn3/SjqPBcjNoBKTBUtA=',
        'updateToken' => '' // needs to be left empty
    ]);

    $protocol = new Protocol($context);
}
catch(\Exception $e) {
    var_dump($e);
    die;
}

############################
#   ENROLL USER ACCOUNTS   #
############################

foreach($userTable as $user) {
    try {
        printf("Enrolling user '%s': ", $user->username);

		// Ideally, you'll ask for users to create a new password, but
		// for this guide, we'll use existing password in DB
        $enroll = $protocol->enrollAccount($user->passwordHash);

        // Save record to database
        $user->record = base64_encode($enroll[0]); 
    
        // Deprecate existing user password field & save in database
        $user->passwordHash = "";

        // Use encryptionKey for protecting user data & save in database
        $encryptionKey = $enroll[1];
        $phe = new PHE();
        $user->ssn = base64_encode($phe->encrypt($user->ssn, $encryptionKey));

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

############################
#     VERIFY PASSWORD      #
############################

$password = "80815C001";
$record = base64_decode($userTable[0]->record);

try {
    $encryptionKey = $protocol->verifyPassword($password, $record);
}
catch(\Exception $e) {
    var_dump($e);
    die;
}

############################
# ENCRYPT AND DECRYPT DATA #
############################

try {
    $homeAddress = "1600 Pennsylvania Ave NW, Washington, DC 20500, USA";
    $phe = new PHE();

    // Use encryption key for encrypting user data
    $encryptedAddress = $phe->encrypt($homeAddress, $encryptionKey);
    printf("'%s's encrypted home address: %s\n", $userTable[0]->username, base64_encode($encryptedAddress));

    // Use encryption key for decrypting user data
    $decryptedAddress = $phe->decrypt($encryptedAddress, $encryptionKey);
    printf("'%s's home address: %s\n", $userTable[0]->username, $decryptedAddress);
}
catch(\Exception $e) {
    var_dump($e);
    die;
}
