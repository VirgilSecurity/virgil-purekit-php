<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

use Virgil\CryptoImpl\VirgilCrypto;

require_once 'vendor/autoload.php';

try {

    printf("Starting recovery...\n");

    // MAIN CONFIGURATION

    $userTableExample = 'user_table.json';
    $mainTableExample = 'main_table.json';

    $recoveryPrivateKeyFile = "recovery_private_key.pem";

    $virgilCrypto = new VirgilCrypto();

    // LOAD DATABASE

    $userTableString = file_get_contents($userTableExample);
    $userTable = json_decode($userTableString);

    $mainTableString = file_get_contents($mainTableExample);
    $mainTable = json_decode($mainTableString);

    // CHECK RECOVERY PRIVATE KEY

    if(!is_file($recoveryPrivateKeyFile))
        throw new Exception("No recovery $recoveryPrivateKeyFile file", 0);

    $recoveryPrivateKeyPEM=file_get_contents($recoveryPrivateKeyFile);

    if(!$recoveryPrivateKeyPEM)
        throw new Exception("No recovery private key", 0);

    // DECRYPT PASSWORD

    $recoveryPrivateKeyDER = VirgilKeyPair::privateKeyToDER($recoveryPrivateKeyPEM);
    $recoveryPrivateKey = $virgilCrypto->importPrivateKey($recoveryPrivateKeyDER);

    foreach ($userTable as $user) {
        $encrypted = base64_decode($user->encrypted);
        $decrpyted = $virgilCrypto->decrypt($encrypted, $recoveryPrivateKey);
        $user->passwordHash = $decrpyted;
        $user->encrypted = "";
        $user->record = "";

        printf("Recovering user '%s'\n", $user->username);
        printf("Password: '%s'\n", $user->passwordHash);
    }

    // CLEAR RECOVERY KEYS

    $mainTable[0]->recovery_public_key = "";
    unset($recoveryPrivateKeyFile);

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

    printf("Finished.\n");

} catch (\Exception $e) {
    printf("\n\nERROR!\n%s\nCode:%s\n%s\n", $e->getMessage(), $e->getCode(), "Finished.\n");
    die;
}