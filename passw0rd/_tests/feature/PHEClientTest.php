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

use passw0rd\Core\PHEClient;
require_once '../src/PHEServer.php';


class PHEClientTest extends \PHPUnit\Framework\TestCase
{
    protected $client;
    protected $server;

    protected function setUp()
    {
        $this->client = new PHEClient();
        $this->server = new PHEServer();
    }

    public function testCustomDataForEnrollShouldSucceed()
    {
        $password = "passw0rd";
        $clientPrivateKey = base64_decode("VLFGws8zMxAIAU9YGaAWNihmkUsnhvdcxNpvQ62sig0=", true);
        $serverPublicKey = base64_decode("BHvu1iVcE2kggN0cQOkHdzd20VHUfe62/KkUhqX9niJbHtcXqU/0GtjbvcJF3sp8jLhdcE1AuxZucUKswt7Jc3w=", true);
        $serverEnrollment = base64_decode("CiBdVlePm0B5n11kOCalFdil1WCV3/G/7GAFyoQN6vIq4BJBBJ+Zc7JnO9oXV1ZEq6ZALCy46iXtiSdpELff4iDTQa1AhMGZaBpevO2moZnmBuUGj5yhW24A9Ispryzh3NuK+/4aQQTsCVyNt8PgWnOywjHIW2vS7vfUQGP/S+Q0hrdt3q0AS2MWv1b36PHVO7qxTi+6npFwQXCnfkHKkwo82wgfvfmzIusBCkEE1ksKZxvSnolCw3AiXA79OivrQVxuiNg4X8r2+j3Xr9wfuAPxcckEWzOVNCmwctmlHfAzOFW4FhHaensywzo4aRJBBLeMkHbNbJsN17NKTTJ8babY7rsf3YvnrntVoIclmk2jqMV3RAhxno8pdSUeC7WfmSjlYaO71JWAhGy1KHMBDkUaQQTMkpdkdxJoE0MUk/NUg4GfPc2nUPFR8m01DR/ZcgMrU7wwE8zCt5MIRNpNsHAjhRxuuu4WEnpcboXDDWd8Lz6aIiAF7a2GPzWsf9nXL5YGSURxNRK4Ty9INUyQT1V7FUCiVQ==", true);

        $this->assertEquals(65, strlen($serverPublicKey));
        $this->assertEquals(32, strlen($clientPrivateKey));
        $this->assertEquals(406, strlen($serverEnrollment));

        $this->client->setKeys($clientPrivateKey, $serverPublicKey);

        $clientEnrollAccount = $this->client->enrollAccount($serverEnrollment, $password);
        $this->assertInternalType('array', $clientEnrollAccount);
        $this->assertCount(2, $clientEnrollAccount);

        $clientEnrollmentRecord = $clientEnrollAccount[0];
        $clientAccountKey = $clientEnrollAccount[1];
        $this->assertInternalType('string', $clientEnrollmentRecord);
        $this->assertInternalType('string', $clientAccountKey);

        $this->assertEquals(202, strlen($clientEnrollmentRecord));
        $this->assertEquals(32, strlen($clientAccountKey));
    }

    public function testFullFlowRandomCorrectPwdShouldSucceed()
    {
        $password = "password";

        $serverKeyPair = $this->server->generateServerKeyPair(); // [{privateKey}, {publicKey}]
        $this->assertInternalType('array', $serverKeyPair);
        $this->assertCount(2, $serverKeyPair);

        $serverPrivateKey = $serverKeyPair[0];
        $serverPublicKey = $serverKeyPair[1];

        $this->assertInternalType('string', $serverPrivateKey);
        $this->assertInternalType('string', $serverPublicKey);

        $this->assertEquals(65, strlen($serverPublicKey));
        $this->assertEquals(32, strlen($serverPrivateKey));

        $clientPrivateKey = $this->client->generateClientPrivateKey(); // {privateKey}
        $this->assertInternalType('string', $clientPrivateKey);

        $this->client->setKeys($clientPrivateKey, $serverPublicKey); // void

        $serverEnrollment = $this->server->getEnrollment($serverPrivateKey, $serverPublicKey);
        $this->assertNotEmpty($serverEnrollment);
        $this->assertInternalType('string', $serverEnrollment);
        $this->assertEquals(406, strlen($serverEnrollment));

        $clientEnrollAccount = $this->client->enrollAccount($serverEnrollment, $password);
        $this->assertInternalType('array', $clientEnrollAccount);
        $this->assertCount(2, $clientEnrollAccount);

        $clientEnrollmentRecord = $clientEnrollAccount[0];
        $clientAccountKey = $clientEnrollAccount[1];
        $this->assertInternalType('string', $clientEnrollmentRecord);
        $this->assertInternalType('string', $clientAccountKey);

        $this->assertEquals(202, strlen($clientEnrollmentRecord));

        $clientCreateVerifyPasswordRequest = $this->client->createVerifyPasswordRequest($password,
            $clientEnrollmentRecord);
        $this->assertNotEmpty($clientCreateVerifyPasswordRequest);
        $this->assertInternalType('string', $clientCreateVerifyPasswordRequest);

        $serverVerifyPassword = $this->server->verifyPassword($serverPrivateKey, $serverPublicKey,
            $clientCreateVerifyPasswordRequest);
        $this->assertInternalType('string', $serverVerifyPassword);

        $clientCheckResponseAndDecrypt = $this->client->checkResponseAndDecrypt($password,
            $clientEnrollmentRecord, $serverVerifyPassword);
        $this->assertInternalType('string', $clientCheckResponseAndDecrypt);
        $this->assertEquals(32, strlen($clientAccountKey));
        $this->assertEquals(32, strlen($clientCheckResponseAndDecrypt));
        $this->assertEquals($clientAccountKey, $clientCheckResponseAndDecrypt);
    }

    public function testRotationRandomRotationServerPublicKeysMatch()
    {
        $serverKeyPair = $this->server->generateServerKeyPair(); // [{privateKey}, {publicKey}]
        $this->assertInternalType('array', $serverKeyPair);
        $this->assertCount(2, $serverKeyPair);
        $serverPrivateKey = $serverKeyPair[0];
        $serverPublicKey = $serverKeyPair[1];
        $this->assertInternalType('string', $serverPrivateKey);
        $this->assertInternalType('string', $serverPublicKey);

        $serverRotateKeys = $this->server->rotateKeys($serverPrivateKey);
        $this->assertInternalType('array', $serverRotateKeys);
        $serverRotatedPrivateKey = $serverRotateKeys[0];
        $serverRotatedPublicKey = $serverRotateKeys[1];
        $serverUpdateToken = $serverRotateKeys[2];
        $this->assertInternalType('string', $serverRotatedPrivateKey);
        $this->assertInternalType('string', $serverRotatedPublicKey);
        $this->assertInternalType('string', $serverUpdateToken);
        $this->assertNotEmpty($serverUpdateToken);

        $clientPrivateKey = $this->client->generateClientPrivateKey(); // {privateKey}
        $this->assertInternalType('string', $clientPrivateKey);
        $this->assertNotEmpty($clientPrivateKey);

        $this->client->setKeys($clientPrivateKey, $serverRotatedPublicKey);

        $clientRotateKeys = $this->client->rotateKeys($serverUpdateToken);
        $this->assertInternalType('array', $clientRotateKeys);
        $clientNewPrivateKey = $clientRotateKeys[0];
        $serverNewPublicKey = $clientRotateKeys[1];
        $this->assertInternalType('string', $clientNewPrivateKey);
        $this->assertInternalType('string', $serverNewPublicKey);

        $this->assertEquals(strlen($serverPublicKey), strlen($serverNewPublicKey));
        $this->assertEquals(strlen($clientPrivateKey), strlen($clientNewPrivateKey));
    }
}
