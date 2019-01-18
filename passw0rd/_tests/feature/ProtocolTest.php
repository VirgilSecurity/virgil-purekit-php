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

use Dotenv\Dotenv;
use passw0rd\Core\PHEClient;
use Passw0rd\EnrollmentResponse;
use passw0rd\Exeptions\ProtocolException;
use passw0rd\Http\Request\EnrollRequest;
use passw0rd\Http\Request\VerifyPasswordRequest;
use passw0rd\Protocol\Protocol;
use passw0rd\Protocol\ProtocolContext;
use passw0rd\Http\HttpClient;
use Passw0rd\VerifyPasswordResponse;


class ProtocolTest extends \PHPUnit\Framework\TestCase
{
    protected $client;
    protected $context;
    protected $protocol;
    protected $httpClient;
    protected $password;
    protected $clientEnrollmentRecord;

    protected function setUp()
    {
        (new Dotenv(__DIR__ . "/../../../"))->load();

        $this->password = "password123456";
        $this->clientEnrollmentRecord = base64_decode($_ENV["CLIENT_ENROLLMENT_RECORD"]);
    }

    public function testProtocolFullFlowWithoutUpdateToken()
    {
        $this->context = (new ProtocolContext)->create([
            'appToken' => $_ENV["APP_TOKEN"],
            'servicePublicKey' => $_ENV["SERVICE_PUBLIC_KEY"],
            'appSecretKey' => $_ENV["APP_SECRET_KEY"],
            'updateToken' => "",
        ]);

        $this->protocol = new Protocol($this->context);

        $enrollAccount = $this->protocol->enrollAccount($this->password); // [clientEnrollmentRecord,
        // clientAccountKey]

        $record = $enrollAccount[0];
        $clientAccountKey = $enrollAccount[1];

        $this->assertInternalType('array', $enrollAccount);
        $this->assertEquals(202, strlen($record));
        $this->assertEquals(32, strlen($clientAccountKey));

        $verifyPassword = $this->protocol->verifyPassword($this->password, $record);
        $this->assertEquals(32, strlen($verifyPassword));

        $this->expectException(\passw0rd\Exeptions\ProtocolContextException::class);
        $newRecord = $this->protocol->updateEnrollmentRecord($record);
    }

    public function testProtocolFullFlowWithUpdateTokenAndSameVersionOfRecord()
    {
        $this->context = (new ProtocolContext)->create([
            'appToken' => $_ENV["APP_TOKEN"],
            'servicePublicKey' => $_ENV["SERVICE_PUBLIC_KEY"],
            'appSecretKey' => $_ENV["APP_SECRET_KEY"],
            'updateToken' => $_ENV["UPDATE_TOKEN"],
        ]);

        $this->protocol = new Protocol($this->context);

        $enrollAccount = $this->protocol->enrollAccount($this->password); // [clientEnrollmentRecord,
        // clientAccountKey]

        $record = $enrollAccount[0];
        $clientAccountKey = $enrollAccount[1];

        $this->assertInternalType('array', $enrollAccount);
        $this->assertEquals(202, strlen($record));
        $this->assertEquals(32, strlen($clientAccountKey));

        $verifyPassword = $this->protocol->verifyPassword($this->password, $record);
        $this->assertEquals(32, strlen($verifyPassword));

        $newRecord = $this->protocol->updateEnrollmentRecord($record);
        $this->assertEquals(null, $newRecord);
    }

    public function testProtocolFullFlowWithUpdateToken()
    {
        $this->context = (new ProtocolContext)->create([
            'appToken' => $_ENV["APP_TOKEN"],
            'servicePublicKey' => $_ENV["SERVICE_PUBLIC_KEY"],
            'appSecretKey' => $_ENV["APP_SECRET_KEY"],
            'updateToken' => $_ENV["UPDATE_TOKEN"],
        ]);

        $this->protocol = new Protocol($this->context);

        $verifyPassword = $this->protocol->verifyPassword($this->password, $this->clientEnrollmentRecord);
        $this->assertEquals(32, strlen($verifyPassword));

        $newRecord = $this->protocol->updateEnrollmentRecord($this->clientEnrollmentRecord);
        $this->assertEquals(202, strlen($newRecord));

        $verifyPassword = $this->protocol->verifyPassword($this->password, $newRecord);
        $this->assertEquals(32, strlen($verifyPassword));
    }
}
