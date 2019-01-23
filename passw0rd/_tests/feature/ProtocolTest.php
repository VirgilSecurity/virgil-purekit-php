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
use passw0rd\Core\Protobuf\DatabaseRecord;
use passw0rd\Exeptions\ProtocolException;
use passw0rd\Protocol\Protocol;
use passw0rd\Protocol\ProtocolContext;


class ProtocolTest extends \PHPUnit\Framework\TestCase
{
    protected $client;
    protected $protocol;
    protected $protocol1;
    protected $protocol2;
    protected $password;
    protected $anotherPassword;
    protected $clientEnrollmentRecord;

    protected function setUp()
    {
        (new Dotenv(__DIR__ . "/../../../"))->load();

        $this->password = "password123456";
        $this->anotherPassword = "123456password";
        $this->clientEnrollmentRecord = base64_decode($_ENV["CLIENT_ENROLLMENT_RECORD"]);
    }

    private function sleep(int $seconds=5)
    {
        sleep($seconds);
    }

    private function getContext(bool $withUpdateToken = true, bool $withCorrectServicePublicKey = true)
    {
        $context = (new ProtocolContext)->create([
            'appToken' => $_ENV["APP_TOKEN"],
            'servicePublicKey' => true==$withCorrectServicePublicKey ? $_ENV["SERVICE_PUBLIC_KEY"] : $_ENV["INCORRECT_SERVICE_PUBLIC_KEY"],
            'appSecretKey' => $_ENV["APP_SECRET_KEY"],
            'updateToken' => true==$withUpdateToken ? $_ENV["UPDATE_TOKEN"] : "",
        ]);

        return $context;
    }

    /**
     * @medium
     */
    public function testCaseHTC_1()
    {
        $this->protocol = new Protocol($this->getContext(false));

        $rec = $this->protocol->enrollAccount($this->password);
        $recRecord = $rec[0];
        $recAccountKey = $rec[1];

        $recVersion = DatabaseRecord::getValue($recRecord, "version");
        $this->assertEquals(2, $recVersion);

        $this->assertNotEmpty($rec);
        $this->assertInternalType('array', $rec);
        $this->assertEquals(207, strlen($recRecord));
        $this->assertEquals(32, strlen($recAccountKey));

        $accountKey = $this->protocol->verifyPassword($this->password, $recRecord);
        $this->assertEquals(32, strlen($accountKey));

        $this->assertEquals($recAccountKey, $accountKey);
    }

    /**
     * @medium
     */
    public function testCaseHTC_2()
    {
        $this->sleep();

        $this->protocol = new Protocol($this->getContext());

        $rec = $this->protocol->enrollAccount($this->password);
        $recRecord = $rec[0];
        $recAccountKey = $rec[1];

        $recVersion = DatabaseRecord::getValue($recRecord, "version");
        $this->assertEquals(3, $recVersion);

        $this->assertNotEmpty($rec);
        $this->assertInternalType('array', $rec);
        $this->assertEquals(207, strlen($recRecord));
        $this->assertEquals(32, strlen($recAccountKey));

        $accountKey = $this->protocol->verifyPassword($this->password, $recRecord);
        $this->assertEquals(32, strlen($accountKey));

        $this->assertEquals($recAccountKey, $accountKey);
    }

    /**
     * @medium
     */
    public function testCaseHTC_3()
    {
        $this->sleep();

        $this->protocol = new Protocol($this->getContext(false));

        $rec = $this->protocol->enrollAccount($this->password);
        $recRecord = $rec[0];
        $recAccountKey = $rec[1];

        $this->assertNotEmpty($rec);
        $this->assertInternalType('array', $rec);
        $this->assertEquals(207, strlen($recRecord));
        $this->assertEquals(32, strlen($recAccountKey));

        $this->expectException(ProtocolException::class);
        $this->protocol->verifyPassword($this->anotherPassword, $recRecord);
    }

    /**
     * @medium
     */
    public function testCaseHTC_4()
    {
        $this->sleep();

        $this->protocol1 = new Protocol($this->getContext(false));

        $rec1 = $this->protocol1->enrollAccount($this->password);
        $rec1Record = $rec1[0];
        $rec1AccountKey = $rec1[1];

        $this->protocol2 = new Protocol($this->getContext(false, false));

        $this->expectException(ProtocolException::class);
        $rec2 = $this->protocol2->enrollAccount($this->password);

        $this->expectException(ProtocolException::class);
        $accountKey = $this->protocol2->verifyPassword($this->password, $rec1Record);
    }

    /**
     * @medium
     */
    public function testCaseHTC_5()
    {
        $this->sleep();

        $this->protocol1 = new Protocol($this->getContext(false));

        $rec1 = $this->protocol1->enrollAccount($this->password);
        $rec1Record = $rec1[0];
        $rec1AccountKey = $rec1[1];

        $res1 = $this->protocol1->verifyPassword($this->password, $rec1Record);

        $this->protocol2 = new Protocol($this->getContext());

        $rec2 = $this->protocol2->updateEnrollmentRecord($rec1Record);
        $res2 = $this->protocol2->verifyPassword($this->password, $rec2);
        $this->assertEquals($res1, $rec1AccountKey);
        $this->assertEquals($res2, $rec1AccountKey);
    }

    /**
     * @medium
     */
    public function testCaseHTC_6()
    {
        $this->sleep();

        $this->protocol = new Protocol($this->getContext());

        $rec1 = $this->protocol->enrollAccount($this->password);
        $rec1Record = $rec1[0];
        $rec1AccountKey = $rec1[1];

        $this->expectException(ProtocolException::class);
        $rec2 = $this->protocol->updateEnrollmentRecord($rec1Record);
    }

    /**
     * @medium
     */
    public function testCaseHTC_7()
    {
        $this->sleep();

        $this->protocol1 = new Protocol($this->getContext());

        $rec1 = $this->protocol1->enrollAccount($this->password);
        $rec1Record = $rec1[0];
        $rec1AccountKey = $rec1[1];

        $r = DatabaseRecord::getValue($rec1Record, "record");
        $rec1RecordVer1 = DatabaseRecord::setup($r, 1);

        $this->protocol2 = new Protocol($this->getContext());

        $this->expectException(ProtocolException::class);
        $rec2 = $this->protocol2->updateEnrollmentRecord($rec1RecordVer1);

        $this->expectException(ProtocolException::class);
        $res1 = $this->protocol2->verifyPassword($this->password, $rec1RecordVer1);
    }

    /**
     * @medium
     */
    public function testCaseHTC_11()
    {
        $this->sleep();

        $this->protocol = new Protocol($this->getContext());

        $this->expectException(ProtocolException::class);
        $rec = $this->protocol->enrollAccount("");
    }
}
