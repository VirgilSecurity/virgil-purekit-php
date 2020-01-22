<?php
/**
 * Copyright (C) 2015-2020 Virgil Security Inc.
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
use Virgil\PureKit\Core\Protobuf\DatabaseRecord;
use Virgil\PureKit\Exceptions\ProtocolException;
use Virgil\PureKit\Protocol\Protocol;
use Virgil\PureKit\Protocol\ProtocolContext;
use Virgil\PureKit\Protocol\RecordUpdater;

class ProtocolTest extends \PHPUnit\Framework\TestCase
{
    protected $protocol;
    protected $protocol1;
    protected $protocol2;
    protected $password;
    protected $anotherPassword;
    protected $recordUpdater = [];
    protected $projects = [];

    protected function setUp(): void
    {
        (new Dotenv(__DIR__ . "/../../virgil-purekit-php/"))->load();
        $this->projects = explode(',',$_ENV['PROJECTS']);

        $this->password = "password123456";
        $this->anotherPassword = "123456password";

        foreach ($this->projects as $project) {
            $this->recordUpdater[$project] = new RecordUpdater($_ENV["{$project}_UPDATE_TOKEN"]);
        }
    }

    private function sleep(int $seconds=5)
    {
        sleep($seconds);
    }

    /**
     * @param string $project
     * @param bool $withUpdateToken
     * @param bool $withCorrectServicePublicKey
     * @return ProtocolContext
     * @throws Exception
     */
    private function getContext(string $project, bool $withUpdateToken = true, bool $withCorrectServicePublicKey =
    true):
    ProtocolContext
    {
        $context[$project] = (new ProtocolContext)->create([
            'appToken' => $_ENV["{$project}_APP_TOKEN"],
            'servicePublicKey' => true==$withCorrectServicePublicKey ? $_ENV["{$project}_SERVICE_PUBLIC_KEY"] :
                $_ENV["{$project}_INCORRECT_SERVICE_PUBLIC_KEY"],
            'appSecretKey' => $_ENV["{$project}_APP_SECRET_KEY"],
            'updateToken' => true==$withUpdateToken ? $_ENV["{$project}_UPDATE_TOKEN"] : "",
        ]);

        return $context[$project];
    }

    /**
     * @medium
     */
    public function testCaseHTC_1()
    {
        $this->sleep();

        foreach ($this->projects as $project) {

            $this->protocol[$project] = new Protocol($this->getContext($project,false));

            $rec = $this->protocol[$project]->enrollAccount($this->password);
            $recRecord = $rec[0];
            $recAccountKey = $rec[1];

            $recVersion = DatabaseRecord::getValue($recRecord, "version");
            $this->assertEquals(2, $recVersion);

            $this->assertNotEmpty($rec);
            $this->assertInternalType('array', $rec);
            $this->assertEquals(207, strlen($recRecord));
            $this->assertEquals(32, strlen($recAccountKey));

            $accountKey = $this->protocol[$project]->verifyPassword($this->password, $recRecord);
            $this->assertEquals(32, strlen($accountKey));

            $this->assertEquals($recAccountKey, $accountKey);
        }
    }

    /**
     * @medium
     */
    public function testCaseHTC_2()
    {
        $this->sleep();

        foreach ($this->projects as $project) {
            $this->protocol[$project] = new Protocol($this->getContext($project));

            $rec = $this->protocol[$project]->enrollAccount($this->password);
            $recRecord = $rec[0];
            $recAccountKey = $rec[1];

            $recVersion = DatabaseRecord::getValue($recRecord, "version");
            $this->assertEquals(3, $recVersion);

            $this->assertNotEmpty($rec);
            $this->assertInternalType('array', $rec);
            $this->assertEquals(207, strlen($recRecord));
            $this->assertEquals(32, strlen($recAccountKey));

            $accountKey = $this->protocol[$project]->verifyPassword($this->password, $recRecord);
            $this->assertEquals(32, strlen($accountKey));

            $this->assertEquals($recAccountKey, $accountKey);
        }
    }

    /**
     * @medium
     */
    public function testCaseHTC_3()
    {
        $this->sleep();

        foreach ($this->projects as $project) {
            $this->protocol[$project] = new Protocol($this->getContext($project, false));

            $rec = $this->protocol[$project]->enrollAccount($this->password);
            $recRecord = $rec[0];
            $recAccountKey = $rec[1];

            $this->assertNotEmpty($rec);
            $this->assertInternalType('array', $rec);
            $this->assertEquals(207, strlen($recRecord));
            $this->assertEquals(32, strlen($recAccountKey));

            $this->expectException(ProtocolException::class);
            $this->protocol[$project]->verifyPassword($this->anotherPassword, $recRecord);
        }
    }

    /**
     * @medium
     */
    public function testCaseHTC_4()
    {
        self::markTestSkipped("temp skipped");

        $this->sleep();

        foreach ($this->projects as $project) {
            $this->protocol1[$project] = new Protocol($this->getContext($project, false));

            $rec1 = $this->protocol1[$project]->enrollAccount($this->password);
            $rec1Record = $rec1[0];
            $rec1AccountKey = $rec1[1];

            $this->protocol2[$project] = new Protocol($this->getContext($project, false, false));

            $this->expectException(ProtocolException::class);
            $rec2 = $this->protocol2[$project]->enrollAccount($this->password);

            $this->expectException(ProtocolException::class);
            $accountKey = $this->protocol2[$project]->verifyPassword($this->password, $rec1Record);
        }
    }

    /**
     * @medium
     */
    public function testCaseHTC_5()
    {
        $this->sleep();

        foreach ($this->projects as $project) {
            $this->protocol1[$project] = new Protocol($this->getContext($project, false));

            $rec1 = $this->protocol1[$project]->enrollAccount($this->password);
            $rec1Record = $rec1[0];
            $rec1AccountKey = $rec1[1];

            $res1 = $this->protocol1[$project]->verifyPassword($this->password, $rec1Record);

            $rec2 = $this->recordUpdater[$project]->update($rec1Record);

            $this->protocol2[$project] = new Protocol($this->getContext($project));
            $res2 = $this->protocol2[$project]->verifyPassword($this->password, $rec2);
            $this->assertEquals($res1, $rec1AccountKey);
            $this->assertEquals($res2, $rec1AccountKey);
        }
    }

    /**
     * @medium
     */
    public function testCaseHTC_6()
    {
        $this->sleep();

        foreach ($this->projects as $project) {
            $this->protocol[$project] = new Protocol($this->getContext($project));

            $rec1 = $this->protocol[$project]->enrollAccount($this->password);
            $rec1Record = $rec1[0];
            $rec1AccountKey = $rec1[1];

            $rec2 = $this->recordUpdater[$project]->update($rec1Record);
            $this->assertEquals(null, $rec2);
        }
    }

    /**
     * @medium
     */
    public function testCaseHTC_7()
    {
        $this->sleep();

        foreach ($this->projects as $project) {
            $this->protocol1[$project] = new Protocol($this->getContext($project));

            $rec1 = $this->protocol1[$project]->enrollAccount($this->password);
            $rec1Record = $rec1[0];
            $rec1AccountKey = $rec1[1];

            $r = DatabaseRecord::getValue($rec1Record, "record");
            $rec1RecordVer1 = DatabaseRecord::setup($r, 1);

            $this->protocol2[$project] = new Protocol($this->getContext($project));

            $this->expectException(Exception::class);
            $rec2 = $this->recordUpdater[$project]->update($rec1RecordVer1);

            $this->expectException(ProtocolException::class);
            $res1 = $this->protocol2[$project]->verifyPassword($this->password, $rec1RecordVer1);
        }
    }

    /**
     * @medium
     */
    public function testCaseHTC_11()
    {
        $this->sleep();

        foreach ($this->projects as $project) {
            $this->protocol[$project] = new Protocol($this->getContext($project));

            $this->expectException(ProtocolException::class);
            $rec = $this->protocol[$project]->enrollAccount("");
        }
    }
}
