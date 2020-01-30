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

namespace Virgil\PureKit\_tests\feature;

use Dotenv\Dotenv;
use Virgil\PureKit\Phe\ProtocolContext;

class ContextTest extends \PHPUnit\Framework\TestCase
{
    protected $appToken;
    protected $context;

    protected function setUp(): void
    {
        (new Dotenv(__DIR__ . "/../"))->load();
        $this->appToken = $_ENV["APP_TOKEN"];
    }

    private function getKey(int $key)
    {
        return [
            'PK' => "PK.$key.{$_ENV["SERVICE_PUBLIC_KEY"]}",
            'SK' => "SK.$key.{$_ENV["APP_SECRET_KEY"]}",
            'UT' => "UT.$key.{$_ENV["UPDATE_TOKEN"]}"
        ];
    }

    public function testCaseHTC_8()
    {
        $this->context = (new ProtocolContext)->create([
            'appToken' => $this->appToken,
            'servicePublicKey' => $this->getKey(3)['PK'],
            'appSecretKey' => $this->getKey(3)['SK'],
            'updateToken' => "",
        ]);

        $this->assertEquals(3, $this->context->getVersion());
        $this->assertEquals(null, $this->context->getUpdateToken());
    }

    public function testCaseHTC_9()
    {
        $this->context = (new ProtocolContext)->create([
            'appToken' => $this->appToken,
            'servicePublicKey' => $this->getKey(1)['PK'],
            'appSecretKey' => $this->getKey(1)['SK'],
            'updateToken' => $this->getKey(2)['UT'],
        ]);

        $this->assertEquals(2, $this->context->getVersion());
        $this->assertEquals(68, strlen($this->context->getUpdateToken()));
    }

    public function testCaseHTC_10()
    {
        $this->expectException(\Exception::class);
        (new ProtocolContext)->create([
            'appToken' => $this->appToken,
            'servicePublicKey' => $this->getKey(1)['PK'],
            'appSecretKey' => $this->getKey(1)['SK'],
            'updateToken' => $this->getKey(3)['UT'],
        ]);
    }
}