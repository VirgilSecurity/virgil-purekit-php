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

namespace Virgil\PureKit\Tests;


use Virgil\PureKit\Pure\NonrotatableSecretsGenerator;

class NonrotatableSecretsGeneratorTest extends \PHPUnit\Framework\TestCase
{
    private $nms;
    private $ak;
    private $oskpId;
    private $vskpId;

    protected function setUp(): void
    {
        $this->nms = "6PvWsrUn/U6ggoabbXCriBk7dtV3NfT+cvqbFGG3DGU=";
        $this->ak = "67s7EAt22cKY+M+OFFG7qBbT0f8J0ZIYlCph8rb8vJo=";
        $this->oskpId = "45IvIXkOQ7c=";
        $this->vskpId = "7QksLSjG56g=";

    }

    public function testGenerateSecretsFixedSeedShouldMatch()
    {
        try {
            $data = base64_decode($this->nms);
            $nonrotatableSecrets = NonrotatableSecretsGenerator::generateSecrets($data);

            $this->assertEquals(base64_decode($this->ak), $nonrotatableSecrets->getAk());
            $this->assertEquals(base64_decode($this->oskpId), $nonrotatableSecrets->getOskp()->getPublicKey()
                ->getIdentifier());
            $this->assertEquals(base64_decode($this->vskpId), $nonrotatableSecrets->getVskp()->getPublicKey()
                ->getIdentifier());

        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

}