<?php
/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

namespace passw0rd\Protocol;

use passw0rd\Credentials\InputCredentialsChecker;
use passw0rd\Exeptions\InputCredentialsCheckerException;
use passw0rd\Exeptions\ProtocolContextException;

/**
 * Class ProtocolContext
 * @package passw0rd
 */
class ProtocolContext
{
    private $accessToken;
    private $publicKey;
    private $secretKey;
    private $updateToken;

    const PK_PREFIX = "PK";
    const SK_PREFIX = "SK";
    const UT_PREFIX = "UT";

    /**
     * @param array $credentials
     * @return ProtocolContext
     */
    public function create(array $credentials): ProtocolContext
    {
        $credentialsChecker = new InputCredentialsChecker();
        try {
            $credentialsChecker->check($credentials);
        }
        catch(InputCredentialsCheckerException $e) {
            var_dump($e->getMessage());
            die;
        }

        $this->setCredentials($credentials);

        return $this;
    }

    /**
     * @param array $credentials
     * @return void
     */
    private function setCredentials(array $credentials): void
    {
        $this->accessToken = $credentials['accessToken'];
        $this->publicKey = $credentials['publicKey'];
        $this->secretKey = $credentials['secretKey'];
        $this->updateToken = $credentials['updateToken'];
    }

    /**
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getPublicKey()
    {
        try {
            return $this->getParsedContext(self::PK_PREFIX, $this->publicKey);
        }
        catch(ProtocolContextException $e) {
            var_dump($e->getMessage());
            die;
        }
    }

    /**
     * @return string
     */
    public function getSecretKey(): string
    {
        try {
            return $this->getParsedContext(self::SK_PREFIX, $this->secretKey);
        }
        catch(ProtocolContextException $e) {
            var_dump($e->getMessage());
            die;
        }
    }

    /**
     * @return string
     */
    public function getUpdateToken(): string
    {
        try {
            return $this->getParsedContext(self::UT_PREFIX, $this->updateToken);
        }
        catch(ProtocolContextException $e) {
            var_dump($e->getMessage());
            die;
        }
    }

    /**
     * @param string $prefix
     * @param string $key
     * @return string
     * @throws ProtocolContextException
     */
    private function getParsedContext(string $prefix, string $key): string
    {
        $parts = explode(".", $key);

        if(count($parts) !== 3 || $parts[0] !== $prefix)
            throw new ProtocolContextException("Invalid string");

        if((int) $parts[1] < 1)
            throw new ProtocolContextException("Invalid version");

        $decodedKey = base64_decode($parts[2]);

        if(strlen($decodedKey) !== 65)
            throw new ProtocolContextException("Invalid string");

        return $decodedKey;
    }
}