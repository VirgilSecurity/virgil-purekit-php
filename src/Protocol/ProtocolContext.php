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

namespace Virgil\PureKit\Protocol;

use Virgil\PureKit\Credentials\InputCredentialsChecker;
use Virgil\PureKit\Exceptions\ProtocolContextException;
use VirgilCrypto\Phe\PheClient;

/**
 * Class ProtocolContext
 * @package passw0rd
 */
class ProtocolContext
{
    private $appToken;
    private $servicePublicKey;
    private $appSecretKey;
    private $updateToken;

    private $newRawKeys;

    private $version;

    private $pheImpl;

    const PK_PREFIX = "PK";
    const SK_PREFIX = "SK";
    const UT_PREFIX = "UT";

    /**
     *
     * CreateContext validates input parameters and prepares them for being used in Protocol
     *
     * @param array $credentials
     * @return ProtocolContext
     * @throws \Exception
     */
    public function create(array $credentials): ProtocolContext
    {
        $credentialsChecker = new InputCredentialsChecker($credentials);

        $credentialsChecker->check();

        $this->mainSetter($credentials);

        return $this;
    }

    /**
     * @param array $credentials
     * @throws \Exception
     */
    public function mainSetter(array $credentials)
    {
        $this->setCredentials($credentials);

        if ($this->isKeysVersionsEquals())
            $this->version = (int) $this->getServicePublicKey(true);

        if(!is_null($this->getUpdateToken()))
        {
            if((int) $this->getUpdateToken(true)!==$this->getVersion()+1)
                throw new ProtocolContextException("Incorrect token version ".$this->getUpdateToken(true));

            $this->version = (int) $this->getUpdateToken(true);
        }

        try {
            $this->setPHEClient($this->getAppSecretKey(), $this->getServicePublicKey(), $this->getUpdateToken());
        } catch (\Exception $e) {
            throw new ProtocolContextException("Protocol error with PHE client constructor or setKeys method (code: {$e->getCode()})");
        }
    }

    /**
     * @return bool
     * @throws ProtocolContextException
     */
    private function isKeysVersionsEquals(): bool
    {
        if ((int)$this->getAppSecretKey(true) !== (int)$this->getServicePublicKey(true))
            throw new ProtocolContextException("Versions of appSecretKey and servicePublicKey must be equals");

        return true;
    }

    /**
     * @param array $credentials
     * @return void
     */
    private function setCredentials(array $credentials): void
    {
        $this->appToken = $credentials['appToken'];
        $this->servicePublicKey = $credentials['servicePublicKey'];
        $this->appSecretKey = $credentials['appSecretKey'];
        $this->updateToken = $credentials['updateToken'];
    }

    /**
     * @return string
     */
    public function getAppToken(): string
    {
        return $this->appToken;
    }


    /**
     * @param bool $returnVersion
     * @return string
     * @throws ProtocolContextException
     */
    public function getServicePublicKey(bool $returnVersion = false): string
    {
        return $this->getParsedContext(self::PK_PREFIX, $this->servicePublicKey, $returnVersion);
    }

    /**
     * @param bool $returnVersion
     * @return string
     * @throws ProtocolContextException
     */
    public function getAppSecretKey(bool $returnVersion = false): string
    {
        return $this->getParsedContext(self::SK_PREFIX, $this->appSecretKey, $returnVersion);
    }

    /**
     * @param bool $returnVersion
     * @return null|string
     * @throws ProtocolContextException
     */
    public function getUpdateToken(bool $returnVersion = false)
    {
        return $this->getParsedContext(self::UT_PREFIX, $this->updateToken, $returnVersion);
    }

    /**
     *
     * ParseVersionAndContent splits string into 3 parts: Prefix, version and decoded base64 content
     *
     * @param string $prefix
     * @param string $key
     * @param bool $returnVersion
     * @return null|string
     * @throws ProtocolContextException
     */
    private function getParsedContext(string $prefix, string $key, bool $returnVersion = false)
    {
        if ($prefix == self::UT_PREFIX && $key == "")
            return null;

        $parts = explode(".", $key);

        if (count($parts) !== 3 || $parts[0] !== $prefix)
            throw new ProtocolContextException("Invalid string: $key");

        if ((int)$parts[1] < 1)
            throw new ProtocolContextException("Invalid version: $key");

        $decodedKey = base64_decode($parts[2]);

        return $returnVersion==true ? $parts[1] : $decodedKey;
    }

    /**
     * @return int
     */
    public function getVersion(): int
    {
        return (int) $this->version;
    }

    /**
     * @throws ProtocolContextException
     */
    public function setUpdateTokenVersion(): void
    {
        $this->version = $this->getUpdateToken(true);
    }

    /**
     * @return \Virgil\PureKit\Protocol\PheClient
     */
    public function getPheImpl(): PheClient
    {
        return $this->pheImpl;
    }

    /**
     * @param string $appSecretKey
     * @param string $servicePublicKey
     * @param string|null $updateToken
     * @throws \Exception
     */
    private function setPHEClient(string $appSecretKey, string $servicePublicKey, string $updateToken = null): void
    {
        $PHEClient = new PheClient();
        $PHEClient->setupDefaults();
        $PHEClient->setKeys($appSecretKey, $servicePublicKey);

        $this->pheImpl = $PHEClient;

        if (!is_null($updateToken)) {
            $newKeys = $PHEClient->rotateKeys($updateToken);

            $this->newRawKeys = $newKeys;

            $nextPHEClient = new PheClient();
            $nextPHEClient->setupDefaults();
            $nextPHEClient->setKeys($newKeys[0], $newKeys[1]);

            $this->setUpdateTokenVersion();

            $this->pheImpl = $nextPHEClient;
        }
    }

    /**
     * @return array|null
     */
    public function getNewRawKeys()
    {
        return $this->newRawKeys;
    }
}