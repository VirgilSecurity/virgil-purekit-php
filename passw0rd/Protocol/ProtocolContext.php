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

namespace passw0rd\Protocol;

use passw0rd\Core\PHEClient;
use passw0rd\Credentials\InputCredentialsChecker;
use passw0rd\Exeptions\InputCredentialsCheckerException;
use passw0rd\Exeptions\ProtocolContextException;

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

    private $version;

    private $PHEClient;
    private $nextPHEClient;

    private $pheImpl;

    const PK_PREFIX = "PK";
    const SK_PREFIX = "SK";
    const UT_PREFIX = "UT";

    /**
     * @param array $credentials
     * @return ProtocolContext
     * @throws \Exception
     */
    public function create(array $credentials): ProtocolContext
    {
        $credentialsChecker = new InputCredentialsChecker($credentials);

        try {
            $credentialsChecker->check();
        } catch (InputCredentialsCheckerException $e) {
            var_dump($e->getMessage());
            die;
        }

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

        try {
            if ($this->isKeysVersionsEquals())
                $this->version = (int) $this->getServicePublicKey(true);

            if(!is_null($this->getUpdateToken()))
            {
                if((int) $this->getUpdateToken(true)!==$this->getVersion()+1)
                    throw new \Exception("Incorrect token version ".$this->getUpdateToken(true));

                $this->version = (int) $this->getUpdateToken(true);
            }

            try {
                $this->setPHEClient($this->getAppSecretKey(), $this->getServicePublicKey(), $this->getUpdateToken());
            } catch (\Exception $e) {
                throw new ProtocolContextException('Protocol error with PHE client constructor or setKeys method');
            }

        } catch (\Exception $e) {
            throw new \Exception($e->getMessage());
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
     */
    public function getServicePublicKey(bool $returnVersion = false): string
    {
        try {
            return $this->getParsedContext(self::PK_PREFIX, $this->servicePublicKey, $returnVersion);
        } catch (ProtocolContextException $e) {
            var_dump($e->getMessage());
            die;
        }
    }

    /**
     * @param bool $returnVersion
     * @return string
     */
    public function getAppSecretKey(bool $returnVersion = false): string
    {
        try {
            return $this->getParsedContext(self::SK_PREFIX, $this->appSecretKey, $returnVersion);
        } catch (ProtocolContextException $e) {
            var_dump($e->getMessage());
            die;
        }
    }

    /**
     * @param bool $returnVersion
     * @return null|string
     */
    public function getUpdateToken(bool $returnVersion = false):? string
    {
        try {
            return $this->getParsedContext(self::UT_PREFIX, $this->updateToken, $returnVersion);
        } catch (ProtocolContextException $e) {
            var_dump($e->getMessage());
            die;
        }
    }

    /**
     * @param string $prefix
     * @param string $key
     * @param bool $returnVersion
     * @return null|string
     * @throws ProtocolContextException
     */
    private function getParsedContext(string $prefix, string $key, bool $returnVersion = false): ?string
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
     * @return void
     */
    public function setNextVersion(): void
    {
        $this->version = $this->version + 1;
    }

    /**
     * @return void
     */
    public function setUpdateTokenVersion(): void
    {
        $this->version = $this->getUpdateToken(true);
    }

    /**
     * @return PHEClient
     */
    public function getPHEImpl(): PHEClient
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
        $this->PHEClient = new PHEClient();
        $this->PHEClient->setKeys($appSecretKey, $servicePublicKey);

        $this->pheImpl = $this->PHEClient;

        if (!is_null($updateToken)) {
            $newKeys = $this->PHEClient->rotateKeys($updateToken);
            $this->nextPHEClient = new PHEClient();
            $this->nextPHEClient->setKeys($newKeys[0], $newKeys[1]);

            $this->setUpdateTokenVersion();

            $this->pheImpl = $this->nextPHEClient;
        }
    }
}