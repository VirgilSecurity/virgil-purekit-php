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

namespace Virgil\PureKit\Pure;


use Virgil\CryptoImpl\Core\VirgilKeyPair;
use Virgil\CryptoImpl\Core\VirgilPublicKey;
use Virgil\CryptoImpl\VirgilCrypto;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Util\ValidateUtil;

/**
 * Class PureContext
 * @package Virgil\PureKit\Pure
 */
class PureContext
{
    private const AK_LENGTH = 32;
    private const AK_PREFIX = "AK";
    private const BUPPK_PREFIX = "BU";
    private const HPK_PREFIX = "HB";
    private const SECRET_KEY_PREFIX = "SK";
    private const PUBLIC_KEY_PREFIX = "PK";
    private const UPDATE_TOKEN_PREFIX = "UT";
    private const VIRGIL_SIGNING_KEY_PREFIX = "VS";
    private const OWN_SIGNING_KEY_PREFIX = "OS";

    private $crypto;
    private $ak;
    private $buppk;
    private $hpk;
    private $oskp;
    private $appSecretKey;
    private $servicePublicKey;
    private $storage;
    private $pheClient;
    private $externalPublicKeys;
    private $updateToken;

    /**
     * PureContext constructor.
     * @param VirgilCrypto $crypto
     * @param string $appToken
     * @param string $ak
     * @param string $buppk
     * @param string $hpk
     * @param string $oskp
     * @param string $appSecretKey
     * @param string $servicePublicKey
     * @param PureStorage $storage
     * @param VirgilPublicKeyCollection $externalPublicKeys
     * @param string $pheServiceAddress
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureLogicException
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    public function __construct(VirgilCrypto $crypto, string $appToken, string $ak, string $buppk, string $hpk, string $oskp, string $appSecretKey, string $servicePublicKey, PureStorage $storage, VirgilPublicKeyCollection $externalPublicKeys, string $pheServiceAddress)
    {
        ValidateUtil::checkNull($storage, "storage");

        $this->crypto = $crypto;
        $this->ak = self::parseCredentials(self::AK_PREFIX, $ak, false);

        $buppkData = self::parseCredentials(self::BUPPK_PREFIX, $buppk, false)->getPayload();
        $this->buppk = $crypto->importPublicKey($buppkData);

        $hpkData = self::parseCredentials(self::HPK_PREFIX, $hpk, false)->getPayload();
        $this->hpk = $crypto->importPublicKey($hpkData);

        $osskData = self::parseCredentials(self::OWN_SIGNING_KEY_PREFIX, $oskp, false)->getPayload();
        $this->oskp = $crypto->importPrivateKey($osskData);

        $this->appSecretKey = self::parseCredentials(self::SECRET_KEY_PREFIX, $appSecretKey, true);
        $this->servicePublicKey = self::parseCredentials(self::PUBLIC_KEY_PREFIX, $servicePublicKey, true);

        $this->storage = $storage;
        $this->pheClient = new HttpPheClient($appToken, $pheServiceAddress);

//        TODO!
//        if (!is_null($externalPublicKeys)) {
//            this.externalPublicKeys = new HashMap<>(externalPublicKeys.size());
//            for (String key : externalPublicKeys.keySet()) {
//                List<String> publicKeysBase64 = externalPublicKeys.get(key);
//                ArrayList<VirgilPublicKey> publicKeys = new ArrayList<>(publicKeysBase64.size());
//
//                for (String publicKeyBase64 : publicKeysBase64) {
//                    VirgilPublicKey publicKey =
//                        crypto.importPublicKey(Base64.decode(publicKeyBase64.getBytes()));
//                    publicKeys.add(publicKey);
//                }
//
//                this.externalPublicKeys.put(key, publicKeys);
//            }
//        } else {
//            this.externalPublicKeys = new HashMap<>();
//        }

        if ($this->appSecretKey->getVersion() != $this->servicePublicKey->getVersion())
            throw new PureLogicException(ErrorStatus::KEYS_VERSION_MISMATCH());

        if (self::AK_LENGTH != strlen($this->ak->getPayload()))
            throw new PureLogicException(ErrorStatus::AK_INVALID_LENGTH());
    }

    /**
     * @param string $appToken
     * @param string $ak
     * @param string $bu
     * @param string $hb
     * @param string $os
     * @param PureStorage $storage
     * @param string $appSecretKey
     * @param string $servicePublicKey
     * @param VirgilPublicKeyCollection $externalPublicKeys
     * @param string $pheServiceAddress
     * @return PureContext
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureLogicException
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    public static function createCustomContext(string $appToken, string $ak, string $bu, string $hb, string $os,
                                               PureStorage $storage, string $appSecretKey, string $servicePublicKey,
                                               VirgilPublicKeyCollection $externalPublicKeys,
                                               string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS): PureContext
    {
        return self::createContext(
            new VirgilCrypto(),
            $appToken,
            $ak, $bu, $hb, $os,
            $appSecretKey,
            $servicePublicKey,
            $storage,
            $externalPublicKeys,
            $pheServiceAddress
        );
    }

    /**
     * @param string $appToken
     * @param string $ak
     * @param string $bu
     * @param string $hb
     * @param string $os
     * @param string $vs
     * @param string $sk
     * @param string $pk
     * @param VirgilPublicKeyCollection $externalPublicKeys
     * @param string $pheServiceAddress
     * @param string $pureServiceAddress
     * @return PureContext
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureLogicException
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    public static function createVirgilContext(string $appToken, string $ak, string $bu, string $hb, string $os,
                                               string $vs, string $sk, string $pk,
                                               VirgilPublicKeyCollection $externalPublicKeys,
                                               string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
                                               string $pureServiceAddress = HttpPureClient::SERVICE_ADDRESS): PureContext
    {
        $crypto = new VirgilCrypto();
        $pureClient = new HttpPureClient($appToken, $pureServiceAddress);
        $vsCredentials = self::parseCredentials(self::VIRGIL_SIGNING_KEY_PREFIX, $vs, false);
        $storage = new VirgilCloudPureStorage($crypto, $pureClient, $crypto->importPrivateKey
        ($vsCredentials->getPayload()));

        return self::createContext($crypto, $appToken, $ak, $bu, $hb, $os, $sk, $pk, $storage, $externalPublicKeys,
            $pheServiceAddress);
    }

    /**
     * @param VirgilCrypto $crypto
     * @param string $appToken
     * @param string $ak
     * @param string $bu
     * @param string $hb
     * @param string $os
     * @param string $sk
     * @param string $pk
     * @param PureStorage $storage
     * @param VirgilPublicKeyCollection $externalPublicKeys
     * @param string $pheServiceAddress
     * @return PureContext
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureLogicException
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    public static function createContext(VirgilCrypto $crypto, string $appToken, string $ak, string $bu, string $hb,
                                          string $os, string $sk, string $pk, PureStorage $storage,
                                          VirgilPublicKeyCollection $externalPublicKeys,
                                          string $pheServiceAddress): PureContext
    {
        return new self(
            $crypto, $appToken, $ak, $bu, $hb, $os, $sk, $pk, $storage, $externalPublicKeys, $pheServiceAddress
        );
    }

    /**
     * @param string $prefix
     * @param string $credentials
     * @param bool $isVersioned
     * @return Credentials
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureLogicException
     */
    private static function parseCredentials(string $prefix, string $credentials, bool $isVersioned): Credentials
    {
        ValidateUtil::checkNullOrEmpty($prefix, "prefix");
        ValidateUtil::checkNullOrEmpty($credentials, "credentials");

        $parts = [];
        $parts = explode("\\.", $credentials);

        if (count($parts) != ($isVersioned ? 3 : 2))
            throw new PureLogicException(ErrorStatus::CREDENTIALS_PARSING_ERROR());

        $index = 0;

        if (!$parts[$index] !== $prefix)
            throw new PureLogicException(ErrorStatus::CREDENTIALS_PARSING_ERROR());

        $index++;

        if ($isVersioned) {
            // TODO!
            $version = $parts[$index];
            $index++;
        } else {
            $version = 0;
        }

        // TODO!
        $payload = base64_decode($parts[$index]);

        return new Credentials($payload, $version);
    }

    public function getStorage(): PureStorage
    {
        return $this->storage;
    }

    public function getUpdateToken(): Credentials
    {
        return $this->updateToken;
    }

    /**
     * @param string $updateToken
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureLogicException
     */
    public function setUpdateToken(string $updateToken): void
    {
        $this->updateToken = self::parseCredentials(self::UPDATE_TOKEN_PREFIX, $updateToken, true);

        if ($this->updateToken->getVersion() != $this->appSecretKey->getVersion() + 1)
            throw new PureLogicException(ErrorStatus::UPDATE_TOKEN_VERSION_MISMATCH());
    }

    public function getAk(): Credentials
    {
        return $this->ak;
    }

    public function getBuppk(): VirgilPublicKey
    {
        return $this->buppk;
    }

    public function getOskp(): VirgilKeyPair
    {
        return $this->oskp;
    }

    public function getHpk(): VirgilPublicKey
    {
        return $this->hpk;
    }

    public function getAppSecretKey(): Credentials
    {
        return $this->appSecretKey;
    }

    public function getServicePublicKey(): Credentials
    {
        return $this->servicePublicKey;
    }

    public function getPheClient(): HttpPheClient
    {
        return $this->pheClient;
    }

    public function getExternalPublicKeys(): VirgilPublicKeyCollection
    {
        return $this->externalPublicKeys;
    }

    public function getCrypto(): VirgilCrypto
    {
        return $this->crypto;
    }
}