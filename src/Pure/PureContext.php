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


use Virgil\Crypto\Core\VirgilPublicKey;
use Virgil\Crypto\VirgilCrypto;
use Virgil\PureKit\Http\HttpKmsClient;
use Virgil\PureKit\Http\HttpPheClient;
use Virgil\PureKit\Http\HttpPureClient;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyMap;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureLogicErrorStatus;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Storage\PureStorage;
use Virgil\PureKit\Pure\Storage\VirgilCloudPureStorage;
use Virgil\PureKit\Pure\Util\ValidateUtil;

/**
 * Class PureContext
 * @package Virgil\PureKit\Pure
 */
class PureContext
{
    private const NMS_PREFIX = "NM";
    private const BUPPK_PREFIX = "BU";
    private const SECRET_KEY_PREFIX = "SK";
    private const PUBLIC_KEY_PREFIX = "PK";

    private $crypto;
    private $buppk;
    private $secretKey;
    private $publicKey;
    private $nonrotableSecrets;
    private $storage;
    private $pheClient;
    private $kmsClient;
    private $externalPublicKeys;
    private $updateToken;

    public function __construct(VirgilCrypto $crypto, string $appToken, string $nms, string $buppk,
                                string $secretKey, string $publicKey, PureStorage $storage,
                                array $externalPublicKeys,
                                string $pheServiceAddress, string $kmsServiceAddress)
    {
        ValidateUtil::checkNull($crypto, "crypto");
        ValidateUtil::checkNullOrEmpty($appToken, "appToken");
        ValidateUtil::checkNullOrEmpty($nms, "nms");
        ValidateUtil::checkNullOrEmpty($buppk, "bupkk");
        ValidateUtil::checkNullOrEmpty($secretKey, "secretKey");
        ValidateUtil::checkNullOrEmpty($publicKey, "publicKey");
        ValidateUtil::checkNull($storage, "storage");
        ValidateUtil::checkNullOrEmpty($pheServiceAddress, "pheServiceAddress");
        ValidateUtil::checkNullOrEmpty($kmsServiceAddress, "kmsServiceAddress");

        $this->crypto = $crypto;

        $nmsCred = self::parseCredentials(self::NMS_PREFIX, $nms, false, 1);
        $this->nonrotableSecrets = NonrotatableSecretsGenerator::generateSecrets($nmsCred->getPayload1());

        $buppkData = self::parseCredentials(self::BUPPK_PREFIX, $buppk, false, 1)->getPayload1();

        try {
            $this->buppk = $crypto->importPublicKey($buppkData);
        } catch (CryptoException $exception) {
            throw new PureCryptoException($exception);
        }

        $this->secretKey = self::parseCredentials(self::SECRET_KEY_PREFIX, $secretKey, true, 3);
        $this->publicKey = self::parseCredentials(self::PUBLIC_KEY_PREFIX, $publicKey, true, 2);
        $this->pheClient = new HttpPheClient($appToken, $pheServiceAddress, true);
        $this->kmsClient = new HttpKmsClient($appToken, $kmsServiceAddress, true);

        if ($storage instanceof PureModelSerializerDependent) {
            $dependent = $storage;

            $serializer = new PureModelSerializer($crypto, $this->nonrotableSecrets->getVskp());
            $dependent->setPureModelSerializer($serializer);
        }

        $this->storage = $storage;

        $this->externalPublicKeys = new VirgilPublicKeyMap();

        if (!empty($externalPublicKeys)) {
            foreach ($externalPublicKeys as $key => $publicKeysBase64) {

                foreach ($publicKeysBase64 as $publicKeyBase64) {
                    try {
                        $pubKey = $crypto->importPublicKey(base64_decode($publicKeyBase64));
                    } catch (CryptoException | \Exception $exception) {
                        throw new PureCryptoException($exception);
                    }

                    $this->externalPublicKeys->put($key, $pubKey);
                }

            }
        }

        if ($this->secretKey->getVersion() != $this->publicKey->getVersion())
            throw new PureLogicException(PureLogicErrorStatus::KEYS_VERSION_MISMATCH());
    }

    public static function createCustomContext(string $at, string $nm, string $bu,
                                               string $sk, string $pk, PureStorage $storage,
                                               array $externalPublicKeys = [],
                                               string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
                                               string $kmsServiceAddress = HttpKmsClient::SERVICE_ADDRESS): PureContext
    {
        return self::_createContext(
            new VirgilCrypto(),
            $at,
            $nm, $bu,
            $sk, $pk,
            $storage,
            $externalPublicKeys,
            $pheServiceAddress,
            $kmsServiceAddress
        );
    }

    public static function createVirgilContext(string $at, string $nm, string $bu, string $sk, string $pk,
                                               array $externalPublicKeys = [],
                                               string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
                                               string $pureServiceAddress = HttpPureClient::SERVICE_ADDRESS,
                                               string $kmsServiceAddress = HttpKmsClient::SERVICE_ADDRESS): PureContext
    {
        ValidateUtil::checkNullOrEmpty($at, "at");
        ValidateUtil::checkNullOrEmpty($pureServiceAddress, "pureServiceAddress");

        $crypto = new VirgilCrypto();
        $pureClient = new HttpPureClient($at, $pureServiceAddress);

        $storage = new VirgilCloudPureStorage($pureClient);

        return self::_createContext($crypto, $at, $nm, $bu, $sk, $pk, $storage, $externalPublicKeys,
            $pheServiceAddress, $kmsServiceAddress);
    }

    private static function _createContext(VirgilCrypto $crypto, string $appToken, string $nms, string $bu,
                                           string $sk, string $pk,
                                           PureStorage $storage,
                                           array $externalPublicKeys = [],
                                           string $pheServiceAddress, string $kmsServiceAddress): PureContext
    {
        return new self(
            $crypto, $appToken, $nms, $bu, $sk, $pk, $storage, $externalPublicKeys, $pheServiceAddress,
            $kmsServiceAddress
        );
    }

    private static function parseCredentials(string $prefix, string $credentials, bool $isVersioned, int
    $numberOfPayloads):
    Credentials
    {
        ValidateUtil::checkNullOrEmpty($prefix, "prefix");
        ValidateUtil::checkNullOrEmpty($credentials, "credentials");

        $parts = [];
        $parts = explode(".", $credentials);

        $numberOfParts = 1 + $numberOfPayloads + ($isVersioned ? 1 : 0);

        if (count($parts) != $numberOfParts)
            throw new PureLogicException(ErrorStatus::CREDENTIALS_PARSING_ERROR());

        $index = 0;

        if ($parts[$index] != $prefix)
            throw new PureLogicException(ErrorStatus::CREDENTIALS_PARSING_ERROR());

        $index++;

        if ($isVersioned) {
            $version = (int)$parts[$index];
            $index++;
        } else {
            $version = 0;
        }

        $payload1 = base64_decode($parts[$index]);
        $payload2 = null;
        $payload3 = null;

        $numberOfPayloads--;
        $index++;

        if ($numberOfPayloads > 0) {
            $payload2 = base64_decode($parts[$index]);
            $numberOfPayloads--;
            $index++;
        }

        if ($numberOfPayloads > 0)
            $payload3 = base64_decode($parts[$index]);

        return new Credentials($payload1, $payload2, $payload3, $version);
    }

    public function getStorage(): PureStorage
    {
        return $this->storage;
    }

    public function getUpdateToken(): ?Credentials
    {
        return $this->updateToken;
    }

    public function setUpdateToken(string $updateToken): void
    {
        $this->updateToken = self::parseCredentials(self::UPDATE_TOKEN_PREFIX, $updateToken, true, 3);

        if ($this->updateToken->getVersion() != $this->publicKey->getVersion() + 1)
            throw new PureLogicException(ErrorStatus::UPDATE_TOKEN_VERSION_MISMATCH());
    }

    public function setStorage(PureStorage $storage)
    {
        $this->storage = $storage;
    }

    public function getBuppk(): VirgilPublicKey
    {
        return $this->buppk;
    }

    public function getSecretKey(): Credentials
    {
        return $this->secretKey;
    }

    public function getPublicKey(): Credentials
    {
        return $this->publicKey;
    }

    public function getPheClient(): HttpPheClient
    {
        return $this->pheClient;
    }

    public function getKmsClient(): HttpKmsClient
    {
        return $this->kmsClient;
    }

    public function getExternalPublicKeys(): VirgilPublicKeyMap
    {
        return $this->externalPublicKeys;
    }

    public function getCrypto(): VirgilCrypto
    {
        return $this->crypto;
    }

    public function getNonrotableSecrets(): NonrotableSecrets
    {
        return $this->nonrotableSecrets;
    }
}