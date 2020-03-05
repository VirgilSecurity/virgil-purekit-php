<?php
/**
 * Copyright (c) 2015-2020 Virgil Security Inc.
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
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyMap;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureLogicErrorStatus;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Storage\PureStorage;
use Virgil\PureKit\Pure\Storage\VirgilCloudPureStorage;
use Virgil\PureKit\Pure\Util\ValidationUtils;

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
    private const UPDATE_TOKEN_PREFIX = "UT";

    /**
     * @var VirgilCrypto
     */
    private $crypto;
    /**
     * @var VirgilPublicKey
     */
    private $buppk;
    /**
     * @var Credentials
     */
    private $secretKey;
    /**
     * @var Credentials
     */
    private $publicKey;
    /**
     * @var NonrotableSecrets
     */
    private $nonrotableSecrets;
    /**
     * @var PureModelSerializerDependent|PureStorage
     */
    private $storage;
    /**
     * @var HttpPheClient
     */
    private $pheClient;
    /**
     * @var HttpKmsClient
     */
    private $kmsClient;
    /**
     * @var VirgilPublicKeyMap
     */
    private $externalPublicKeys;
    /**
     * @var
     */
    private $updateToken;

    /**
     * PureContext constructor.
     * @param VirgilCrypto $crypto
     * @param string $appToken
     * @param string $nms
     * @param string $buppk
     * @param string $secretKey
     * @param string $publicKey
     * @param PureStorage $storage
     * @param array $externalPublicKeys
     * @param string $pheServiceAddress
     * @param string $kmsServiceAddress
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureCryptoException
     * @throws PureLogicException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function __construct(VirgilCrypto $crypto, string $appToken, string $nms, string $buppk,
                                string $secretKey, string $publicKey, PureStorage $storage,
                                array $externalPublicKeys,
                                string $pheServiceAddress, string $kmsServiceAddress)
    {
        ValidationUtils::checkNull($crypto, "crypto");
        ValidationUtils::checkNullOrEmpty($appToken, "appToken");
        ValidationUtils::checkNullOrEmpty($nms, "nms");
        ValidationUtils::checkNullOrEmpty($buppk, "bupkk");
        ValidationUtils::checkNullOrEmpty($secretKey, "secretKey");
        ValidationUtils::checkNullOrEmpty($publicKey, "publicKey");
        ValidationUtils::checkNull($storage, "storage");
        ValidationUtils::checkNullOrEmpty($pheServiceAddress, "pheServiceAddress");
        ValidationUtils::checkNullOrEmpty($kmsServiceAddress, "kmsServiceAddress");

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

    /**
     * @param string $at
     * @param string $nm
     * @param string $bu
     * @param string $sk
     * @param string $pk
     * @param PureStorage $storage
     * @param array $externalPublicKeys
     * @param string $pheServiceAddress
     * @param string $kmsServiceAddress
     * @return PureContext
     * @throws \Exception
     */
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

    /**
     * @param string $at
     * @param string $nm
     * @param string $bu
     * @param string $sk
     * @param string $pk
     * @param array $externalPublicKeys
     * @param string $pheServiceAddress
     * @param string $pureServiceAddress
     * @param string $kmsServiceAddress
     * @return PureContext
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureCryptoException
     * @throws PureLogicException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public static function createVirgilContext(string $at, string $nm, string $bu, string $sk, string $pk,
                                               array $externalPublicKeys = [],
                                               string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
                                               string $pureServiceAddress = HttpPureClient::SERVICE_ADDRESS,
                                               string $kmsServiceAddress = HttpKmsClient::SERVICE_ADDRESS): PureContext
    {
        ValidationUtils::checkNullOrEmpty($at, "at");
        ValidationUtils::checkNullOrEmpty($pureServiceAddress, "pureServiceAddress");

        $crypto = new VirgilCrypto();
        $pureClient = new HttpPureClient($at, $pureServiceAddress);

        $storage = new VirgilCloudPureStorage($pureClient);

        return self::_createContext($crypto, $at, $nm, $bu, $sk, $pk, $storage, $externalPublicKeys,
            $pheServiceAddress, $kmsServiceAddress);
    }

    /**
     * @param VirgilCrypto $crypto
     * @param string $appToken
     * @param string $nms
     * @param string $bu
     * @param string $sk
     * @param string $pk
     * @param PureStorage $storage
     * @param array $externalPublicKeys
     * @param string $pheServiceAddress
     * @param string $kmsServiceAddress
     * @return PureContext
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureCryptoException
     * @throws PureLogicException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
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

    /**
     * @param string $prefix
     * @param string $credentials
     * @param bool $isVersioned
     * @param int $numberOfPayloads
     * @return Credentials
     * @throws Exception\EmptyArgumentException
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureLogicException
     */
    private static function parseCredentials(string $prefix, string $credentials, bool $isVersioned, int
    $numberOfPayloads):
    Credentials
    {
        ValidationUtils::checkNullOrEmpty($prefix, "prefix");
        ValidationUtils::checkNullOrEmpty($credentials, "credentials");

        $parts = [];
        $parts = explode(".", $credentials);

        $numberOfParts = 1 + $numberOfPayloads + ($isVersioned ? 1 : 0);

        if (count($parts) != $numberOfParts) {
            throw new PureLogicException(PureLogicErrorStatus::CREDENTIALS_PARSING_ERROR());
        }

        $index = 0;

        if ($parts[$index] != $prefix)
            throw new PureLogicException(PureLogicErrorStatus::CREDENTIALS_PARSING_ERROR());

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

    /**
     * @return PureStorage
     */
    public function getStorage(): PureStorage
    {
        return $this->storage;
    }

    /**
     * @return null|Credentials
     */
    public function getUpdateToken(): ?Credentials
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
        $this->updateToken = self::parseCredentials(self::UPDATE_TOKEN_PREFIX, $updateToken, true, 3);

        if ($this->updateToken->getVersion() != $this->publicKey->getVersion() + 1)
            throw new PureLogicException(PureLogicErrorStatus::UPDATE_TOKEN_VERSION_MISMATCH());
    }

    /**
     * @param PureStorage $storage
     */
    public function setStorage(PureStorage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * @return VirgilPublicKey
     */
    public function getBuppk(): VirgilPublicKey
    {
        return $this->buppk;
    }

    /**
     * @return Credentials
     */
    public function getSecretKey(): Credentials
    {
        return $this->secretKey;
    }

    /**
     * @return Credentials
     */
    public function getPublicKey(): Credentials
    {
        return $this->publicKey;
    }

    /**
     * @return HttpPheClient
     */
    public function getPheClient(): HttpPheClient
    {
        return $this->pheClient;
    }

    /**
     * @return HttpKmsClient
     */
    public function getKmsClient(): HttpKmsClient
    {
        return $this->kmsClient;
    }

    /**
     * @return VirgilPublicKeyMap
     */
    public function getExternalPublicKeys(): VirgilPublicKeyMap
    {
        return $this->externalPublicKeys;
    }

    /**
     * @return VirgilCrypto
     */
    public function getCrypto(): VirgilCrypto
    {
        return $this->crypto;
    }

    /**
     * @return NonrotableSecrets
     */
    public function getNonrotableSecrets(): NonrotableSecrets
    {
        return $this->nonrotableSecrets;
    }
}