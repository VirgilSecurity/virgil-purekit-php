<?php
/**
 * Copyright (c) 2015-2024 Virgil Security Inc.
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

use Exception;
use Virgil\Crypto\Core\VirgilKeys\VirgilPublicKey;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\Crypto\VirgilCrypto;
use Virgil\PureKit\Http\HttpKmsClient;
use Virgil\PureKit\Http\HttpPheClient;
use Virgil\PureKit\Http\HttpPureClient;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyMap;
use Virgil\PureKit\Pure\Exception\EmptyArgumentException;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureLogicErrorStatus;
use Virgil\PureKit\Pure\Exception\IllegalStateException;
use Virgil\PureKit\Pure\Exception\NullArgumentException;
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
    private const array PREFIXES = [
        'NMS' => 'NM',
        'BUPPK' => 'BU',
        'SECRET_KEY' => 'SK',
        'PUBLIC_KEY' => 'PK',
        'UPDATE_TOKEN' => 'UT'
    ];

    private const array NUMBER_OF_PAYLOADS = [
        self::PREFIXES['NMS'] => 1,
        self::PREFIXES['BUPPK'] => 1,
        self::PREFIXES['SECRET_KEY'] => 3,
        self::PREFIXES['PUBLIC_KEY'] => 2,
        self::PREFIXES['UPDATE_TOKEN'] => 3,
    ];

    private VirgilCrypto $crypto;
    private VirgilPublicKey $buppk;
    private Credentials $secretKey;
    private Credentials $publicKey;
    private NonrotableSecrets $nonrotableSecrets;
    private PureStorage|PureModelSerializerDependent $storage;
    private HttpPheClient $pheClient;
    private HttpKmsClient $kmsClient;
    private VirgilPublicKeyMap $externalPublicKeys;
    private ?Credentials $updateToken = null;

    /**
     * PureContext constructor.
     *
     * @param VirgilCrypto $crypto
     * @param string $appToken
     * @param string $nms
     * @param string $buppk
     * @param string $secretKey
     * @param string $publicKey
     * @param PureModelSerializerDependent|PureStorage $storage
     * @param array $externalPublicKeys
     * @param string $pheServiceAddress
     * @param string $kmsServiceAddress
     *
     * @throws EmptyArgumentException
     * @throws NullArgumentException
     * @throws PureCryptoException
     * @throws PureLogicException
     */
    public function __construct(
        VirgilCrypto $crypto,
        string $appToken,
        string $nms,
        string $buppk,
        string $secretKey,
        string $publicKey,
        PureModelSerializerDependent|PureStorage $storage,
        array $externalPublicKeys,
        string $pheServiceAddress,
        string $kmsServiceAddress
    ) {
        // Validate inputs
        ValidationUtils::checkNull($crypto, "crypto");
        ValidationUtils::checkNullOrEmpty($appToken, "appToken");
        ValidationUtils::checkNullOrEmpty($nms, "nms");
        ValidationUtils::checkNullOrEmpty($buppk, "buppk");
        ValidationUtils::checkNullOrEmpty($secretKey, "secretKey");
        ValidationUtils::checkNullOrEmpty($publicKey, "publicKey");
        ValidationUtils::checkNull($storage, "storage");
        ValidationUtils::checkNullOrEmpty($pheServiceAddress, "pheServiceAddress");
        ValidationUtils::checkNullOrEmpty($kmsServiceAddress, "kmsServiceAddress");

        // Initialize properties
        $this->crypto = $crypto;

        $nmsCred = self::parseCredentials(self::PREFIXES['NMS'], $nms, false);
        $this->nonrotableSecrets = NonrotatableSecretsGenerator::generateSecrets($nmsCred->getPayload1());

        $buppkData = self::parseCredentials(self::PREFIXES['BUPPK'], $buppk, false)->getPayload1();

        try {
            $this->buppk = $crypto->importPublicKey($buppkData);
        } catch (VirgilCryptoException $exception) {
            throw new PureCryptoException($exception);
        }

        $this->secretKey = self::parseCredentials(self::PREFIXES['SECRET_KEY'], $secretKey, true);
        $this->publicKey = self::parseCredentials(self::PREFIXES['PUBLIC_KEY'], $publicKey, true);
        $this->pheClient = new HttpPheClient($appToken, $pheServiceAddress);
        $this->kmsClient = new HttpKmsClient($appToken, $kmsServiceAddress);

        if ($storage instanceof PureModelSerializerDependent) {
            $serializer = new PureModelSerializer($crypto, $this->nonrotableSecrets->getVskp());
            $storage->setPureModelSerializer($serializer);
        }

        $this->storage = $storage;
        $this->externalPublicKeys = new VirgilPublicKeyMap();

        if (!empty($externalPublicKeys)) {
            foreach ($externalPublicKeys as $key => $publicKeysBase64) {
                foreach ($publicKeysBase64 as $publicKeyBase64) {
                    try {
                        $pubKey = $crypto->importPublicKey(base64_decode($publicKeyBase64));
                    } catch (VirgilCryptoException | Exception $exception) {
                        throw new PureCryptoException($exception);
                    }
                    $this->externalPublicKeys->put($key, $pubKey);
                }
            }
        }
        if ($this->secretKey->getVersion() != $this->publicKey->getVersion()) {
            throw new PureLogicException(PureLogicErrorStatus::KEYS_VERSION_MISMATCH());
        }
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
     * @throws Exception
     */
    public static function createCustomContext(
        string $at,
        string $nm,
        string $bu,
        string $sk,
        string $pk,
        PureStorage $storage,
        array $externalPublicKeys = [],
        string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
        string $kmsServiceAddress = HttpKmsClient::SERVICE_ADDRESS
    ): PureContext {
        return self::_createContext(
            new VirgilCrypto(),
            $at,
            $nm,
            $bu,
            $sk,
            $pk,
            $storage,
            $pheServiceAddress,
            $kmsServiceAddress,
            $externalPublicKeys
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
     * @throws EmptyArgumentException
     * @throws NullArgumentException
     * @throws PureCryptoException
     * @throws PureLogicException
     */
    public static function createVirgilContext(
        string $at,
        string $nm,
        string $bu,
        string $sk,
        string $pk,
        array $externalPublicKeys = [],
        string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
        string $pureServiceAddress = HttpPureClient::SERVICE_ADDRESS,
        string $kmsServiceAddress = HttpKmsClient::SERVICE_ADDRESS
    ): PureContext {
        ValidationUtils::checkNullOrEmpty($at, "at");
        ValidationUtils::checkNullOrEmpty($pureServiceAddress, "pureServiceAddress");

        $crypto = new VirgilCrypto();
        $pureClient = new HttpPureClient($at, $pureServiceAddress);

        $storage = new VirgilCloudPureStorage($pureClient);

        return self::_createContext(
            $crypto,
            $at,
            $nm,
            $bu,
            $sk,
            $pk,
            $storage,
            $pheServiceAddress,
            $kmsServiceAddress,
            $externalPublicKeys
        );
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
     * @throws EmptyArgumentException
     * @throws NullArgumentException
     * @throws PureCryptoException
     * @throws PureLogicException
     */
    private static function _createContext(
        VirgilCrypto $crypto,
        string $appToken,
        string $nms,
        string $bu,
        string $sk,
        string $pk,
        PureStorage $storage,
        string $pheServiceAddress,
        string $kmsServiceAddress,
        array $externalPublicKeys = []
    ): PureContext {
        return new self(
            $crypto,
            $appToken,
            $nms,
            $bu,
            $sk,
            $pk,
            $storage,
            $externalPublicKeys,
            $pheServiceAddress,
            $kmsServiceAddress
        );
    }

    /**
     * @param string $prefix
     * @param string $credentials
     * @param bool $isVersioned
     * @return Credentials
     * @throws EmptyArgumentException
     * @throws NullArgumentException
     * @throws PureLogicException
     */
    private static function parseCredentials(string $prefix, string $credentials, bool $isVersioned):
    Credentials
    {
        $numberOfPayloads = self::NUMBER_OF_PAYLOADS[$prefix];
        ValidationUtils::checkNullOrEmpty($prefix, "prefix");
        ValidationUtils::checkNullOrEmpty($credentials, "credentials");

        $parts = explode(".", $credentials);

        $numberOfParts = 1 + $numberOfPayloads + ($isVersioned ? 1 : 0);

        if (count($parts) != $numberOfParts) {
            throw new PureLogicException(PureLogicErrorStatus::CREDENTIALS_PARSING_ERROR());
        }

        $index = 0;

        if ($parts[$index] != $prefix) {
            throw new PureLogicException(PureLogicErrorStatus::CREDENTIALS_PARSING_ERROR());
        }

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

        if ($numberOfPayloads > 0) {
            $payload3 = base64_decode($parts[$index]);
        }

        return new Credentials($version, $payload1, $payload2, $payload3);
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
     * @throws EmptyArgumentException
     * @throws NullArgumentException
     * @throws PureLogicException
     */
    public function setUpdateToken(string $updateToken): void
    {
        $this->updateToken = self::parseCredentials(self::PREFIXES['UPDATE_TOKEN'], $updateToken, true);

        if ($this->updateToken->getVersion() != $this->publicKey->getVersion() + 1) {
            throw new PureLogicException(PureLogicErrorStatus::UPDATE_TOKEN_VERSION_MISMATCH());
        }
    }

    /**
     * @param PureStorage $storage
     */
    public function setStorage(PureStorage $storage): void
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
