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
use Virgil\PureKit\Pure\Exception\ErrorStatus;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Storage\_\PureStorage;
use Virgil\PureKit\Pure\Util\ValidateUtil;

/**
 * Class PureContext
 * @package Virgil\PureKit\Pure
 */
class PureContext
{
    private const NMS_PREFIX = "NM";
    private const BUPPK_PREFIX = "BU";
    private const PHE_SECRET_KEY_PREFIX = "SK";
    private const PHE_PUBLIC_KEY_PREFIX = "PK";
    private const KMS_SECRET_KEY_PREFIX = "KS";
    private const KMS_PUBLIC_KEY_PREFIX = "KP";
    private const UPDATE_TOKEN_PREFIX = "UT";

    private $crypto;
    private $buppk;
    private $pheSecretKey;
    private $phePublicKey;
    private $kmsSecretKey;
    private $kmsPublicKey;
    private $nonrotableSecrets;
    private $storage;
    private $pheClient;
    private $externalPublicKeys;
    private $updateToken;

    public function __construct(VirgilCrypto $crypto, string $appToken, string $nms, string $buppk,
                                string $pheSecretKey, string $phePublicKey, string $kmsSecretKey,
                                string $kmsPublicKey, PureStorage $storage,
                                VirgilPublicKeyCollection $externalPublicKeys,
                                string $pheServiceAddress)
    {
        ValidateUtil::checkNull($storage, "storage");

        $this->crypto = $crypto;

        $nmsCred = self::parseCredentials(self::NMS_PREFIX, $nms, false);
        $this->nonrotableSecrets = NonrotatableSecretsGenerator::generateSecrets($nmsCred->getPayload());

        $buppkData = self::parseCredentials(self::BUPPK_PREFIX, $buppk, false)->getPayload();
        $this->buppk = $crypto->importPublicKey($buppkData);

        $this->pheSecretKey = self::parseCredentials(self::PHE_SECRET_KEY_PREFIX, $pheSecretKey, true);
        $this->phePublicKey = self::parseCredentials(self::PHE_PUBLIC_KEY_PREFIX, $phePublicKey, true);
        $this->kmsSecretKey = self::parseCredentials(self::KMS_SECRET_KEY_PREFIX, $kmsSecretKey, true);
        $this->kmsPublicKey = self::parseCredentials(self::KMS_PUBLIC_KEY_PREFIX, $kmsPublicKey, true);

        if ($storage instanceof PureModelSerializerDependent) {
            $dependent = $storage;

            $serializer = new PureModelSerializer($crypto, $this->nonrotableSecrets->getVskp());
            $dependent->setPureModelSerializer($serializer);
        }

        $this->storage = $storage;

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

        if (
            $this->pheSecretKey->getVersion() != $this->phePublicKey->getVersion()
            || $this->kmsSecretKey->getVersion() != $this->kmsPublicKey->getVersion()
            || $this->phePublicKey->getVersion() != $this->kmsPublicKey->getVersion()
        ) {
            throw new PureLogicException(ErrorStatus::KEYS_VERSION_MISMATCH());
        }
    }

    public static function createCustomContext(string $appToken, string $nms, string $bu,
                                               PureStorage $storage, string $sk, string $pk, string $ks, string $kp,
                                               VirgilPublicKeyCollection $externalPublicKeys,
                                               string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
                                                string $kmsServiceAddress = HttpKmsClient::SERVICE_ADDRESS): PureContext
    {
        return self::_createContext(
            new VirgilCrypto(),
            $appToken,
            $nms, $bu,
            $sk, $pk, $ks, $kp,
            $storage,
            $externalPublicKeys,
            $pheServiceAddress,
            $kmsServiceAddress
        );
    }

    public static function createVirgilContext(string $appToken, string $nms, string $bu, string $sk, string $pk,
                                               string $ks, string $kp,
                                               VirgilPublicKeyCollection $externalPublicKeys,
                                               string $pheServiceAddress = HttpPheClient::SERVICE_ADDRESS,
                                               string $pureServiceAddress = HttpPureClient::SERVICE_ADDRESS,
                                               string $kmsServiceAddress = HttpKmsClient::SERVICE_ADDRESS): PureContext
    {
        $crypto = new VirgilCrypto();
        $pureClient = new HttpPureClient($appToken, $pureServiceAddress);

        $storage = new VirgilCloudPureStorage($crypto, $pureClient);

        return self::_createContext($crypto, $appToken, $nms, $bu, $sk, $pk, $ks, $kp, $storage, $externalPublicKeys,
            $pheServiceAddress, $kmsServiceAddress);
    }

    private static function _createContext(VirgilCrypto $crypto, string $appToken, string $nms, string $bu,
                                           string $sk, string $pk, string $ks, string $kp,
                                           PureStorage $storage,
                                           VirgilPublicKeyCollection $externalPublicKeys,
                                           string $pheServiceAddress, string $kmsServiceAddress): PureContext
    {
        return new self(
            $crypto, $appToken, $nms, $bu, $sk, $pk, $ks, $kp, $storage, $externalPublicKeys, $pheServiceAddress,
            $kmsServiceAddress
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

        if ($this->updateToken->getVersion() != $this->pheSecretKey->getVersion() + 1)
            throw new PureLogicException(ErrorStatus::UPDATE_TOKEN_VERSION_MISMATCH());
    }

    public function getBuppk(): VirgilPublicKey
    {
        return $this->buppk;
    }

    public function getPheSecretKey(): Credentials
    {
        return $this->pheSecretKey;
    }

    public function getPhePublicKey(): Credentials
    {
        return $this->phePublicKey;
    }

    public function getKmsSecretKey(): Credentials
    {
    return $this->kmsSecretKey;
    }

    public function getKmsPublicKey(): Credentials
    {
        return $this->kmsPublicKey;
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

    public function getNonrotableSecrets(): NonrotableSecrets
    {
        return $this->nonrotableSecrets;
    }
}