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

namespace Virgil\PureKit\Tests;

use Virgil\CryptoImpl\Core\KeyPairType;
use Virgil\CryptoImpl\VirgilCrypto;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\PureContext;
use Virgil\PureKit\Pure\PureModelSerializer;
use Virgil\PureKit\Pure\PureSetupResult;
use Virgil\PureKit\Pure\Storage\MariaDBPureStorage;
use Virgil\PureKit\Pure\Storage\RamPureStorage;
use Virgil\PureKit\Pure\Storage\StorageType;

class PureTest extends \PHPUnit\Framework\TestCase
{
    private $crypto;

    protected function setUp(): void
    {

    }

    private function sleep(int $seconds = 2)
    {
        sleep($seconds);
    }

    /**
     * @param string $pheServerAddress
     * @param string $pureServerAddress
     * @param string $appToken
     * @param string $publicKey
     * @param string $secretKey
     * @param string $updateToken
     * @param VirgilPublicKeyCollection $externalPublicKeys
     * @param StorageType $storageType
     * @return PureSetupResult
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\PureLogicException
     */
    private function setupPure(
        string $pheServerAddress,
        string $pureServerAddress,
        string $appToken,
        string $publicKey,
        string $secretKey,
        string $updateToken,
        VirgilPublicKeyCollection $externalPublicKeys,
        StorageType $storageType): PureSetupResult
    {
        $this->crypto = new VirgilCrypto();

        $bupkp = $this->crypto->generateKeyPair(KeyPairType::ED25519());
        $hkp = $this->crypto->generateKeyPair(KeyPairType::ED25519());
        $oskp = $this->crypto->generateKeyPair(KeyPairType::ED25519());

        $akData = $this->crypto->generateRandomData(32);
        $akString = "AK." . base64_encode($akData);

        $bupkpString = "BU.". base64_encode($this->crypto->exportPublicKey($bupkp->getPublicKey()));
        $hkpString = "HB.". base64_encode($this->crypto->exportPublicKey($hkp->getPublicKey()));
        $oskpString = "OS." . base64_encode($this->crypto->exportPrivateKey($oskp->getPrivateKey()));

        $signingKeyPair = $this->crypto->generateKeyPair();
        $vsString = "VS." . base64_encode($this->crypto->exportPrivateKey($signingKeyPair->getPrivateKey()));

        switch ($storageType) {
            case StorageType::RAM():
                $context = PureContext::createContext($appToken, $akString, $bupkpString, $hkpString, $oskpString,
                new RamPureStorage(), $secretKey, $publicKey, $externalPublicKeys, $pheServerAddress);
                break;

            case StorageType::VIRGIL_CLOUD():
                $context = PureContext::createContext($appToken, $akString, $bupkpString, $hkpString, $oskpString,
                    $vsString, $secretKey, $publicKey, $externalPublicKeys, $pheServerAddress, $pureServerAddress);
                break;

            case StorageType::MARIADB():
                $pureModelSerializer = new PureModelSerializer($this->crypto, $signingKeyPair);
                $mariaDbPureStorage = new MariaDbPureStorage("jdbc:mariadb://localhost/puretest?user=root&password=qwerty",
                    $pureModelSerializer);
                $context = PureContext::createContext($appToken, $akString, $bupkpString, $hkpString, $oskpString,
                $mariaDbPureStorage, $secretKey, $publicKey, $externalPublicKeys, $pheServerAddress);
                break;

            default:
                throw new \Exception("Null Pointer Exception");
        }

        if (!is_null($updateToken))
            $context->setUpdateToken($updateToken);

        return new PureSetupResult($context, $bupkp, $hkp);
    }

    private static function createStorages(): array
    {
        $storages = [];
        $storages[0] = StorageType::VIRGIL_CLOUD();
        return $storages;
    }
}