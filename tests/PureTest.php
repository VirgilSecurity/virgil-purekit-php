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

use Virgil\Crypto\Core\KeyPairType;
use Virgil\Crypto\VirgilCrypto;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Pure;
use Virgil\PureKit\Pure\PureContext;
use Virgil\PureKit\Pure\PureSetupResult;
use Virgil\PureKit\Pure\Storage\_\StorageType;
use Virgil\PureKit\Pure\Storage\MariaDBPureStorage;
use Virgil\PureKit\Pure\Storage\RamPureStorage;

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
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
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

        $nmsData = $this->crypto->generateRandomData(32);
        $nmsString = "NM." . base64_encode($nmsData);

        $bupkpString = "BU." . base64_encode($this->crypto->exportPublicKey($bupkp->getPublicKey()));

        switch ($storageType) {
            case StorageType::RAM():
                $context = PureContext::createContext($appToken, $nmsString, $bupkpString,
                    new RamPureStorage(), $secretKey, $publicKey, $externalPublicKeys, $pheServerAddress);
                break;

            case StorageType::VIRGIL_CLOUD():
                $context = PureContext::createContext($appToken, $nmsString, $bupkpString, $secretKey, $publicKey, $externalPublicKeys, $pheServerAddress, $pureServerAddress);
                break;

            case StorageType::MARIADB():
                $mariaDbPureStorage = new MariaDbPureStorage("jdbc:mariadb://localhost/puretest?user=root&password=qwerty");
                $context = PureContext::createContext($appToken, $nmsString, $bupkpString,
                    $mariaDbPureStorage, $secretKey, $publicKey, $externalPublicKeys, $pheServerAddress);
                break;

            default:
                throw new \Exception("Null Pointer Exception");
        }

        if (!is_null($updateToken))
            $context->setUpdateToken($updateToken);

        return new PureSetupResult($context, $bupkp);
    }

    /**
     * @return array
     */
    private static function createStorages(): array
    {
        $storages = [];
        $storages[0] = StorageType::VIRGIL_CLOUD();
        return $storages;
    }

    /**
     * @param string $pheServerAddress
     * @param string $pureServerAddress
     * @param string $appToken
     * @param string $publicKey
     * @param string $secretKey
     */
    public function testRegistrationNewUserShouldSucceed(
        string $pheServerAddress,
        string $pureServerAddress,
        string $appToken,
        string $publicKey,
        string $secretKey): void
    {
        $this->sleep();

        try {
            $storages = self::createStorages();

            foreach ($storages as $storage) {
                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey, null, null, $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = (string)rand(1000, 9999);
                $password = (string)rand(1000, 9999);

                $pure->registerUser($userId, $password);
            }

        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    /**
     * @param string $pheServerAddress
     * @param string $pureServerAddress
     * @param string $appToken
     * @param string $publicKey
     * @param string $secretKey
     */
    public function testAuthenticationNewUserShouldSucceed(string $pheServerAddress,
                                                           string $pureServerAddress,
                                                           string $appToken,
                                                           string $publicKey,
                                                           string $secretKey): void
    {
        $this->sleep();

        try {
            $storages = self::createStorages();

            foreach ($storages as $storage) {
                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey, null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string)rand(1000, 9999);
                $password = (string)rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $authResult = $pure->authenticateUser($userId, $password);

                $this->assertNotNull($authResult->getEncryptedGrant());

                $grant = $authResult->getGrant();

                $this->assertNotNull($grant);

                $this->assertEquals($userId, $grant->getUserId());
                $this->assertNull($grant->getSessionId());
                $this->assertNotNull($grant->getUkp());
                $this->assertNotNull($grant->getCreationDate());
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testEncryptionRandomDataShouldMatch(string $pheServerAddress,
                                                        string $pureServerAddress,
                                                        string $appToken,
                                                        string $publicKey,
                                                        string $secretKey): void
    {
        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey, null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string)rand(1000, 9999);
                $password = (string)rand(1000, 9999);
                $dataId = (string)rand(1000, 9999);
                $text = (string)rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $authResult = $pure->authenticateUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $plainText = $pure->decrypt($authResult->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    /**
     * @param string $pheServerAddress
     * @param string $pureServerAddress
     * @param string $appToken
     * @param string $publicKey
     * @param string $secretKey
     */
    public function testSharing2UsersShouldDecrypt(
        string $pheServerAddress,
        string $pureServerAddress,
        string $appToken,
        string $publicKey,
        string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey, null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = (string)rand(1000, 9999);
                $userId2 = (string)rand(1000, 9999);
                $password1 = (string)rand(1000, 9999);
                $password2 = (string)rand(1000, 9999);
                $dataId = (string)rand(1000, 9999);
                $text = (string)rand(1000, 9999);

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $cipherText = $pure->encrypt($userId1, $dataId, $text);

                $pure->share($authResult1->getGrant(), $dataId, $userId2);

                $plainText1 = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
                $plainText2 = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText1);
                $this->assertEquals($text, $plainText2);
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testSharingRevokeAccessShouldNotDecrypt(string $pheServerAddress,
                                                            string $pureServerAddress,
                                                            string $appToken,
                                                            string $publicKey,
                                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey, null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = (string)rand(1000, 9999);
                $userId2 = (string)rand(1000, 9999);
                $password1 = (string)rand(1000, 9999);
                $password2 = (string)rand(1000, 9999);
                $dataId = (string)rand(1000, 9999);
                $text = (string)rand(1000, 9999);

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $cipherText = $pure->encrypt($userId1, $dataId, $text);

                $pure->share($authResult1->getGrant(), $dataId, $userId2);
                $pure->unshare($userId1, $dataId, $userId2);

                $this->expectException("PureLogicException");
                $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);
            }
        } catch (\Exception $exception) {
            // TODO!
            $this->assertEquals($exception->getErrorStatus(), ErrorStatus::USER_HAS_NO_ACCESS_TO_DATA());
            $this->fail($exception->getMessage());
        }
    }

    public function testGrantChangePasswordShouldNotDecrypt(
        string $pheServerAddress,
        string $pureServerAddress,
        string $appToken,
        string $publicKey,
        string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey, null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string)rand(1000, 9999);
                $password1 = (string)rand(1000, 9999);
                $password2 = (string)rand(1000, 9999);

                $pure->registerUser($userId, $password1);

                $authResult1 = $pure->authenticateUser($userId, $password1);

                $grant = $pure->decryptGrantFromUser($authResult1->getEncryptedGrant());

                $this->assertNotNull($grant);

                $this->assertEquals($grant->getSessionId(), $authResult1->getGrant()->getSessionId());
                $this->assertEquals($grant->getUserId(), $authResult1->getGrant()->getUserId());
                $this->assertEquals($grant->getUkp()->getPrivateKey()->getIdentifier(), $authResult1->getGrant()->getUkp()->getPrivateKey()->getIdentifier());

                $pure->changeUserPassword($userId, $password1, $password2);

                $this->expectException("PureCryptoException");
                $pure->decryptGrantFromUser($authResult1->getEncryptedGrant());
            }
        } catch (\Exception $exception) {
            $this->assertEquals($exception->getStatusCode(), ErrorStatus::ERROR_AES_FAILED());
            $this->fail($exception->getMessage());
        }
    }

    public function testGrantAdminAccessShouldDecrypt(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey, $secretKey,
                        null, null, $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = (string)rand(1000, 9999);
                $password = (string)rand(1000, 9999);
                $dataId = (string)rand(1000, 9999);
                $text = (string)rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $adminGrant = $pure->createUserGrantAsAdmin($userId, $pureResult->getBupkp()->getPrivateKey());

                $this->assertNotNull($adminGrant);

                $plainText = $pure->decrypt($adminGrant, null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testResetPwdNewUserShouldNotDecrypt(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, null, $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = (string)rand(1000, 9999);
                $password1 = (string)rand(1000, 9999);
                $password2 = (string)rand(1000, 9999);
                $dataId = (string)rand(1000, 9999);
                $text = (string)rand(1000, 9999);

                $pure->registerUser($userId, $password1);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $pure->resetUserPassword($userId, $password2);

                $authResult = $pure->authenticateUser($userId, $password2);

                $this->assertNotNull($authResult);
                $pure->decrypt($authResult->getGrant(), null, $dataId, $cipherText);
            }
        } catch (\Exception $exception) {

            $this->assertEquals($exception->getErrorStatus(), ErrorStatus::USER_HAS_NO_ACCESS_TO_DATA());
            $this->fail($exception->getMessage());
        }
    }


    public function testRestorePwdNewUserShouldDecrypt(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string)rand(1000, 9999);
                $password1 = (string)rand(1000, 9999);
                $password2 = (string)rand(1000, 9999);
                $dataId = (string)rand(1000, 9999);
                $text = (string)rand(1000, 9999);

                $pure->registerUser($userId, $password1);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $adminGrant = $pure->createUserGrantAsAdmin($userId, $pureResult->getBupkp()->getPrivateKey());

                $pure->changeUserPassword($adminGrant, $password2);

                $authResult = $pure->authenticateUser($userId, $password2);

                $this->assertNotNull($authResult);

                $plainText = $pure->decrypt($authResult->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testRotationLocalStorageShouldRotate(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey, string $updateToken): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // VirgilCloudPureStorage should not support that
                if (StorageType::VIRGIL_CLOUD() == $storage) {
                    continue;
                }

                $total = 30;

                    $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                        $secretKey,
                            null, null, $storage);
                    $pure = new Pure($pureResult->getContext());
                    $pureStorage = $pure->getStorage();

                    if (StorageType::MARIADB() == $storage) {
                        $mariaDbPureStorage = $pure->getStorage();
                        $mariaDbPureStorage->dropTables();
                        $mariaDbPureStorage->createTables();
                    }

                    for ($i = 0; $i < $total; $i++) {
                    $userId = (string) rand(1000, 9999);
                        $password = (string) rand(1000, 9999);

                        $pure->registerUser($userId, $password);
                    }

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        $updateToken, null, $storage);
                $pureResult->getContext()->setStorage($pureStorage);
                $pure = new Pure($pureResult->getContext());

                $rotated = $pure->performRotation();

                $this->assertEquals($total, $rotated);

                // TODO: Check auth and decryption works

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testPerformance(string $pheServerAddress,
                                    string $pureServerAddress,
                                    string $appToken,
                                    string $publicKey,
                                    string $secretKey,
                                    string $updateToken): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                if (StorageType::VIRGIL_CLOUD() == $storage) {
                    continue;
                }

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $total = 10;

                for ($i = 0; $i < $total; $i++) {
                    $userId = (string) rand(1000, 9999);
                    $password = (string) rand(1000, 9999);

                    // TODO! Add in ms
                    $startTime = new \DateTime("now");

                    $pure->registerUser($userId, $password);

                    $finishTime = new \DateTime("now");

                    $diff = $finishTime - $startTime;

//                    var_dump("That took: " . $diff . " ms");
                }

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testEncryptionAdditionalKeysShouldDecrypt(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = (string)rand(1000, 9999);
                $userId2 = (string)rand(1000, 9999);
                $password1 = (string)rand(1000, 9999);
                $password2 = (string)rand(1000, 9999);
                $dataId = (string)rand(1000, 9999);
                $text = (string)rand(1000, 9999);

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $keyPair = $pure->getCrypto()->generateKeyPair();

                $cipherText = $pure->encrypt($userId1, $dataId, $userId2, [],
                    $keyPair->getPublicKey(), $text);

                $plainText = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

                $plainText = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

                $plainText = $pure->decrypt($keyPair->getPrivateKey(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testEncryptionExternalKeysShouldDecrypt(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $keyPair = $this->crypto->generateKeyPair();
                $dataId = (string) rand(1000, 9999);
                $publicKeyBase64 = base64_encode($this->crypto->exportPublicKey($keyPair->getPublicKey()));
//                Map<String, List<String>> externalPublicKeys = Collections.singletonMap(dataId, Collections.singletonList(publicKeyBase64));

                $externalPublicKeys = [$dataId => $publicKeyBase64];

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, $externalPublicKeys, $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = (string) rand(1000, 9999);
                $password = (string) rand(1000, 9999);

                $text = (string) rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $plainText = $pure->decrypt($keyPair->getPrivateKey(), $userId, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testDeleteUserCascadeShouldDeleteUserAndKeys(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string) rand(1000, 9999);
                $password = (string) rand(1000, 9999);
                $dataId = (string) rand(1000, 9999);
                $text = (string) rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $authResult1 = $pure->authenticateUser($userId, $password);

                $pure->deleteUser($userId, true);

                $this->expectException("PureLogicException");
                $pure->authenticateUser($userId, $password);

                $this->expectException("PureLogicException");
                $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
            }
        } catch (\Exception $exception) {
            // TODO!
            $this->assertEquals(ErrorStatus::USER_NOT_FOUND_IN_STORAGE(), $exception->getErrorStatus());
            $this->assertEquals(ErrorStatus::CELL_KEY_NOT_FOUND_IN_STORAGE(), $exception->getErrorStatus());

            $this->fail($exception->getMessage());
        }
    }


    public function testDeleteUserNoCascadeShouldDeleteUser(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // MariaDbPureStorage only supports cascade = true
                if (StorageType::MARIADB() == $storage)
                    continue;

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey, $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string) rand(1000, 9999);
                $password = (string) rand(1000, 9999);
                $dataId = (string) rand(1000, 9999);
                $text = (string) rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $authResult1 = $pure->authenticateUser($userId, $password);

                $pure->deleteUser($userId, false);

                $this->expectException("PureLogicException");
                $pure->authenticateUser($userId, $password);

                $plainText = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->assertEquals(ErrorStatus::USER_NOT_FOUND_IN_STORAGE(), $exception->getErrorStatus());


            $this->fail($exception->getMessage());
        }
    }

    public function testDeleteKeyNewKeyShouldDelete(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string) rand(1000, 9999);
                $password = (string) rand(1000, 9999);
                $dataId = (string) rand(1000, 9999);
                $text = (string) rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, $text);

                $authResult1 = $pure->authenticateUser($userId, $password);

                $pure->deleteKey($userId, $dataId);

                $this->expectException("PureLogicException");
                $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);

            }
        } catch (\Exception $exception) {
            $this->assertEquals(ErrorStatus::CELL_KEY_NOT_FOUND_IN_STORAGE(), $exception->getErrorStatus());


            $this->fail($exception->getMessage());
        }
    }

    public function testRegistrationNewUserBackupsPwdHash(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, publicKey, $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = (string) rand(1000, 9999);
                $password = (string) rand(1000, 9999);

                $pure->registerUser($userId, $password);

                $record = $pure->getStorage()->selectUser($userId);

                $pwdHashDecrypted = $pure->getCrypto()->decrypt($record->getEncryptedPwdHash(),
                    $pureResult->getBupkp()->getPrivateKey());

                $pwdHash = $pure->getCrypto()->computeHash($password);

                $this->assertEquals($pwdHash, $pwdHashDecrypted);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testEncryptionRolesShouldDecrypt(string $pheServerAddress,
                                            string $pureServerAddress,
                                            string $appToken,
                                            string $publicKey,
                                            string $secretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                // TODO: Remove
                if (StorageType::VirgilCloudstorage() == $storage)
                    continue;

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $appToken, $publicKey,
                    $secretKey,
                        null, null, $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = (string) rand(1000, 9999);
                $userId2 = (string) rand(1000, 9999);
                $password1 = (string) rand(1000, 9999);
                $password2 = (string) rand(1000, 9999);
                $dataId = (string) rand(1000, 9999);
                $roleName = (string) rand(1000, 9999);

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $text = (string) rand(1000, 9999);

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $userIds = [];
                $userIds[] = $userId1;
                $userIds[] = $userId2;

                $pure->createRole($roleName, $userIds);

                $cipherText = $pure->encrypt($userId1, $dataId, [], $roleName, [], $text);

                $plainText1 = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
                $plainText2 = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText1);
                $this->assertEquals($text, $plainText2);
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testRecoveryNewUserShouldRecover(string $pheServerAddress,
                                                     string $pureServerAddress,
                                                     string $kmsServerAddress,
                                                     string $appToken,
                                                     string $phePublicKey,
                                                     string $pheSecretKey,
                                                     string $kmsPublicKey,
                                                     string $kmsSecretKey): void
    {

        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure($pheServerAddress, $pureServerAddress, $kmsServerAddress, $appToken,
                        $phePublicKey, $pheSecretKey, $kmsPublicKey, $kmsSecretKey,  null,null, null, $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = (string) rand(1000, 9999);
                $password1 = (string) rand(1000, 9999);
                $password2 = (string) rand(1000, 9999);

                // TODO: Check encryption
                $pure->registerUser($userId, $password1);

                $pure->recoverUser($userId, $password2);

                $this->expectException(PureLogicException::class);
                $pure->authenticateUser($userId, $password1);


                $grant = $pure->authenticateUser($userId, $password2);
                $this->assertNotNull($grant);

            }
        } catch (\Exception $exception) {

            $this->assertEquals($exception->getErrorStatus(), ErrorStatus::INVALID_PASSWORD());
            $this->fail($exception->getMessage());
        }
    }
}