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

use Dotenv\Dotenv;
use Virgil\Crypto\Core\Data;
use Virgil\Crypto\Core\HashAlgorithms;
use Virgil\Crypto\Core\KeyPairType;
use Virgil\Crypto\VirgilCrypto;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureLogicErrorStatus;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureStorageGenericErrorStatus;
use Virgil\PureKit\Pure\Exception\NullPointerException;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKeyNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageGenericException;
use Virgil\PureKit\Pure\Pure;
use Virgil\PureKit\Pure\PureContext;
use Virgil\PureKit\Pure\PureSetupResult;
use Virgil\PureKit\Pure\Storage\_\StorageType;
use Virgil\PureKit\Pure\Storage\MariaDBPureStorage;
use Virgil\PureKit\Pure\Storage\RamPureStorage;

class PureTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var VirgilCrypto
     */
    private $crypto;
    /**
     * @var string
     */
    private $appToken;
    /**
     * @var string
     */
    private $publicKeyOld;
    /**
     * @var string
     */
    private $secretKeyOld;
    /**
     * @var string
     */
    private $publicKeyNew;
    /**
     * @var string
     */
    private $secretKeyNew;
    /**
     * @var string
     */
    private $publicKeyWrong;
    /**
     * @var string
     */
    private $updateToken;
    /**
     * @var string
     */
    private $pheServerAddress;
    /**
     * @var string
     */
    private $pureServerAddress;
    /**
     * @var string
     */
    private $kmsServerAddress;

    /**
     *
     */
    protected function setUp(): void
    {
        $this->crypto = new VirgilCrypto();

        (new Dotenv(__DIR__ . "/../"))->load();

        $this->appToken = $_ENV["TEST_APP_TOKEN"];
        $this->publicKeyOld = $_ENV["TEST_PUBLIC_KEY_OLD"];
        $this->secretKeyOld = $_ENV["TEST_SECRET_KEY_OLD"];
        $this->publicKeyNew = $_ENV["TEST_PUBLIC_KEY_NEW"];
        $this->secretKeyNew = $_ENV["TEST_SECRET_KEY_NEW"];
        $this->publicKeyWrong = $_ENV["TEST_PUBLIC_KEY_WRONG"];
        $this->updateToken = $_ENV["UPDATE_TOKEN"];
        $this->pheServerAddress = $_ENV["TEST_PHE_SERVER_ADDRESS"];
        $this->pureServerAddress = $_ENV["TEST_PURE_SERVER_ADDRESS"];
        $this->kmsServerAddress = $_ENV["TEST_KMS_SERVER_ADDRESS"];
    }

    /**
     * @param int $length
     * @return string
     */
    private static function generateRandomString(int $length = 16)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = "";
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    /**
     * @param int $seconds
     */
    private function sleep(int $seconds = 2)
    {
        sleep($seconds);
    }

    private function setupPure(string $nms = null, bool $updateToken = false,
                               array $externalPublicKeys = [],
                               StorageType $storageType): PureSetupResult
    {
        $bupkp = $this->crypto->generateKeyPair(KeyPairType::ED25519());

        $nmsData = $nms;

        if (empty($nms))
            $nmsData = $this->crypto->generateRandomData(32);

        $nmsString = "NM." . base64_encode($nmsData);

        $bupkpString = "BU." . base64_encode($this->crypto->exportPublicKey($bupkp->getPublicKey()));

        switch ($storageType) {
            case StorageType::RAM():
                $context = PureContext::createCustomContext($this->appToken, $nmsString, $bupkpString,
                    new RamPureStorage(), $this->secretKeyNew, $this->publicKeyNew, $externalPublicKeys,
                    $this->pheServerAddress, $this->kmsServerAddress);
                break;

            case StorageType::VIRGIL_CLOUD():
                $context = PureContext::createVirgilContext($this->appToken, $nmsString, $bupkpString,
                    $this->secretKeyNew, $this->publicKeyNew, $externalPublicKeys,
                    $this->pheServerAddress, $this->pureServerAddress, $this->kmsServerAddress);
                break;

            case StorageType::MARIADB():
                $mariaDbPureStorage = new MariaDbPureStorage("jdbc:mariadb://localhost/puretest?user=root&password=qwerty");
                $context = PureContext::createCustomContext($this->appToken, $nmsString, $bupkpString,
                    $mariaDbPureStorage, $this->secretKeyNew, $this->publicKeyNew, $externalPublicKeys,
                    $this->pheServerAddress, $this->kmsServerAddress);
                break;

            default:
                throw new NullPointerException();
        }

        if ($updateToken)
            $context->setUpdateToken($this->updateToken);

        return new PureSetupResult($context, $bupkp, $nmsData);
    }

    /**
     * @return array
     */
    private static function createStorages(): array
    {
        // storages[0] = StorageType::RAM();
        // storages[1] = StorageType::MariaDB();
        $storages[0] = StorageType::VIRGIL_CLOUD();
        return $storages;
    }

    public function testRegistrationNewUserShouldSucceed(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();

            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();

                $pure->registerUser($userId, $password);
                $this->assertTrue(true);
            }

        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testAuthenticationNewUserShouldSucceed(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();

            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();

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

    public function testEncryptionRandomDataShouldMatch(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password);

                $authResult = $pure->authenticateUser($userId, $password);
                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $plainText = $pure->decrypt($authResult->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testSharing2UsersShouldDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = self::generateRandomString();
                $userId2 = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $cipherText = $pure->encrypt($userId1, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

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


    public function testSharingRevokeAccessShouldNotDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = self::generateRandomString();
                $userId2 = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $cipherText = $pure->encrypt($userId1, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $pure->share($authResult1->getGrant(), $dataId, $userId2);
                $pure->unshare($userId1, $dataId, $userId2);

                try {
                    $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);
                } catch (PureLogicException $exception) {
                    $this->assertEquals($exception->getErrorStatus(), PureLogicErrorStatus::USER_HAS_NO_ACCESS_TO_DATA());
                }
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testGrantChangePasswordShouldNotDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();

                $pure->registerUser($userId, $password1);
                $authResult1 = $pure->authenticateUser($userId, $password1);

                $grant = $pure->decryptGrantFromUser($authResult1->getEncryptedGrant());

                $this->assertNotNull($grant);

                $this->assertEquals($grant->getSessionId(), $authResult1->getGrant()->getSessionId());
                $this->assertEquals($grant->getUserId(), $authResult1->getGrant()->getUserId());
                $this->assertEquals($grant->getUkp()->getPrivateKey()->getIdentifier(), $authResult1->getGrant()->getUkp()->getPrivateKey()->getIdentifier());

                $pure->changeUserPassword($userId, $password1, $password2);

                try {
                    $pure->decryptGrantFromUser($authResult1->getEncryptedGrant());
                } catch (PureCryptoException $exception) {
                    // TODO!!! Fix hardcode
                    $this->assertEquals(-7, $exception->getPheException()->getCode());
                }
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testGrantAdminAccessShouldDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $adminGrant = $pure->createUserGrantAsAdmin($userId, $pureResult->getBupkp()->getPrivateKey());

                $this->assertNotNull($adminGrant);

                $plainText = $pure->decrypt($adminGrant, null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testResetPwdNewUserShouldNotDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password1);

                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $pure->resetUserPassword($userId, $password2);

                $authResult = $pure->authenticateUser($userId, $password2);

                $this->assertNotNull($authResult);

                try {
                    $pure->decrypt($authResult->getGrant(), null, $dataId, $cipherText);
                } catch (PureLogicException $exception) {
                    $this->assertEquals(PureLogicErrorStatus::USER_HAS_NO_ACCESS_TO_DATA(), $exception->getErrorStatus
                    ());
                }
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testRestorePwdNewUserShouldDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep(0);

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password1);

                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $adminGrant = $pure->createUserGrantAsAdmin($userId, $pureResult->getBupkp()->getPrivateKey());

                // TODO! Fix method name
                $pure->changeUserPassword_($adminGrant, $password2);

                $authResult = $pure->authenticateUser($userId, $password2);

                $this->assertNotNull($authResult);

                $plainText = $pure->decrypt($authResult->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    // TODO! Update test for MariaDB
    public function testRotationLocalStorageShouldRotate(): void
    {
        $this->markTestSkipped("Need to be updated for MariaDB, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // VirgilCloudPureStorage should not support that
                if (StorageType::VIRGIL_CLOUD() == $storage) {
                    continue;
                }

                $total = 30;

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());
                $pureStorage = $pure->getStorage();

                if (StorageType::MARIADB() == $storage) {
                    $mariaDbPureStorage = $pure->getStorage();
                    $mariaDbPureStorage->dropTables();
                    $mariaDbPureStorage->createTables();
                }

                for ($i = 0; $i < $total; $i++) {
                    $userId = (string)rand(1000, 9999);
                    $password = (string)rand(1000, 9999);

                    $pure->registerUser($userId, $password);
                }

                $pureResult = $this->setupPure($this->updateToken, false, [], $storage);
                $pureResult->getContext()->setStorage($pureStorage);
                $pure = new Pure($pureResult->getContext());

                $rotated = $pure->performRotation();

                $this->assertEquals($total, $rotated);
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testEncryptionAdditionalKeysShouldDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = self::generateRandomString();
                $userId2 = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $keyPair = $pureResult->getContext()->getCrypto()->generateKeyPair();

                $pkc = new VirgilPublicKeyCollection();
                $pkc->add($keyPair->getPublicKey());

                $cipherText = $pure->encrypt($userId1, $dataId, [$userId2], [],
                    $pkc, $text);

                $plainText = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

                $plainText = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

                // TODO! Fix method name
                $plainText = $pure->decrypt_($keyPair->getPrivateKey(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testEncryptionExternalKeysShouldDecrypt(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $keyPair = $this->crypto->generateKeyPair();
                $dataId = self::generateRandomString();

                $publicKeyBase64 = base64_encode($this->crypto->exportPublicKey($keyPair->getPublicKey()));
                $externalPublicKeys = [$dataId => [$publicKeyBase64]];

                $pureResult = $this->setupPure(null, false, $externalPublicKeys, $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                // TODO!
                $plainText = $pure->decrypt_($keyPair->getPrivateKey(), $userId, $dataId, $cipherText);
                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testDeleteUserCascadeShouldDeleteUserAndKeys(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $authResult1 = $pure->authenticateUser($userId, $password);

                $pure->deleteUser($userId, true);

                try {
                    $pure->authenticateUser($userId, $password);
                } catch (PureStorageGenericException $exception) {
                    $this->assertEquals(PureStorageGenericErrorStatus::USER_NOT_FOUND(), $exception->getErrorStatus());
                }

                try {
                    $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
                } catch (\Exception $exception) {
                    $this->assertTrue($exception instanceof PureStorageCellKeyNotFoundException);
                }
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }


    public function testDeleteUserNoCascadeShouldDeleteUser(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // MariaDbPureStorage only supports cascade = true
                if (StorageType::MARIADB() == $storage)
                    continue;

                $pureResult = $this->setupPure(null, false , [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $authResult1 = $pure->authenticateUser($userId, $password);

                $pure->deleteUser($userId, false);

                try {
                    $pure->authenticateUser($userId, $password);
                } catch (PureStorageGenericException $exception) {
                    $this->assertEquals(PureStorageGenericErrorStatus::USER_NOT_FOUND(), $exception->getErrorStatus());
                }

                $plainText = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testDeleteKeyNewKeyShouldDelete(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $pure->registerUser($userId, $password);

                $cipherText = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $authResult1 = $pure->authenticateUser($userId, $password);

                $pure->deleteKey($userId, $dataId);

                try {
                    $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
                } catch (\Exception $exception) {
                    $this->assertTrue($exception instanceof PureStorageCellKeyNotFoundException);
                }
            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testRegistrationNewUserBackupsPwdHash(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();

                $pure->registerUser($userId, $password);

                $record = $pure->getStorage()->selectUser($userId);

                $data = new Data($record->getBackupPwdHash());

                $pwdHashDecrypted = $pureResult->getContext()->getCrypto()->decrypt($data, $pureResult->getBupkp()
                    ->getPrivateKey());

                $pwdHash = $pureResult->getContext()->getCrypto()->computeHash($password, HashAlgorithms::SHA512());

                $this->assertEquals($pwdHash, $pwdHashDecrypted);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }

    public function testEncryptionRolesShouldDecrypt(): void
    {
        $this->sleep(0);

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = self::generateRandomString();
                $userId2 = self::generateRandomString();
                $userId3 = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $password3 = self::generateRandomString();
                $dataId = self::generateRandomString();
                $roleName = self::generateRandomString();

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);
                $pure->registerUser($userId3, $password3);

                $text = self::generateRandomString();

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);
                $authResult3 = $pure->authenticateUser($userId3, $password3);

                $userIds = [];
                $userIds[] = $userId1;
                $userIds[] = $userId2;

                $pure->createRole($roleName, $userIds);

                $cipherText = $pure->encrypt($userId1, $dataId, [], [$roleName], new VirgilPublicKeyCollection(),
                    $text);

//                $plainText11 = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
                $plainText21 = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText11);
                $this->assertEquals($text, $plainText21);

                try {
                    $pure->decrypt($authResult3->getGrant(), $userId1, $dataId, $cipherText);
                } catch (PureLogicException $exception) {
                    $this->assertEquals(PureLogicErrorStatus::USER_HAS_NO_ACCESS_TO_DATA(), $exception->getErrorStatus());
                }

                $pure->assignRole($roleName, $authResult2->getGrant(), [$userId3]);
                $pure->unassignRole($roleName, [$userId1, $userId2]);

                $plainText12 = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
                $plainText32 = $pure->decrypt($authResult3->getGrant(), $userId1, $dataId, $cipherText);

                $this->assertEquals($text, $plainText12);
                $this->assertEquals($text, $plainText32);

                try {
                    $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);
                } catch (PureLogicException $exception) {
                    $this->assertEquals(PureLogicErrorStatus::USER_HAS_NO_ACCESS_TO_DATA(), $exception->getErrorStatus());
                }

                $pure->assignRole($roleName, $authResult3->getGrant(), [$userId2]);

                $plaintText23 = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $cipherText);
                $this->assertEquals($text, $plaintText23);
            }
        } catch (\Exception $exception) {

            var_dump(383838383838, get_class($exception), $exception->getMessage(), $exception->getCode(),
                $exception->getFile(), $exception->getLine());
            die;

            $this->fail($exception->getMessage());
        }
    }


    public function testRecoveryNewUserShouldRecover(): void
    {
        $this->markTestSkipped("OK, skipped");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();

                $pure->registerUser($userId, $password1);

                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                $blob = $pure->encrypt($userId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $pure->recoverUser($userId, $password2);

                try {
                    $pure->authenticateUser($userId, $password1);
                } catch (PureLogicException $exception) {
                    $this->assertEquals(PureLogicErrorStatus::INVALID_PASSWORD(), $exception->getErrorStatus());
                }

                $authResult = $pure->authenticateUser($userId, $password2);
                $this->assertNotNull($authResult);

                $decrypted = $pure->decrypt($authResult->getGrant(), $userId, $dataId, $blob);
                $this->assertEquals($text, $decrypted);

            }
        } catch (\Exception $exception) {
            $this->fail($exception->getMessage());
        }
    }
}