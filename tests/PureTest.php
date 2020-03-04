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
use Virgil\PureKit\Pure\Exception\PureException;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKeyNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageGenericException;
use Virgil\PureKit\Pure\Exception\PureStorageUserNotFoundException;
use Virgil\PureKit\Pure\Pure;
use Virgil\PureKit\Pure\PureContext;
use Virgil\PureKit\Pure\PureSessionParams;
use Virgil\PureKit\Pure\PureSetupResult;
use Virgil\PureKit\Pure\Storage\_\StorageType;
use Virgil\PureKit\Pure\Storage\MariaDBPureStorage;
use Virgil\PureKit\Pure\Storage\RamPureStorage;

/**
 * Class PureTest
 * @package Virgil\PureKit\Tests
 */
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
     * @var string
     */
    private $dbHost;
    /**
     * @var string
     */
    private $dbLogin;
    /**
     * @var string
     */
    private $dbPassword;
    /**
     * @var string
     */
    private $sqls;
    /**
     * @var
     */
    private $testData;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->crypto = new VirgilCrypto();

        (new Dotenv(__DIR__ . "/../"))->load();

        $l = $e = null;
        if (!empty($_ENV["ENV"]))
            list($e, $l) = [$_ENV["ENV"], strtolower($_ENV["ENV"])];

        $this->appToken = $e ? $_ENV["{$e}_APP_TOKEN"] : $_ENV["APP_TOKEN"];
        $this->publicKeyOld = $e ? $_ENV["{$e}_PUBLIC_KEY"] : $_ENV["PUBLIC_KEY"];
        $this->secretKeyOld = $e ? $_ENV["{$e}_SECRET_KEY"] : $_ENV["SECRET_KEY"];
        $this->publicKeyNew = $e ? $_ENV["{$e}_PUBLIC_KEY_NEW"] : $_ENV["PUBLIC_KEY_NEW"];
        $this->secretKeyNew = $e ? $_ENV["{$e}_SECRET_KEY_NEW"] : $_ENV["SECRET_KEY_NEW"];
        $this->publicKeyWrong = $e ? $_ENV["{$e}_PUBLIC_KEY_WRONG"] : substr_replace($_ENV["PUBLIC_KEY"],
            self::generateRandomString(176), 5,176);
        $this->updateToken = $e ? $_ENV["{$e}_UPDATE_TOKEN"] : $_ENV["UPDATE_TOKEN"];
        $this->pheServerAddress = $e ? $_ENV["{$e}_PHE_SERVER_ADDRESS"] : null;
        $this->pureServerAddress = $e ? $_ENV["{$e}_PURE_SERVER_ADDRESS"] : null;
        $this->kmsServerAddress = $e ? $_ENV["{$e}_KMS_SERVER_ADDRESS"] : null;

        $s = $e ? __DIR__.DIRECTORY_SEPARATOR."_resources".DIRECTORY_SEPARATOR."compatibility_tables_{$l}.sql" :
        __DIR__.DIRECTORY_SEPARATOR."_resources".DIRECTORY_SEPARATOR."compatibility_tables.sql";

        $this->sqls = file_get_contents($s);

        $c = $e ? __DIR__.DIRECTORY_SEPARATOR."_resources".DIRECTORY_SEPARATOR."compatibility_data_{$l}.json" :
            __DIR__.DIRECTORY_SEPARATOR."_resources".DIRECTORY_SEPARATOR."compatibility_data.json";

        $this->testData = json_decode(file_get_contents($c));

        $this->dbHost = $_ENV["DB_HOST"];
        $this->dbLogin = $_ENV["DB_LOGIN"];
        $this->dbPassword = $_ENV["DB_PASSWORD"];
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
     * @param \Exception $exception
     * @param bool $asString
     * @return string
     */
    private function debugException(\Exception $exception, bool $asString = true)
    {
        if ($asString) {
            return
                "FAIL with exception:\n" .
                "class: " . get_class($exception) . "\n" .
                "message: " . $exception->getMessage() . "\n" .
                "code: " . $exception->getCode() . "\n" .
                "file: " . $exception->getFile() . "\n" .
                "line: " . $exception->getLine();
        } else {
            var_dump("DEBUG", get_class($exception), $exception->getMessage(), $exception->getCode(), $exception->getFile(), $exception->getLine());
            die;
        }
    }

    /**
     * @param int $seconds
     */
    private function sleep(int $seconds = 0)
    {
        sleep($seconds);
    }

    /**
     * @param bool $useOldKeys
     * @param string|null $nms
     * @param bool $useUpdateToken
     * @param array $externalPublicKeys
     * @param StorageType $storageType
     * @param bool $skipClean
     * @return PureSetupResult
     * @throws NullPointerException
     * @throws PureCryptoException
     * @throws PureLogicException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\MariaDbSqlException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    private function setupPure(bool $useOldKeys = true, string $nms = null, bool $useUpdateToken = false, array
$externalPublicKeys = [],
                               StorageType $storageType, bool $skipClean = false):
    PureSetupResult
    {
        $bupkp = $this->crypto->generateKeyPair(KeyPairType::ED25519());

        $nmsData = $nms;

        $publicKey = $useOldKeys ? $this->publicKeyOld : $this->publicKeyNew;
        $secretKey = $useOldKeys ? $this->secretKeyOld : $this->secretKeyNew;

        if (empty($nms))
            $nmsData = $this->crypto->generateRandomData(32);

        $nmsString = "NM." . base64_encode($nmsData);

        $bupkpString = "BU." . base64_encode($this->crypto->exportPublicKey($bupkp->getPublicKey()));

        switch ($storageType) {
            case StorageType::RAM():
                $context = PureContext::createCustomContext($this->appToken, $nmsString, $bupkpString,
                    $secretKey, $publicKey, new RamPureStorage(), $externalPublicKeys,
                    $this->pheServerAddress, $this->kmsServerAddress);
                break;

            case StorageType::VIRGIL_CLOUD():
                $context = PureContext::createVirgilContext($this->appToken, $nmsString, $bupkpString,
                    $secretKey, $publicKey, $externalPublicKeys,
                    $this->pheServerAddress, $this->pureServerAddress, $this->kmsServerAddress);
                break;

            case StorageType::MARIADB():
                $mariaDbPureStorage = new MariaDbPureStorage($this->dbHost, $this->dbLogin, $this->dbPassword);
                if (!$skipClean) {
                    $mariaDbPureStorage->cleanDb();
                    $mariaDbPureStorage->initDb(20);
                }

                $context = PureContext::createCustomContext($this->appToken, $nmsString, $bupkpString,
                    $secretKey, $publicKey, $mariaDbPureStorage, $externalPublicKeys,
                    $this->pheServerAddress, $this->kmsServerAddress);
                break;

            default:
                throw new NullPointerException();
        }

        if ($useUpdateToken)
            $context->setUpdateToken($this->updateToken);

        return new PureSetupResult($context, $bupkp, $nmsData);
    }

    /**
     * @return array
     */
    private static function createStorages(): array
    {
        // $storages[0] = StorageType::RAM();
        // $storages[0] = StorageType::MARIADB();
         $storages[0] = StorageType::VIRGIL_CLOUD();
        return $storages;
    }

    public function testRegistrationNewUserShouldSucceed(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();

            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(true,null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();

                $pure->registerUser($userId, $password);
                $this->assertTrue(true);
            }

        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testAuthenticationNewUserShouldSucceed(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIA_DB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();

            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testEncryptionRandomDataShouldMatch(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(true, null, false, [], $storage);
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
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();
        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testSharingRevokeAccessShouldNotDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testGrantChangePasswordShouldNotDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testGrantExpireShouldNotDecrypt(): void
    {
        $this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();

                $pure->registerUser($userId, $password);
                $authResult = $pure->authenticateUser($userId, $password, new PureSessionParams(null, 20));

                $grant1 = $pure->decryptGrantFromUser($authResult->getEncryptedGrant());

                $this->assertNotNull($grant1);

                $this->sleep(16);

                $grant2 = $pure->decryptGrantFromUser($authResult->getEncryptedGrant());

                $this->assertNotNull($grant2);

                $this->sleep(8);

                try {
                    $pure->decryptGrantFromUser($authResult->getEncryptedGrant());
                } catch (PureException $exception) {
                    if ($exception instanceof PureLogicException) {
                        $this->assertEquals(PureLogicErrorStatus::GRANT_IS_EXPIRED(), $exception->getErrorStatus());
                    } elseif ($exception instanceof PureStorageGenericException) {
                        $this->assertEquals(PureStorageGenericErrorStatus::GRANT_KEY_NOT_FOUND(),
                            $exception->getErrorStatus());
                    } else {
                        $this->assertEquals(0, 1);
                    }
                }
            }
        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testGrantInvalidateShouldNotDecrypt(): void
    {
        $this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(true,null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId = self::generateRandomString();
                $password = self::generateRandomString();

                $authResult = $pure->registerUser_($userId, $password, new PureSessionParams());

                $pure->invalidateEncryptedUserGrant($authResult->getEncryptedGrant());

                try {
                    $pure->decryptGrantFromUser($authResult->getEncryptedGrant());
                } catch (PureStorageGenericException $exception) {
                    $this->assertEquals(PureStorageGenericErrorStatus::GRANT_KEY_NOT_FOUND(), $exception->getErrorStatus());
                }
            }
        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testGrantAdminAccessShouldDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(true,null, false, [], $storage);

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
            $this->fail($this->debugException($exception));
        }
    }

    public function testResetPwdNewUserShouldNotDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId1 = self::generateRandomString();
                $password1 = self::generateRandomString();
                $userId2 = self::generateRandomString();
                $password21 = self::generateRandomString();
                $password22 = self::generateRandomString();
                $dataId1 = self::generateRandomString();
                $dataId2 = self::generateRandomString();
                $text = self::generateRandomString();

                $authResult1 = $pure->registerUser_($userId1, $password1, new PureSessionParams());
                $pure->registerUser($userId2, $password21);

                $cipherText1 = $pure->encrypt($userId1, $dataId1, [], [], new VirgilPublicKeyCollection(), $text);
                $pure->share($authResult1->getGrant(), $dataId1, $userId2);

                $cipherText2 = $pure->encrypt($userId2, $dataId2, [], [], new VirgilPublicKeyCollection(), $text);

                $pure->resetUserPassword($userId2, $password22, true);

                $authResult = $pure->authenticateUser($userId2, $password22);

                $this->assertNotNull($authResult);

                try {
                    $pure->decrypt($authResult->getGrant(), $userId1, $dataId1, $cipherText1);
                } catch (PureLogicException $exception) {
                    $this->assertEquals(PureLogicErrorStatus::USER_HAS_NO_ACCESS_TO_DATA(), $exception->getErrorStatus
                    ());
                }

                try {
                    $pure->decrypt($authResult->getGrant(), null, $dataId2, $cipherText2);
                } catch (PureStorageCellKeyNotFoundException $exception) {
                    $this->assertTrue($exception instanceof PureStorageCellKeyNotFoundException);
                }
            }
        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testRestorePwdNewUserShouldDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testRotationLocalStorageDecryptAndRecoverWorks(): void
    {
        //$this->markTestIncomplete("VIRGIL_CLOUD: ok | MARIADB: fail");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // VirgilCloudPureStorage should not support that
                if (StorageType::VIRGIL_CLOUD() == $storage) {
                    continue;
                }

                $total = 20;

                $firstUserId = null;
                $firstUserPwd = null;
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();
                $newPwd = self::generateRandomString();

                {
                    $pureResult = $this->setupPure(true, null, false, [], $storage);
                    $pure = new Pure($pureResult->getContext());
                    $pureStorage = $pure->getStorage();
                    $nms = $pureResult->getNmsData();

                    for ($i = 0; $i < $total; $i++) {
                        $userId = self::generateRandomString();
                        $password = self::generateRandomString();

                        $pure->registerUser($userId, $password);

                        if (0 == $i)
                            list($firstUserId, $firstUserPwd) = [$userId, $password];
                    }
                }

                {
                    $pureResult = $this->setupPure(true, $nms, true, [], $storage, true);
                    $pureResult->getContext()->setStorage($pureStorage);
                    $pure = new Pure($pureResult->getContext());

                    $blob = $pure->encrypt($firstUserId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                    $results = $pure->performRotation();

                    $this->assertEquals($total, $results->getUsersRotated());
                    $this->assertEquals(0, $results->getGrantKeysRotated());
                }

                {
                    $pureResult = $this->setupPure(false, $nms, false, [], $storage, true);
                    $pureResult->getContext()->setStorage($pureStorage);
                    $pure = new Pure($pureResult->getContext());

                    $authResult = $pure->authenticateUser($firstUserId, $firstUserPwd);

                    $decrypted = $pure->decrypt($authResult->getGrant(), $firstUserId, $dataId, $blob);

                    $this->assertEquals($text, $decrypted);

                    $pure->recoverUser($firstUserId, $newPwd);

                    $authResult2 = $pure->authenticateUser($firstUserId, $newPwd);

                    $decrypted2 = $pure->decrypt($authResult2->getGrant(), $firstUserId, $dataId, $blob);

                    $this->assertEquals($text, $decrypted2);
                }

                {
                    $pureResult = $this->setupPure(true, $nms, true, [], $storage, true);
                    $pureResult->getContext()->setStorage($pureStorage);
                    $pure = new Pure($pureResult->getContext());

                    $authResult = $pure->authenticateUser($firstUserId, $newPwd);

                    $decrypted = $pure->decrypt($authResult->getGrant(), $firstUserId, $dataId, $blob);

                    $this->assertEquals($text, $decrypted);

                    $newPwd2 = self::generateRandomString();

                    $pure->recoverUser($firstUserId, $newPwd2);

                    $authResult2 = $pure->authenticateUser($firstUserId, $newPwd2);

                    $decrypted2 = $pure->decrypt($authResult2->getGrant(), $firstUserId, $dataId, $blob);

                    $this->assertEquals($text, $decrypted2);
                }
            }

            $this->assertTrue(true);

        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testRotationLocalStorageGrantWorks(): void
    {
        //$this->markTestIncomplete("VIRGIL_CLOUD: ok | MARIADB: fail");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // VirgilCloudPureStorage should not support that
                if (StorageType::VIRGIL_CLOUD() == $storage) {
                    continue;
                }

                $total = 20;

                $firstUserId = null;
                $firstUserPwd = null;
                $dataId = self::generateRandomString();
                $text = self::generateRandomString();

                {
                    $pureResult = $this->setupPure(true, null, false, [], $storage);
                    $pure = new Pure($pureResult->getContext());

                    $pureStorage = $pure->getStorage();
                    $nms = $pureResult->getNmsData();

                    for ($i = 0; $i < $total; $i++) {
                        $userId = self::generateRandomString();
                        $password = self::generateRandomString();

                        $pure->registerUser($userId, $password);

                        if ($i == 0) {
                            $firstUserId = $userId;
                            $firstUserPwd = $password;
                        }
                    }

                    $encryptedGrant1 = $pure->authenticateUser($firstUserId, $firstUserPwd)->getEncryptedGrant();
                }

                {
                    $pureResult = $this->setupPure(true, $nms, true, [], $storage, true);
                    $pureResult->getContext()->setStorage($pureStorage);
                    $pure = new Pure($pureResult->getContext());

                    $blob = $pure->encrypt($firstUserId, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                    $encryptedGrant2 = $pure->authenticateUser($firstUserId, $firstUserPwd)->getEncryptedGrant();

                    $results = $pure->performRotation();

                    $this->assertEquals($total, $results->getUsersRotated());
                    $this->assertEquals(1, $results->getGrantKeysRotated());
                }

                {
                    $pureResult = $this->setupPure(false, $nms, false, [], $storage, true);
                    $pureResult->getContext()->setStorage($pureStorage);
                    $pure = new Pure($pureResult->getContext());

                    $pureGrant1 = $pure->decryptGrantFromUser($encryptedGrant1);
                    $this->assertNotNull($pureGrant1);

                    $pureGrant2 = $pure->decryptGrantFromUser($encryptedGrant2);
                    $this->assertNotNull($pureGrant2);

                    $decrypted1 = $pure->decrypt($pureGrant1, $firstUserId, $dataId, $blob);
                    $this->assertEquals($text, $decrypted1);

                    $decrypted2 = $pure->decrypt($pureGrant2, $firstUserId, $dataId, $blob);
                    $this->assertEquals($text, $decrypted2);
                }

                {
                    $pureResult = $this->setupPure(true, $nms, true, [], $storage, true);
                    $pureResult->getContext()->setStorage($pureStorage);
                    $pure = new Pure($pureResult->getContext());

                    $pureGrant1 = $pure->decryptGrantFromUser($encryptedGrant1);
                    $this->assertNotNull($pureGrant1);

                    $pureGrant2 = $pure->decryptGrantFromUser($encryptedGrant2);
                    $this->assertNotNull($pureGrant2);

                    $decrypted1 = $pure->decrypt($pureGrant1, $firstUserId, $dataId, $blob);
                    $this->assertEquals($text, $decrypted1);

                    $decrypted2 = $pure->decrypt($pureGrant2, $firstUserId, $dataId, $blob);
                    $this->assertEquals($text, $decrypted2);
                }
            }

            $this->assertTrue(true);

        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testEncryptionAdditionalKeysShouldDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testEncryptionExternalKeysShouldDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $keyPair = $this->crypto->generateKeyPair();
                $dataId = self::generateRandomString();

                $publicKeyBase64 = base64_encode($this->crypto->exportPublicKey($keyPair->getPublicKey()));
                $externalPublicKeys = [$dataId => [$publicKeyBase64]];

                $pureResult = $this->setupPure(true, null, false, $externalPublicKeys, $storage);

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
            $this->fail($this->debugException($exception));
        }
    }

    public function testDeleteUserCascadeShouldDeleteUserAndKeys(): void
    {
        $this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
                    // TODO!
                    $this->assertTrue($exception instanceof PureStorageCellKeyNotFoundException);
                }
            }
        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testDeleteUserNoCascadeShouldDeleteUser(): void
    {
        $this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // MariaDbPureStorage only supports cascade = true
                if (StorageType::MARIADB() == $storage)
                    continue;

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
                } catch (\Exception $exception) {
                    $this->assertTrue($exception instanceof PureStorageUserNotFoundException);

                    $this->assertTrue(in_array($userId, $exception->getUserIds()));
                }

                $plainText = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);

                $this->assertEquals($text, $plainText);

            }
        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testDeleteKeyNewKeyShouldDelete(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testRegistrationNewUserBackupsPwdHash(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true, null, false, [], $storage);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testEncryptionRolesShouldDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {
                $pureResult = $this->setupPure(true, null, false, [], $storage);
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

                $plainText11 = $pure->decrypt($authResult1->getGrant(), null, $dataId, $cipherText);
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
            $this->fail($this->debugException($exception));
        }
    }

    public function testDeleteRolesNewRoleShouldDelete(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                // VirgilCloudPureStorage should not support that
                if (StorageType::VIRGIL_CLOUD() == $storage) {
                    continue;
                }

                $pureResult = $this->setupPure(true, null, false, [], $storage);
                $pure = new Pure($pureResult->getContext());

                $userId1 = self::generateRandomString();
                $userId2 = self::generateRandomString();
                $password1 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $dataId1 = self::generateRandomString();
                $dataId2 = self::generateRandomString();
                $roleName1 = self::generateRandomString();
                $roleName2 = self::generateRandomString();

                $pure->registerUser($userId1, $password1);
                $pure->registerUser($userId2, $password2);

                $text1 = self::generateRandomString();
                $text2 = self::generateRandomString();

                $authResult1 = $pure->authenticateUser($userId1, $password1);
                $authResult2 = $pure->authenticateUser($userId2, $password2);

                $pure->createRole($roleName1, [$userId1]);
                $pure->createRole($roleName2, [$userId2]);

                $cipherText1 = $pure->encrypt($userId1, $dataId1, [], [$roleName2], new VirgilPublicKeyCollection(),
                    $text1);
                $cipherText2 = $pure->encrypt($userId2, $dataId2, [], [$roleName1], new VirgilPublicKeyCollection(),
                    $text2);

                $pure->deleteRole($roleName1, true);

                try {
                    $pure->decrypt($authResult1->getGrant(), $userId2, $dataId2, $cipherText2);
                } catch (PureLogicException $exception) {
                    $this->assertEquals(PureLogicErrorStatus::USER_HAS_NO_ACCESS_TO_DATA(), $exception->getErrorStatus
                        ());
                }

                if ($storage != StorageType::MARIADB()) {
                    $pure->deleteRole($roleName2, false);
                    $plainText = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId1, $cipherText1);
                    $this->assertEquals($text1, $plainText);
                }
            }

            $this->assertTrue(true);

        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testRecoveryNewUserShouldRecover(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);

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
            $this->fail($this->debugException($exception));
        }
    }

    public function testShareRoleShouldDecrypt(): void
    {
        //$this->markTestSkipped("VIRGIL_CLOUD: ok | MARIADB: ok");
        $this->sleep();

        try {
            $storages = self::createStorages();
            foreach ($storages as $storage) {

                $pureResult = $this->setupPure(true,null, false, [], $storage);

                $pure = new Pure($pureResult->getContext());

                $userId1 = self::generateRandomString();
                $password1 = self::generateRandomString();
                $userId2 = self::generateRandomString();
                $password2 = self::generateRandomString();
                $dataId = self::generateRandomString();
                $roleName = self::generateRandomString();
                $text = self::generateRandomString();

                $authResult1 = $pure->registerUser_($userId1, $password1, new PureSessionParams());
                $authResult2 = $pure->registerUser_($userId2, $password2, new PureSessionParams());

                $blob = $pure->encrypt($userId1, $dataId, [], [], new VirgilPublicKeyCollection(), $text);

                $pure->createRole($roleName, [$userId2]);
                $pure->shareToRole($authResult1->getGrant(), $dataId, [$roleName]);

                $decrypted = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId, $blob);
                $this->assertEquals($text, $decrypted);
            }
        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }

    public function testCrossCompatibilityJsonShouldWork(): void
    {
        $this->markTestIncomplete("VIRGIL_CLOUD: ok | MARIADB: fail");
        $this->sleep();

        try {
            $encryptedGrant = $this->testData->encrypted_grant;
            $userId1 = $this->testData->user_id1;
            $userId2 = $this->testData->user_id2;
            $password1 = $this->testData->password1;
            $password2 = $this->testData->password2;
            $dataId1 = $this->testData->data_id1;
            $dataId2 = $this->testData->data_id2;
            $text1 = base64_decode($this->testData->text1);
            $text2 = base64_decode($this->testData->text2);
            $blob1 = base64_decode($this->testData->blob1);
            $blob2 = base64_decode($this->testData->blob2);
            $nms = base64_decode($this->testData->nms);

            $pureResult = $this->setupPure(true, $nms, false, [], StorageType::MARIADB(), true);
            $pure = new Pure($pureResult->getContext());

            $mariaDbPureStorage = $pureResult->getContext()->getStorage();

            $mariaDbPureStorage->cleanDb();

            $mariaDbPureStorage->executeSql($this->sqls);

            $pureGrant = $pure->decryptGrantFromUser($encryptedGrant);

            $this->assertNotNull($pureGrant);

            $authResult1 = $pure->authenticateUser($userId1, $password1);
            $authResult2 = $pure->authenticateUser($userId2, $password2);

            $this->assertNotNull($authResult1);
            $this->assertNotNull($authResult2);

            $text11 = $pure->decrypt($authResult1->getGrant(), null, $dataId1, $blob1);
            $text12 = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId1, $blob1);
            $text21 = $pure->decrypt($authResult1->getGrant(), null, $dataId2, $blob2);
            $text22 = $pure->decrypt($authResult2->getGrant(), $userId1, $dataId2, $blob2);

            $this->assertEquals($text1, $text11);
            $this->assertEquals($text1, $text12);
            $this->assertEquals($text2, $text21);
            $this->assertEquals($text2, $text22);

        } catch (\Exception $exception) {
            $this->fail($this->debugException($exception));
        }
    }
}