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

use Purekit\EnrollmentRequest as ProtoEnrollmentRequest;
use Purekit\VerifyPasswordRequest as ProtoVerifyPasswordRequest;
use PurekitV3Client\DecryptRequest as ProtoDecryptRequest;
use PurekitV3Grant\EncryptedGrant as ProtoEncryptedGrant;
use PurekitV3Grant\EncryptedGrantHeader as ProtoEncryptedGrantHeader;
use Virgil\Crypto\Core\VirgilKeyPair;
use Virgil\Crypto\Core\VirgilPrivateKey;
use Virgil\Crypto\Core\VirgilPublicKey;
use Virgil\Crypto\VirgilCrypto;
use Virgil\CryptoWrapper\Foundation\Aes256Gcm;
use Virgil\PureKit\Http\_\AvailableRequest;
use Virgil\PureKit\Http\Request\Phe\EnrollRequest;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\PureGrant;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\Storage\_\PureStorage;
use Virgil\PureKit\Pure\Util\ValidateUtil;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\CryptoWrapper\Phe\PheCipher;
use Virgil\CryptoWrapper\Phe\PheClient;
use Virgil\Crypto\Core\HashAlgorithms;

class Pure
{

    private $currentVersion;
    private $crypto;
    private $pureCrypto;
    private $cipher;
    private $storage;
    private $ak;
    private $buppk;
    private $oskp;
    private $externalPublicKeys;
    private $pheManager;
    private $kmsManager;

    private $currentGrantVersion = 1;

    /**
     * Pure constructor.
     * @param PureContext $context
     * @throws PureCryptoException
     */
    public function __construct(PureContext $context)
    {
        try {
            $this->crypto = $context->getCrypto();
            $this->pureCrypto = new PureCrypto($this->crypto);
            $this->cipher = new PheCipher();
            $this->cipher->useRandom($this->crypto->getRng());
            $this->storage = $context->getStorage();
            $this->ak = $context->getNonrotableSecrets()->getAk();
            $this->buppk = $context->getBuppk();
            $this->oskp = $context->getNonrotableSecrets()->getOskp();
            $this->externalPublicKeys = $context->getExternalPublicKeys();
            $this->pheManager = new PheManager($context);
            $this->kmsManager = new KmsManager($context);

            if (!is_null($context->getUpdateToken())) {
                $this->currentVersion = $context->getPublicKey()->getVersion() + 1;
            } else {
                $this->currentVersion = $context->getPublicKey()->getVersion();
            }
        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param string $userId
     * @param string $password
     * @throws PureCryptoException
     */
    public function registerUser(string $userId, string $password): void
    {
        $this->_registerUser($userId, $password, true);
    }

    /**
     * @param string $userId
     * @param string $password
     * @param string|null $sessionId
     * @return AuthResult
     * @throws PureCryptoException
     */
    public function authenticateUser(string $userId, string $password, string $sessionId = null): AuthResult
    {
        try {
            ValidateUtil::checkNullOrEmpty($userId, "userId");
            ValidateUtil::checkNullOrEmpty($password, "password");

            $userRecord = $this->storage->selectUser($userId);

            $phek = $this->pheManager->computePheKey($userRecord, $password);

            $uskData = $this->cipher->decrypt($userRecord->getEncryptedUsk(), $phek);

            $ukp = $this->crypto->importPrivateKey($uskData);

            $grant = new PureGrant($ukp, $userId, $sessionId, new \DateTime("now"));

            // TODO!
            $timestamp = (int) ($grant->getCreationDate()->getTime() / 1000);

            $headerBuilder = (new ProtoEncryptedGrantHeader)
                ->setCreationDate($timestamp)
                ->setUserId($grant->getUserId());

            if (!is_null($sessionId)) {
                $headerBuilder->setSessionId($sessionId);
            }

            $headerBytes = $headerBuilder->serializeToString();

            $encryptedPhek = $this->cipher->authEncrypt($phek, $headerBytes, $this->ak);

            $encryptedGrantData = (new ProtoEncryptedGrant)
                ->setVersion($this->currentGrantVersion)
                ->setHeader($headerBytes)
                ->setEncryptedPhek($encryptedPhek)
                ->serializeToString();

            $encryptedGrant = base64_encode($encryptedGrantData);

            return new AuthResult($grant, $encryptedGrant);

        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    public function createUserGrantAsAdmin(string $userId, VirgilPrivateKey $bupsk): PureGrant
    {
        ValidateUtil::checkNullOrEmpty($userId, "userId");

        $userRecord = $this->storage->selectUser($userId);

        $usk = $this->crypto->decrypt($userRecord->getEncryptedUskBackup(), $bupsk);

        $upk = $this->crypto->importPrivateKey($usk);

        return new PureGrant($upk, $userId, null, new \DateTime());
    }

    public function decryptGrantFromUser(string $encryptedGrantString): PureGrant
    {
        try {
            ValidateUtil::checkNullOrEmpty($encryptedGrantString, "encryptedGrantString");

            $encryptedGrantData = base64_decode($encryptedGrantString);

            $encryptedGrant = (new ProtoEncryptedGrant)
                ->mergeFromString($encryptedGrantData);

            $encryptedData = $encryptedGrant->getEncryptedPhek();

            $phek = $this->cipher->authDecrypt($encryptedData, $encryptedGrant->getHeader(), $this->ak);

            $header = (new ProtoEncryptedGrantHeader)->mergeFromString($encryptedGrant->getHeader());

            $userRecord = $this->storage->selectUser($header->getUserId());

            $usk = $this->cipher->decrypt($userRecord->getEncryptedUsk(), $phek);

            $ukp = $this->crypto->importPrivateKey($usk);

            $sessionId = $header->getSessionId();

            if (empty($sessionId))
                $sessionId = null;

            return new PureGrant($ukp, $header->getUserId(), $sessionId, $header->getCreationDate() * 1000);
        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    public function changeUserPassword(string $userId, string $oldPassword, string $newPassword): void
    {
        try {
            ValidateUtil::checkNullOrEmpty($userId, "userId");
            ValidateUtil::checkNullOrEmpty($oldPassword, "oldPassword");
            ValidateUtil::checkNullOrEmpty($newPassword, "newPassword");

            $userRecord = $this->storage->selectUser($userId);

            $oldPhek = $this->pheManager->computePheKey($userRecord, $oldPassword);

            $privateKeyData = $this->cipher->decrypt($userRecord->getEncryptedUsk(), $oldPhek);

            $this->_changeUserPassword($userRecord, $privateKeyData, $newPassword);

        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    // TODO!
    public function changeUserPassword_(PureGrant $grant, string $newPassword): void
    {
        ValidateUtil::checkNull($grant, "grant");
        ValidateUtil::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($grant->getUserId());

        $privateKeyData = $this->crypto->exportPrivateKey($grant->getUkp()->getPrivateKey());

        $this->_changeUserPassword($userRecord, $privateKeyData, $newPassword);
    }

    public function recoverUser(string $userId, string $newPassword): void
    {
        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($userId);

        $pwdHash = $this->kmsManager->recoverPwd($userRecord);

        $oldPhek = $this->pheManager->computePheKey($userRecord, $pwdHash);

        $privateKeyData = $this->cipher->decrypt($userRecord->getEncryptedUsk(), $oldPhek);

        $this->changeUserPassword($userRecord, $privateKeyData, $newPassword);
    }

    public function resetUserPassword(string $userId, string $newPassword): void
    {
        // TODO: Add possibility to delete cell keys? -> ????
        $this->_registerUser($userId, $newPassword, false);
    }

    public function deleteUser(string $userId, bool $cascade): void
    {
        $this->storage->deleteUser($userId, $cascade);
        // TODO: Should delete role assignments
    }

    public function performRotation(): int
    {
        if ($this->currentVersion <= 1)
            return 0;

        $rotations = 0;

        while (true) {
            $userRecords = $this->storage->selectUsers($this->currentVersion - 1);
            $newUserRecords = [];

            foreach ($userRecords as $userRecord) {
                // TODO!
                // $userRecord->getPheRecordVersion() == $this->currentVersion - 1;

                $newRecord = $this->pheManager-$this->performRotation($userRecord->getPheRecord());
                $newWrap = $this->kmsManager->performRotation($userRecord->getPasswordResetWrap());

                $newUserRecord = new UserRecord(
                    $userRecord->getUserId(),
                    $newRecord,
                    $this->currentVersion,
                    $userRecord->getUpk(),
                    $userRecord->getEncryptedUsk(),
                    $userRecord->getEncryptedUskBackup(),
                    $userRecord->getEncryptedPwdHash(),
                    $newWrap,
                    $userRecord->getPasswordResetBlob()
                );

               $newUserRecords->add($newUserRecord);
            }

            $this->storage->updateUsers($newUserRecords, $this->currentVersion - 1);

            if (empty($newUserRecords)) {
                break;
            }
            else {
                $rotations += count($newUserRecords);
            }
        }

        return $rotations;
    }

    public function encrypt(string $userId, string $dataId, array $otherUserIds = [], array $roleNames = [],
                            VirgilPublicKeyCollection $publicKeys = null, string $plainText): string
    {
        ValidateUtil::checkNull($otherUserIds, "otherUserIds");
        ValidateUtil::checkNull($publicKeys, "publicKeys");
        ValidateUtil::checkNull($plainText, "plainText");

        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNullOrEmpty($dataId, "dataId");

        $cellKey1 = $this->storage->selectCellKey($userId, $dataId);

        if (is_null($cellKey1)) {
            try {

                $recipientList = [];

                $recipientList[] = $publicKeys;

                $userIds[] = $userId;
                $userIds[] = $otherUserIds;

                $userRecords = $this->storage->selectUsers($userIds);

                foreach ($userRecords as $record) {
                    $otherUpk = $this->crypto->importPublicKey($record->getUpk());
                    $recipientList[] = $otherUpk;
                }

                $roles = $this->storage->selectRoles($roleNames);

                foreach ($roles as $role) {
                    $rpk = $this->crypto->importPublicKey($role->getRpk());
                    $recipientList[] = $rpk;
                }

                $externalPublicKeys = $this->externalPublicKeys->get($dataId);

                if (!is_null($externalPublicKeys))
                    $recipientList[] = $externalPublicKeys;

                $ckp = $this->crypto->generateKeyPair();
                $cpkData = $this->crypto->exportPublicKey($ckp->getPublicKey());
                $cskData = $this->crypto->exportPrivateKey($ckp->getPrivateKey());

                $encryptedCskData = $this->pureCrypto->encrypt($cskData, $this->oskp->getPrivateKey(), $recipientList);

                $cellKey = new CellKey($userId, $dataId, $cpkData, $encryptedCskData->getCms(),
                    $encryptedCskData->getBody());

                $this->storage->insertCellKey($cellKey);
                $cpk = $ckp->getPublicKey();

            } catch (\Exception $exception) {
                if ($exception->getErrorStatus() != ErrorStatus::CELL_KEY_ALREADY_EXISTS_IN_STORAGE()) {
                    throw new PureLogicException($exception);
                }

                $cellKey2 = $this->storage->selectCellKey($userId, $dataId);

                $cpk = $this->crypto->importPublicKey($cellKey2->getCpk());
            }
        } else {
            $cpk = $this->crypto->importPublicKey($cellKey1->getCpk());
        }

        // TODO: Replace crypto.encrypt everywhere
        return $this->crypto->encrypt($plainText, $cpk);
    }

    public function decrypt(PureGrant $grant, string $ownerUserId, string $dataId, string $cipherText): string
    {
        ValidateUtil::checkNull($grant, "grant");
        ValidateUtil::checkNull($cipherText, "cipherText");

        ValidateUtil::checkNullOrEmpty($dataId, "dataId");

        $userId = $ownerUserId;

        if (is_null($userId) == null)
            $userId = $grant->getUserId();

        $cellKey = $this->storage->selectCellKey($userId, $dataId);

        if (is_null($cellKey))
            throw new PureLogicException(ErrorStatus::CELL_KEY_NOT_FOUND_IN_STORAGE());

        $pureCryptoData = new PureCryptoData($cellKey->getEncryptedCskCms(),
        $cellKey->getEncryptedCskBody());

        $csk = null;

        try {
            $csk = $this->pureCrypto->decrypt($pureCryptoData,
                $this->oskp->getPublicKey(),
                $grant->getUkp()->getPrivateKey());
        } catch (\Exception $exception) {
            // TODO!
//            if (is_null($exception->getFoundationException()) ||
//                ($exception->getFoundationException()->getStatusCode() !=
//                    ErrorStatus::ERROR_KEY_RECIPIENT_IS_NOT_FOUND()) {
//                throw $exception;
//            }

            $roleAssignments = $this->storage->selectRoleAssignments($grant->getUserId());

            $publicKeysIds = $this->pureCrypto->extractPublicKeysIds($cellKey->getEncryptedCskCms());

            foreach ($roleAssignments as $roleAssignment) {
                $publicKeyId = $roleAssignment->getPublicKeyId();

                if ($publicKeysIds.contains($publicKeyId)) {
                    // FIXME: Refactor
                    $rskData = $this->crypto->decrypt($roleAssignment->getEncryptedRsk(),
                        $grant->getUkp()->getPrivateKey());

                    $rkp = $this->crypto->importPrivateKey($rskData);

                    $csk = $this->pureCrypto->decrypt($pureCryptoData, $this->oskp->getPublicKey(),
                        $rkp->getPrivateKey());
                    break;
                }
            }

            if (is_null($csk))
                throw new PureLogicException(ErrorStatus::USER_HAS_NO_ACCESS_TO_DATA());
        }

        $ckp = $this->crypto->importPrivateKey($csk);

        return $this->crypto->decrypt($cipherText, $ckp->getPrivateKey());
    }

    public function decrypt_(VirgilPrivateKey $privateKey, string $ownerUserId, string $dataId,
                            string $cipherText): string
    {
        // TODO: Delete copy&paste

        ValidateUtil::checkNull($privateKey, "privateKey");
        ValidateUtil::checkNullOrEmpty($dataId, "dataId");
        ValidateUtil::checkNullOrEmpty($ownerUserId, "ownerUserId");

        $cellKey = $this->storage->selectCellKey($ownerUserId, $dataId);

        if (is_null($cellKey))
            throw new PureLogicException(ErrorStatus::CELL_KEY_NOT_FOUND_IN_STORAGE());

        $pureCryptoData = new PureCryptoData($cellKey->getEncryptedCskCms(),
        $cellKey->getEncryptedCskBody());

        $csk = $this->pureCrypto->decrypt($pureCryptoData, $this->oskp->getPublicKey(), $privateKey);

        $ckp = $this->crypto->importPrivateKey($csk);

        return $this->crypto->decrypt($cipherText, $ckp->getPrivateKey());
    }

    public function share(PureGrant $grant, string $dataId, string $otherUserId): void
    {
        ValidateUtil::checkNull($grant, "grant");

        ValidateUtil::checkNullOrEmpty($dataId, "dataId");
        ValidateUtil::checkNullOrEmpty($otherUserId, "otherUserId");

        $this->share_($grant, $dataId, $otherUserId, null);
    }

    // TODO!
    public function share_(PureGrant $grant, string $dataId, array $otherUserIds,
                          VirgilPublicKeyCollection $publicKeys = null): void
    {
        ValidateUtil::checkNull($grant, "grant");
        ValidateUtil::checkNull($otherUserIds, "otherUserIds");
        ValidateUtil::checkNull($publicKeys, "publicKeys");

        ValidateUtil::checkNullOrEmpty($dataId, "dataId");

        $keys = $this->keysWithOthers($publicKeys, $otherUserIds);
        $cellKey = $this->storage->selectCellKey($grant->getUserId(), $dataId);

        $encryptedCskCms = $this->pureCrypto->addRecipients($cellKey->getEncryptedCskCms(),
            $grant->getUkp()->getPrivateKey(),
            $keys);

        $cellKeyNew = new CellKey($cellKey->getUserId(), $cellKey->getDataId(),
        $cellKey->getCpk(), $encryptedCskCms,
        $cellKey->getEncryptedCskBody());

        $this->storage->updateCellKey($cellKeyNew);
    }

    public function unshare(string $ownerUserId, string $dataId, string $otherUserId): void
    {
        $this->unshare_($ownerUserId, $dataId, $otherUserId, new VirgilPublicKeyCollection());
    }

    // TODO!
    public function unshare_(string $ownerUserId, string $dataId, array $otherUserIds,
                            VirgilPublicKeyCollection $publicKeys): void
    {
        ValidateUtil::checkNull($otherUserIds, "otherUserIds");
        ValidateUtil::checkNull($publicKeys, "publicKeys");

        ValidateUtil::checkNullOrEmpty($ownerUserId, "ownerUserId");
        ValidateUtil::checkNullOrEmpty($dataId, "dataId");

        $keys = $this->keysWithOthers($publicKeys, $otherUserIds);

        $cellKey = $this->storage->selectCellKey($ownerUserId, $dataId);

        $encryptedCskCms = $this->pureCrypto->deleteRecipients($cellKey->getEncryptedCskCms(), $keys);

        $cellKeyNew = new CellKey($cellKey->getUserId(), $cellKey->getDataId(),
        $cellKey->getCpk(), $encryptedCskCms, $cellKey->getEncryptedCskBody());

        $this->storage->updateCellKey($cellKeyNew);
    }

    public function deleteKey(string $userId, string $dataId): void
    {
        $this->storage->deleteCellKey($userId, $dataId);
    }

    /**
     * @param string $roleName
     * @param string ...$userIds
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    public function createRole(string $roleName, string ...$userIds):void
    {
        $rkp = $this->crypto->generateKeyPair();
        $rpkData = $this->crypto->exportPublicKey($rkp->getPublicKey());
        $rskData = $this->crypto->exportPrivateKey($rkp->getPrivateKey());

        $role = new Role($roleName, $rpkData);

        $this->storage->insertRole($role);

        $this->assignRole_($roleName, $rkp->getPublicKey()->getIdentifier(), $rskData, $userIds);
    }

    public function assignRole(string $roleToAssign, PureGrant $grant, string ...$userIds): void
    {
        $roleAssignment = $this->storage->selectRoleAssignment($roleToAssign, $grant->getUserId());

        $rskData = $this->crypto->decrypt($roleAssignment->getEncryptedRsk(), $grant->getUkp()->getPrivateKey());

        $this->assignRole_($roleToAssign, $roleAssignment->getPublicKeyId(), $rskData, $userIds);
    }

    private function assignRole_(string $roleName, string $publicKeyId, string $rskData, string ...$userIds): void
    {
        $userRecords = $this->storage->selectUsers($userIds);

        $roleAssignments = [];

        foreach ($userRecords as $userRecord) {
            $upk = $this->crypto->importPublicKey($userRecord->getUpk());

            $encryptedRsk = $this->crypto->encrypt($rskData, $upk);

            $roleAssignments[] = new RoleAssignment($roleName, $userRecord->getUserId(), $publicKeyId, $encryptedRsk);
        }

        $this->storage->insertRoleAssignments($roleAssignments);
    }

    public function deassignRole(string $roleName, string ...$userIds): void
    {
        $this->storage->deleteRoleAssignments($roleName, $userIds);
    }

    /**
     * @param string $userId
     * @param string $password
     * @param bool $isUserNew
     * @throws PureCryptoException
     */
    private function _registerUser(string $userId, string $password, bool $isUserNew): void
    {
        try {
            ValidateUtil::checkNullOrEmpty($userId, "userId");
            ValidateUtil::checkNullOrEmpty($password, "password");

            $passwordHash = $this->crypto->computeHash($password, HashAlgorithms::SHA512());

            $encryptedPwdHash = $this->crypto->encrypt($passwordHash, $this->buppk);

            $pwdResetData = $this->kmsManager->generatePwdResetData($passwordHash);

            $pheResult = $this->pheManager->getEnrollment($passwordHash);

            $ukp = $this->crypto->generateKeyPair();

            $uskData = $this->crypto->exportPrivateKey($ukp->getPrivateKey());

            $encryptedUsk = $this->cipher->encrypt($uskData, $pheResult->getAccountKey());

            $encryptedUskBackup = $this->crypto->encrypt($uskData, $this->buppk);

            $publicKey = $this->crypto->exportPublicKey($ukp->getPublicKey());

            $userRecord = new UserRecord(
                $userId,
                $pheResult->getEnrollmentRecord(),
                $this->currentVersion,
                $publicKey,
                $encryptedUsk,
                $encryptedUskBackup,
                $encryptedPwdHash,
                $pwdResetData->getWrap(),
                $pwdResetData->getBlob()
            );

            $isUserNew ? $this->storage->insertUser($userRecord) : $this->storage->updateUser($userRecord);
        }
        catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param UserRecord $userRecord
     * @param string $privateKeyData
     * @param string $newPassword
     * @throws PureCryptoException
     */
    private function _changeUserPassword(UserRecord $userRecord, string $privateKeyData, string $newPassword): void
    {
        try {
            ValidateUtil::checkNullOrEmpty($newPassword, "newPassword");

            $newPasswordHash = $this->crypto->computeHash($newPassword,
                    HashAlgorithms::SHA512());

            $enrollResult = $this->pheManager->getEnrollment($newPasswordHash);

            $pwdResetData = $this->kmsManager->generatePwdResetData($newPasswordHash);

            $newEncryptedUsk = $this->cipher->encrypt($privateKeyData, $enrollResult->getAccountKey());

            $encryptedPwdHash = $this->crypto->encrypt($newPasswordHash, $this->buppk);

            $newUserRecord = new UserRecord(
                $userRecord->getUserId(),
                $enrollResult->getEnrollmentRecord(),
                $this->currentVersion,
                $userRecord->getUpk(),
                $newEncryptedUsk,
                $userRecord->getEncryptedUskBackup(),
                $encryptedPwdHash,
                $pwdResetData->getWrap(),
                $pwdResetData->getBlob()
            );

            $this->storage->updateUser($newUserRecord);
        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    private function keysWithOthers(VirgilPublicKeyCollection $publicKeys,
                                    string ...$otherUserIds): VirgilPublicKeyCollection
    {
        $keys = [];

        $otherUserRecords = $this->storage->selectUsers($otherUserIds);

        foreach ($otherUserRecords as $record) {
            $otherUpk = $this->crypto->importPublicKey($record->getUpk());

            $keys[] = $otherUpk;
        }

        return $keys;
    }

    public function getCrypto(): VirgilCrypto {
        return $this->crypto;
    }

    public function getStorage(): PureStorage {
        return $this->storage;
    }

    public function getAk(): string{
        return $this->ak;
    }

    public function getBuppk(): VirgilPublicKey {
        return $this->buppk;
    }

    public function getOskp(): VirgilKeyPair {
        return $this->oskp;
    }

    public function getExternalPublicKeys(): VirgilPublicKeyCollection {
        return $this->externalPublicKeys;
    }
}