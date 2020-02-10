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

use PurekitV3Grant\EncryptedGrant as ProtoEncryptedGrant;
use PurekitV3Grant\EncryptedGrantHeader as ProtoEncryptedGrantHeader;
use Virgil\Crypto\Core\VirgilKeyPair;
use Virgil\Crypto\Core\VirgilPrivateKey;
use Virgil\Crypto\Core\VirgilPublicKey;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureLogicErrorStatus;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKEyAlreadyExistsException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKeyNotFoundException;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\PureGrant;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\Storage\PureStorage;
use Virgil\PureKit\Pure\Util\ValidateUtil;
use Virgil\PureKit\Pure\Exception\PureCryptoException;

class Pure
{
    public const DEFAULT_GRANT_TTL = 60 * 60;

    private $currentVersion;
    private $pureCrypto;
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

        $this->pureCrypto = new PureCrypto($context->getCrypto());
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


    public function authenticateUser(string $userId, string $password, string $sessionId = null, int $ttl = self::DEFAULT_GRANT_TTL):
    AuthResult
    {
        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNullOrEmpty($password, "password");

        $userRecord = $this->storage->selectUser($userId);

        $phek = $this->pheManager->computePheKey($userRecord, $password);

        $uskData = $this->pureCrypto->decryptSymmetricNewNonce($userRecord->getEncryptedUsk(), "", $phek);

        $ukp = $this->pureCrypto->importPrivateKey($uskData);

        $creationDate = new \DateTime("now");
        $ts = $creationDate->getTimestamp() + ($ttl * 1000);
        $expirationDate = new \DateTime("@$ts");

        $grant = new PureGrant($ukp, $userId, $sessionId, $creationDate, $expirationDate);

        $grantKeyRaw = $this->pureCrypto->generateSymmetricOneTimeKey();
        $keyId = $this->pureCrypto->computeSymmetricKeyId($grantKeyRaw);

        $headerBuilder = (new ProtoEncryptedGrantHeader)
            ->setCreationDate($grant->getCreationDate()->getTimestamp() / 1000)
            ->setExpirationDate($grant->getExpirationDate()->getTimestamp() / 1000)
            ->setUserId($grant->getUserId())
            ->setKeyId($keyId);

        if (!is_null($sessionId)) {
            $headerBuilder->setSessionId($sessionId);
        }

        $headerBytes = $headerBuilder->serializeToString();

        $encryptedGrantKey = $this->pureCrypto->encryptSymmetricNewNonce($grantKeyRaw, "", $this->ak);

        $grantKey = new GrantKey($userId, $keyId, $encryptedGrantKey, $creationDate, $expirationDate);

        $this->storage->insertGrantKey($grantKey);

        $encryptedPhek = $this->pureCrypto->encryptSymmetricOneTimeKey($phek, $headerBytes, $grantKeyRaw);

        $encryptedGrantData = (new ProtoEncryptedGrant)
            ->setVersion($this->currentGrantVersion)
            ->setHeader($headerBytes)
            ->setEncryptedPhek($encryptedPhek)
            ->serializeToString();

        $encryptedGrant = base64_encode($encryptedGrantData);

        return new AuthResult($grant, $encryptedGrant);
    }

    public function createUserGrantAsAdmin(string $userId, VirgilPrivateKey $bupsk, int $ttl = self::DEFAULT_GRANT_TTL): PureGrant
    {
        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNull($bupsk, "bupsk");

        $userRecord = $this->storage->selectUser($userId);

        $usk = $this->pureCrypto->decryptBackup($userRecord->getEncryptedUskBackup(), $bupsk, $this->oskp->getPublicKey());

        $upk = $this->pureCrypto->importPrivateKey($usk);

        $creationDate = new \DateTime();
        $expirationDate = new \DateTime($creationDate + $ttl * 1000);

        return new PureGrant($upk, $userId, null, $creationDate, $expirationDate);
    }

    public function decryptGrantFromUser(string $encryptedGrantString): PureGrant
    {
        ValidateUtil::checkNullOrEmpty($encryptedGrantString, "encryptedGrantString");

        $encryptedGrantData = base64_decode($encryptedGrantString);

        try {
            $encryptedGrant = new ProtoEncryptedGrant();
            $encryptedGrant->mergeFromString($encryptedGrantData);
        } catch (\Exception $exception) {
            throw new PureLogicException(PureLogicErrorStatus::GRANT_INVALID_PROTOBUF());
        }

        $encryptedData = $encryptedGrant->getEncryptedPhek();

        try {
            $header = new ProtoEncryptedGrantHeader();
            $header->mergeFromString($encryptedGrant->getHeader());
        } catch (\Exception $exception) {
            throw new PureLogicException(PureLogicErrorStatus::GRANT_INVALID_PROTOBUF());
        }

        $grantKey = $this->storage->selectGrantKey($header->getUserId(), $header->getKeyId());

        if ($grantKey->getExpirationDate() < new \DateTime("now"))
            throw new PureLogicException(PureLogicErrorStatus::GRANT_IS_EXPIRED());


        $grantKeyRaw = $this->pureCrypto->decryptSymmetricNewNonce($grantKey->getEncryptedGrantKey(), "", $this->ak);

        $phek = $this->pureCrypto->decryptSymmetricOneTime($encryptedData, $encryptedGrant->getHeader(),
            $grantKeyRaw);

        $userRecord = $this->storage->selectUser($header->getUserId());

        $usk = $this->pureCrypto->decryptSymmetricNewNonce($userRecord->getEncryptedUsk(), "", $phek);

        $ukp = $this->pureCrypto->importPrivateKey($usk);

        $sessionId = $header->getSessionId();

        if (empty($sessionId))
            $sessionId = null;

        $cd = $header->getCreationDate() * 1000;
        $ed = $header->getExpirationDate() * 1000;

        return new PureGrant($ukp, $header->getUserId(), $sessionId,
            new \DateTime("@$cd"),
            new \DateTime("@$ed"));
    }

    public function changeUserPassword(string $userId, string $oldPassword, string $newPassword): void
    {
        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNullOrEmpty($oldPassword, "oldPassword");
        ValidateUtil::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($userId);

        $oldPhek = $this->pheManager->computePheKey($userRecord, $oldPassword);

        $privateKeyData = $this->pureCrypto->decryptSymmetricNewNonce($userRecord->getEncryptedUsk(), "", $oldPhek);

        $this->_changeUserPassword($userRecord, $privateKeyData, $newPassword);
    }

    // TODO!
    public function changeUserPassword_(PureGrant $grant, string $newPassword): void
    {
        ValidateUtil::checkNull($grant, "grant");
        ValidateUtil::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($grant->getUserId());

        $privateKeyData = $this->pureCrypto->exportPrivateKey($grant->getUkp()->getPrivateKey());

        $this->_changeUserPassword($userRecord, $privateKeyData, $newPassword);
    }

    public function recoverUser(string $userId, string $newPassword): void
    {
        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($userId);

        $pwdHash = $this->kmsManager->recoverPwd($userRecord);

        $oldPhek = $this->pheManager->computePheKey($userRecord, $pwdHash);

        $privateKeyData = $this->pureCrypto->decryptSymmetricNewNonce($userRecord->getEncryptedUsk(), "", $oldPhek);

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
                // $userRecord->getRecordVersion() == $this->currentVersion - 1;

                $newRecord = $this->pheManager - $this->performRotation($userRecord->getPheRecord());
                $newWrap = $this->kmsManager->performRotation($userRecord->getPasswordRecoveryWrap());

                $newUserRecord = new UserRecord(
                    $userRecord->getUserId(),
                    $newRecord,
                    $this->currentVersion,
                    $userRecord->getUpk(),
                    $userRecord->getEncryptedUsk(),
                    $userRecord->getEncryptedUskBackup(),
                    $userRecord->getBackupPwdHash(),
                    $newWrap,
                    $userRecord->getPasswordResetBlob()
                );

                $newUserRecords->add($newUserRecord);
            }

            $this->storage->updateUsers($newUserRecords, $this->currentVersion - 1);

            if (empty($newUserRecords)) {
                break;
            } else {
                $rotations += count($newUserRecords);
            }
        }

        return $rotations;
    }

    public function encrypt(string $userId, string $dataId, array $otherUserIds, array $roleNames,
                            VirgilPublicKeyCollection $publicKeys, string $plainText): string
    {
        ValidateUtil::checkNull($otherUserIds, "otherUserIds");
        ValidateUtil::checkNull($publicKeys, "publicKeys");
        ValidateUtil::checkNull($plainText, "plainText");

        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNullOrEmpty($dataId, "dataId");

        try {
            $cellKey = $this->storage->selectCellKey($userId, $dataId);
            $cpk = $this->pureCrypto->importPublicKey($cellKey->getCpk());
        } catch (PureStorageCellKeyNotFoundException $exception) {

            $vpkc = new VirgilPublicKeyCollection();
            try {
                $recipientList = new VirgilPublicKeyCollection();

                $recipientList->addCollection($publicKeys);

                $userIds[] = $userId;
                $userIds = array_merge($userIds, $otherUserIds);

                $userRecords = $this->storage->selectUsers($userIds);

                foreach ($userRecords->getAsArray() as $record) {
                    $otherUpk = $this->pureCrypto->importPublicKey($record->getUpk());
                    $recipientList->add($otherUpk);
                }

                $roles = $this->storage->selectRoles($roleNames);

                if ($roles->getAsArray()) {
                    foreach ($roles->getAsArray() as $role) {
                        $rpk = $this->pureCrypto->importPublicKey($role->getRpk());
                        $recipientList->add($rpk);
                    }
                }

                $externalPublicKeys = $this->externalPublicKeys->get($dataId);

                if (!is_null($externalPublicKeys))
                    $recipientList->addCollection($externalPublicKeys);

                $ckp = $this->pureCrypto->generateCellKey();
                $cpkData = $this->pureCrypto->exportPublicKey($ckp->getPublicKey());
                $cskData = $this->pureCrypto->exportPrivateKey($ckp->getPrivateKey());

                $encryptedCskData = $this->pureCrypto->encryptCellKey($cskData, $recipientList, $this->oskp->getPrivateKey());

                $cellKey = new CellKey($userId, $dataId, $cpkData, $encryptedCskData->getCms(),
                    $encryptedCskData->getBody());

                $this->storage->insertCellKey($cellKey);

                $cpk = $ckp->getPublicKey();
                $vpkc->add($cpk);

            } catch (PureStorageCellKeyAlreadyExistsException $exception) {
                $cellKey = $this->storage->selectCellKey($userId, $dataId);

                $cpk = $this->pureCrypto->importPublicKey($cellKey->getCpk());
                $vpkc->add($cpk);
            }
        }

        return $this->pureCrypto->encryptData($plainText, $vpkc, $this->oskp->getPrivateKey());
    }

    public function decrypt(PureGrant $grant, string $ownerUserId = null, string $dataId, string $cipherText): string
    {
        ValidateUtil::checkNull($grant, "grant");
        ValidateUtil::checkNull($cipherText, "cipherText");
        ValidateUtil::checkNullOrEmpty($dataId, "dataId");

        $userId = $ownerUserId;

        if (is_null($userId))
            $userId = $grant->getUserId();

        $cellKey = $this->storage->selectCellKey($userId, $dataId);

        $pureCryptoData = new PureCryptoData($cellKey->getEncryptedCskCms(),
            $cellKey->getEncryptedCskBody());

        $csk = null;

        try {
            $csk = $this->pureCrypto->decryptCellKey(
                $pureCryptoData,
                $grant->getUkp()->getPrivateKey(),
                $this->oskp->getPublicKey());

        } catch (PureCryptoException | \Exception $exception) {
            if (is_null($exception->getFoundationException()) ||
                ($exception->getFoundationException()->getStatusCode() != ErrorStatus::ERROR_KEY_RECIPIENT_IS_NOT_FOUND())) {
                var_dump(get_class($exception), $exception->getMessage(), $exception->getCode());
                die;
            }

            $roleAssignments = $this->storage->selectRoleAssignments($grant->getUserId());

            $publicKeysIds = $this->pureCrypto->extractPublicKeysIdsFromCellKey($cellKey->getEncryptedCskCms());

            foreach ($roleAssignments as $roleAssignment) {
                $publicKeyId = $roleAssignment->getPublicKeyId();

                if ($publicKeysIds . contains($publicKeyId)) {

                    $rskData = $this->pureCrypto->decryptRolePrivateKey($roleAssignment->getEncryptedRsk(),
                        $grant->getUkp()->getPrivateKey(), $this->oskp->getPublicKey());

                    $rkp = $this->pureCrypto->importPrivateKey($rskData);

                    $csk = $this->pureCrypto->decryptCellKey($pureCryptoData, $rkp->getPrivateKey(),
                        $this->oskp->getPublicKey());
                    break;
                }
            }

            if (is_null($csk))
                throw new PureLogicException(PureLogicErrorStatus::USER_HAS_NO_ACCESS_TO_DATA());
        }

        $ckp = $this->pureCrypto->importPrivateKey($csk);

        return $this->pureCrypto->decryptData($cipherText, $ckp->getPrivateKey(), $this->oskp->getPublicKey());
    }

    public function decrypt_(VirgilPrivateKey $privateKey, string $ownerUserId, string $dataId,
                             string $cipherText): string
    {
        ValidateUtil::checkNull($privateKey, "privateKey");
        ValidateUtil::checkNullOrEmpty($dataId, "dataId");
        ValidateUtil::checkNullOrEmpty($ownerUserId, "ownerUserId");

        $cellKey = $this->storage->selectCellKey($ownerUserId, $dataId);

        $pureCryptoData = new PureCryptoData($cellKey->getEncryptedCskCms(),
            $cellKey->getEncryptedCskBody());

        $csk = $this->pureCrypto->decryptCellKey($pureCryptoData, $privateKey, $this->oskp->getPublicKey());

        $ckp = $this->pureCrypto->importPrivateKey($csk);

        return $this->pureCrypto->decryptData($cipherText, $ckp->getPrivateKey(), $this->oskp->getPublicKey());
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

        $encryptedCskCms = $this->pureCrypto->addRecipientsToCellKey($cellKey->getEncryptedCskCms(),
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

        $encryptedCskCms = $this->pureCrypto->deleteRecipientsFromCellKey($cellKey->getEncryptedCskCms(), $keys);

        $cellKeyNew = new CellKey($cellKey->getUserId(), $cellKey->getDataId(),
            $cellKey->getCpk(), $encryptedCskCms, $cellKey->getEncryptedCskBody());

        $this->storage->updateCellKey($cellKeyNew);
    }

    public function deleteKey(string $userId, string $dataId): void
    {
        $this->storage->deleteCellKey($userId, $dataId);
    }

    public function createRole(string $roleName, string ...$userIds): void
    {
        $rkp = $this->pureCrypto->generateRoleKey();
        $rpkData = $this->pureCrypto->exportPublicKey($rkp->getPublicKey());
        $rskData = $this->pureCrypto->exportPrivateKey($rkp->getPrivateKey());

        $role = new Role($roleName, $rpkData);

        $this->storage->insertRole($role);

        $this->assignRole_($roleName, $rkp->getPublicKey()->getIdentifier(), $rskData, $userIds);
    }

    public function assignRole(string $roleToAssign, PureGrant $grant, string ...$userIds): void
    {
        $roleAssignment = $this->storage->selectRoleAssignment($roleToAssign, $grant->getUserId());

        $rskData = $this->pureCrypto->decryptRolePrivateKey($roleAssignment->getEncryptedRsk(), $grant->getUkp()->getPrivateKey(),
            $this->oskp->getPublicKey());

        $this->assignRole_($roleToAssign, $roleAssignment->getPublicKeyId(), $rskData, $userIds);
    }

    private function assignRole_(string $roleName, string $publicKeyId, string $rskData, string ...$userIds): void
    {
        $userRecords = $this->storage->selectUsers($userIds);

        $roleAssignments = [];

        foreach ($userRecords as $userRecord) {
            $upk = $this->pureCrypto->importPublicKey($userRecord->getUpk());

            $encryptedRsk = $this->pureCrypto->encryptRolePrivateKey($rskData, $upk, $this->oskp->getPrivateKey());

            $roleAssignments[] = new RoleAssignment($roleName, $userRecord->getUserId(), $publicKeyId, $encryptedRsk);
        }

        $this->storage->insertRoleAssignments($roleAssignments);
    }

    public function unassignRole(string $roleName, string ...$userIds): void
    {
        $this->storage->deleteRoleAssignments($roleName, $userIds);
    }


    private function _registerUser(string $userId, string $password, bool $isUserNew): void
    {
        ValidateUtil::checkNullOrEmpty($userId, "userId");
        ValidateUtil::checkNullOrEmpty($password, "password");

        $passwordHash = $this->pureCrypto->computePasswordHash($password);

        $encryptedPwdHash = $this->pureCrypto->encryptForBackup($passwordHash, $this->buppk, $this->oskp->getPrivateKey
        ());

        $pwdRecoveryData = $this->kmsManager->generatePwdRecoveryData($passwordHash);

        // [enrollment_record, account_key]
        $pheResult = $this->pheManager->getEnrollment($passwordHash);

        $ukp = $this->pureCrypto->generateUserKey();

        $uskData = $this->pureCrypto->exportPrivateKey($ukp->getPrivateKey());

        $encryptedUsk = $this->pureCrypto->encryptSymmetricNewNonce($uskData, "", $pheResult[1]);

        $encryptedUskBackup = $this->pureCrypto->encryptForBackup($uskData, $this->buppk, $this->oskp->getPrivateKey());

        $publicKey = $this->pureCrypto->exportPublicKey($ukp->getPublicKey());

        $userRecord = new UserRecord(
            $userId,
            $pheResult[0],
            $this->currentVersion,
            $publicKey,
            $encryptedUsk,
            $encryptedUskBackup,
            $encryptedPwdHash,
            $pwdRecoveryData->getWrap(),
            $pwdRecoveryData->getBlob()
        );

        $isUserNew ? $this->storage->insertUser($userRecord) : $this->storage->updateUser($userRecord);
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

            $newPasswordHash = $this->pureCrypto->computePasswordHash($newPassword);

            // [enrollment_record, account_key]
            $enrollResult = $this->pheManager->getEnrollment($newPasswordHash);

            $pwdRecoveryData = $this->kmsManager->generatePwdRecoveryData($newPasswordHash);

            $newEncryptedUsk = $this->pureCrypto->encryptSymmetricNewNonce($privateKeyData, "",
                $enrollResult[1]);

            $encryptedPwdHash = $this->pureCrypto->encryptForBackup($newPasswordHash, $this->buppk,
                $this->oskp->getPrivateKey());

            $newUserRecord = new UserRecord(
                $userRecord->getUserId(),
                $enrollResult[0],
                $this->currentVersion,
                $userRecord->getUpk(),
                $newEncryptedUsk,
                $userRecord->getEncryptedUskBackup(),
                $encryptedPwdHash,
                $pwdRecoveryData->getWrap(),
                $pwdRecoveryData->getBlob()
            );

            $this->storage->updateUser($newUserRecord);
        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    private function keysWithOthers(VirgilPublicKeyCollection $publicKeys,
                                    string ...$otherUserIds): VirgilPublicKeyCollection
    {
        $otherUserRecords = $this->storage->selectUsers($otherUserIds);

        foreach ($otherUserRecords as $record) {
            $otherUpk = $this->pureCrypto->importPublicKey($record->getUpk());

            $publicKeys->add($otherUpk);
        }

        return $publicKeys;
    }

    public function getCurrentVersion(): int
    {
        return $this->currentVersion;
    }

    public function getStorage(): PureStorage
    {
        return $this->storage;
    }

    public function getAk(): string
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

    public function getExternalPublicKeys(): VirgilPublicKeyCollection
    {
        return $this->externalPublicKeys;
    }
}