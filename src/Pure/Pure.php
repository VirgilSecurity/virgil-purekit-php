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
use Virgil\PureKit\Pure\Collection\GrantKeyCollection;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyMap;
use Virgil\PureKit\Pure\Exception\EmptyArgumentException;
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
use Virgil\PureKit\Pure\Util\ValidationUtils;
use Virgil\PureKit\Pure\Exception\PureCryptoException;

class Pure
{
    public const DEFAULT_GRANT_TTL = 60 * 60;

    private $currentGrantVersion = 1;

    private $currentVersion;
    private $pureCrypto;
    private $storage;
    private $buppk;
    private $oskp;
    private $externalPublicKeys;
    private $pheManager;
    private $kmsManager;

    /**
     * Pure constructor.
     * @param PureContext $context
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureCryptoException
     */
    public function __construct(PureContext $context)
    {
        ValidationUtils::checkNull($context, "context");

        $this->pureCrypto = new PureCrypto($context->getCrypto());
        $this->storage = $context->getStorage();
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

    public function registerUser(string $userId, string $password): void
    {
        $this->_registerUserInternal($userId, $password);
    }


    public function registerUser_(string $userId, string $password, PureSessionParams $pureSessionParams):
    AuthResult
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($password, "password");
        ValidationUtils::checkNull($pureSessionParams, "pureSessionParams");

        $registrationResult = $this->_registerUserInternal($userId, $password);

        return $this->_authenticateUserInternal($registrationResult->getUserRecord(), $registrationResult->getUkp(),
            $registrationResult->getPhek(), $pureSessionParams->getSessionId(), $pureSessionParams->getTtl());
    }

    public function authenticateUser(string $userId, string $password, PureSessionParams $pureSessionParams = null):
    AuthResult
    {
        if (is_null($pureSessionParams))
            $pureSessionParams = new PureSessionParams();

        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($password, "password");

        $userRecord = $this->storage->selectUser($userId);

        $phek = $this->pheManager->computePheKey($userRecord, $password);

        $uskData = $this->pureCrypto->decryptSymmetricWithNewNonce($userRecord->getEncryptedUsk(), "", $phek);

        $ukp = $this->pureCrypto->importPrivateKey($uskData);

        return $this->_authenticateUserInternal($userRecord, $ukp, $phek, $pureSessionParams->getSessionId(),
            $pureSessionParams->getTtl());
    }

    public function invalidateEncryptedUserGrant(string $encryptedGrantString): void
    {
        $deserializedEncryptedGrant = $this->deserializeEncryptedGrant($encryptedGrantString);

        // Just to check that grant was valid
        $this->decryptPheKeyFromEncryptedGrant($deserializedEncryptedGrant);

        $this->getStorage()->deleteGrantKey($deserializedEncryptedGrant->getHeader()->getUserId(),
        $deserializedEncryptedGrant->getHeader()->getKeyId());
    }

    public function createUserGrantAsAdmin(string $userId, VirgilPrivateKey $bupsk, int $ttl = self::DEFAULT_GRANT_TTL): PureGrant
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNull($bupsk, "bupsk");

        $userRecord = $this->storage->selectUser($userId);

        $usk = $this->pureCrypto->decryptBackup($userRecord->getEncryptedUskBackup(), $bupsk, $this->oskp->getPublicKey());

        $upk = $this->pureCrypto->importPrivateKey($usk);

        $creationDate = new \DateTime("now");
        $ts = $creationDate->getTimestamp() + ($ttl * 1000);
        $expirationDate = new \DateTime("@$ts");

        return new PureGrant($upk, $userId, null, $creationDate, $expirationDate);
    }

    private function deserializeEncryptedGrant(string $encryptedGrantString): DeserializedEncryptedGrant
    {
        ValidationUtils::checkNullOrEmpty($encryptedGrantString, "encryptedGrantString");

        $encryptedGrantData = base64_decode($encryptedGrantString);

        try {
            $encryptedGrant = new ProtoEncryptedGrant();
            $encryptedGrant->mergeFromString($encryptedGrantData);
        } catch (\Exception $exception) {
            throw new PureLogicException(PureLogicErrorStatus::GRANT_INVALID_PROTOBUF());
        }

        try {
            $header = new ProtoEncryptedGrantHeader();
            $header->mergeFromString($encryptedGrant->getHeader());
        } catch (\Exception $exception) {
            throw new PureLogicException(PureLogicErrorStatus::GRANT_INVALID_PROTOBUF());
        }

        return new DeserializedEncryptedGrant($encryptedGrant, $header);
    }

    private function decryptPheKeyFromEncryptedGrant(DeserializedEncryptedGrant $deserializedEncryptedGrant): string
    {
        $encryptedData = $deserializedEncryptedGrant->getEncryptedGrant()->getEncryptedPhek();

        $grantKey = $this->storage->selectGrantKey($deserializedEncryptedGrant->getHeader()->getUserId(),
            $deserializedEncryptedGrant->getHeader()->getKeyId());

        if ($grantKey->getExpirationDate() < new \DateTime("now"))
            throw new PureLogicException(PureLogicErrorStatus::GRANT_IS_EXPIRED());

        $header = $deserializedEncryptedGrant->getHeader()->serializeToString();
        $grantKeyRaw = $this->kmsManager->recoverGrantKey($grantKey, $header);

        return $this->pureCrypto->decryptSymmetricWithOneTimeKey($encryptedData, $header, $grantKeyRaw);
    }

    public function decryptGrantFromUser(string $encryptedGrantString): PureGrant
    {
        $deserializedEncryptedGrant = $this->deserializeEncryptedGrant($encryptedGrantString);

        $phek = $this->decryptPheKeyFromEncryptedGrant($deserializedEncryptedGrant);

        $userRecord = $this->storage->selectUser($deserializedEncryptedGrant->getHeader()->getUserId());

        $usk = $this->pureCrypto->decryptSymmetricWithNewNonce($userRecord->getEncryptedUsk(), "", $phek);

        $ukp = $this->pureCrypto->importPrivateKey($usk);

        $sessionId = $deserializedEncryptedGrant->getHeader()->getSessionId();

        if (empty($sessionId))
            $sessionId = null;

        $cd = $deserializedEncryptedGrant->getHeader()->getCreationDate() * 1000;
        $ed = $deserializedEncryptedGrant->getHeader()->getExpirationDate() * 1000;

        return new PureGrant($ukp, $deserializedEncryptedGrant->getHeader()->getUserId(), $sessionId,
            new \DateTime("@$cd"),
            new \DateTime("@$ed"));
    }

    public function changeUserPassword(string $userId, string $oldPassword, string $newPassword): void
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($oldPassword, "oldPassword");
        ValidationUtils::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($userId);

        $oldPhek = $this->pheManager->computePheKey($userRecord, $oldPassword);

        $privateKeyData = $this->pureCrypto->decryptSymmetricWithNewNonce($userRecord->getEncryptedUsk(), "", $oldPhek);

        $this->_changeUserPasswordInternal($userRecord, $privateKeyData, $newPassword);
    }

    // TODO!
    public function changeUserPassword_(PureGrant $grant, string $newPassword): void
    {
        ValidationUtils::checkNull($grant, "grant");
        ValidationUtils::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($grant->getUserId());

        $privateKeyData = $this->pureCrypto->exportPrivateKey($grant->getUkp()->getPrivateKey());

        $this->_changeUserPasswordInternal($userRecord, $privateKeyData, $newPassword);
    }

    public function recoverUser(string $userId, string $newPassword): void
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($newPassword, "newPassword");

        $userRecord = $this->storage->selectUser($userId);

        $pwdHash = $this->kmsManager->recoverPwd($userRecord);

        $oldPhek = $this->pheManager->computePheKey_($userRecord, $pwdHash);

        $privateKeyData = $this->pureCrypto->decryptSymmetricWithNewNonce($userRecord->getEncryptedUsk(), "", $oldPhek);

        $this->_changeUserPasswordInternal($userRecord, $privateKeyData, $newPassword);
    }

    public function resetUserPassword(string $userId, string $newPassword, bool $cascade): void
    {
        $this->deleteUser($userId, $cascade);
        $this->_registerUserInternal($userId, $newPassword, false);
    }

    public function deleteUser(string $userId, bool $cascade = true): void
    {
        $this->storage->deleteUser($userId, $cascade);
    }

    public function performRotation(): RotationResults
    {
        if ($this->currentVersion <= 1)
            return new RotationResults(0, 0);

        $usersRotated = 0;
        $grantKeysRotated = 0;

        while (true) {
            $userRecords = $this->storage->selectUsers_($this->currentVersion - 1);
            $newUserRecords = new UserRecordCollection();

            foreach ($userRecords as $userRecord) {

                // TODO! Need to be checked
                if ($userRecord->getRecordVersion() != $this->currentVersion - 1) {
                    throw new \Exception("Assertion err: userRecordVersion != currentVersion");
                }

                $newRecord = $this->pheManager - $this->performRotation($userRecord->getPheRecord());
                $newWrap = $this->kmsManager->performPwdRotation($userRecord->getPasswordRecoveryWrap());

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

            if (empty($newUserRecords->getAsArray())) {
                break;
            } else {
                $usersRotated += count($newUserRecords->getAsArray());
            }
        }

        while (true) {
            $grantKeys = $this->getStorage()->selectGrantKeys($this->currentVersion - 1);

            $newGrantKeys = new GrantKeyCollection();

            if (!empty($grantKeys->getAsArray())) {
                foreach ($grantKeys->getAsArray() as $grantKey) {

                    // TODO! Need to be checked
                    if ($grantKey->getRecordVersion() != $this->currentVersion - 1) {
                        throw new \Exception("Assertion err: grantKeyVersion != currentVersion");
                    }

                    $newWrap = $this->kmsManager->performGrantRotation($grantKey->getEncryptedGrantKeyWrap());

                    $newGrantKey = new GrantKey(
                        $grantKey->getUserId(),
                        $grantKey->getKeyId(),
                        $this->currentVersion,
                        $newWrap,
                        $grantKey->getEncryptedGrantKeyBlob(),
                        $grantKey->getCreationDate(),
                        $grantKey->getExpirationDate()
                    );

                    $newGrantKeys->add($newGrantKey);
                }
            }

            $this->getStorage()->updateGrantKeys($newGrantKeys);

            if (empty($newGrantKeys->getAsArray())) {
                break;
            }
            else {
                $grantKeysRotated += count($newGrantKeys->getAsArray());
            }
        }

        return new RotationResults($usersRotated, $grantKeysRotated);
    }

    public function encrypt(string $userId, string $dataId, array $otherUserIds, array $roleNames,
                            VirgilPublicKeyCollection $publicKeys, string $plainText): string
    {
        ValidationUtils::checkNull($otherUserIds, "otherUserIds");
        ValidationUtils::checkNull($publicKeys, "publicKeys");
        ValidationUtils::checkNull($plainText, "plainText");

        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($dataId, "dataId");

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
        ValidationUtils::checkNull($grant, "grant");
        ValidationUtils::checkNull($cipherText, "cipherText");
        ValidationUtils::checkNullOrEmpty($dataId, "dataId");

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

        } catch (PureCryptoException $exception) {

            if (is_null($exception->getFoundationException()) ||
                // TODO! Add Error code enum!
                ($exception->getFoundationException()->getCode() != -303)) {
                throw $exception;
            }

            $roleAssignments = $this->storage->selectRoleAssignments($grant->getUserId());

            $publicKeysIds = $this->pureCrypto->extractPublicKeysIdsFromCellKey($cellKey->getEncryptedCskCms());

            if ($roleAssignments->getAsArray()) {
                foreach ($roleAssignments->getAsArray() as $roleAssignment) {
                    $publicKeyId = $roleAssignment->getPublicKeyId();

                    if (in_array($publicKeyId, $publicKeysIds)) {

                        $rskData = $this->pureCrypto->decryptRolePrivateKey($roleAssignment->getEncryptedRsk(),
                            $grant->getUkp()->getPrivateKey(), $this->oskp->getPublicKey());

                        $rkp = $this->pureCrypto->importPrivateKey($rskData);

                        $csk = $this->pureCrypto->decryptCellKey($pureCryptoData, $rkp->getPrivateKey(),
                            $this->oskp->getPublicKey());
                        break;
                    }
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
        ValidationUtils::checkNull($privateKey, "privateKey");
        ValidationUtils::checkNullOrEmpty($dataId, "dataId");
        ValidationUtils::checkNullOrEmpty($ownerUserId, "ownerUserId");

        $cellKey = $this->storage->selectCellKey($ownerUserId, $dataId);

        $pureCryptoData = new PureCryptoData($cellKey->getEncryptedCskCms(),
            $cellKey->getEncryptedCskBody());

        $csk = $this->pureCrypto->decryptCellKey($pureCryptoData, $privateKey, $this->oskp->getPublicKey());

        $ckp = $this->pureCrypto->importPrivateKey($csk);

        return $this->pureCrypto->decryptData($cipherText, $ckp->getPrivateKey(), $this->oskp->getPublicKey());
    }

    public function shareToRole(PureGrant $grant, string $dataId, array $roleNames): void
    {
        ValidationUtils::checkNull($grant, "grant");
        ValidationUtils::checkNullOrEmpty($dataId, "dataId");
        ValidationUtils::checkNull($roleNames, "roleNames");

        if (empty($roleNames)) {
            throw new EmptyArgumentException("roleNames");
        }

        $roles = $this->getStorage()->selectRoles($roleNames);

        $roleKeys = new VirgilPublicKeyCollection();

        if (!empty($roles->getAsArray())) {
            foreach ($roles->getAsArray() as $role) {
                $roleKeys->add($this->pureCrypto->importPublicKey($role->getRpk()));
            }
        }

        $this->share_($grant, $dataId, [], $roleKeys);
    }

    public function share(PureGrant $grant, string $dataId, string $otherUserId): void
    {
        ValidationUtils::checkNull($grant, "grant");
        ValidationUtils::checkNullOrEmpty($dataId, "dataId");
        ValidationUtils::checkNullOrEmpty($otherUserId, "otherUserId");

        $this->share_($grant, $dataId, [$otherUserId], new VirgilPublicKeyCollection());
    }

    public function share_(PureGrant $grant, string $dataId, array $otherUserIds,
                           VirgilPublicKeyCollection $publicKeys): void
    {
        ValidationUtils::checkNull($grant, "grant");
        ValidationUtils::checkNull($otherUserIds, "otherUserIds");
        ValidationUtils::checkNull($publicKeys, "publicKeys");

        ValidationUtils::checkNullOrEmpty($dataId, "dataId");

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
        $this->unshare_($ownerUserId, $dataId, [$otherUserId], new VirgilPublicKeyCollection());
    }

    public function unshare_(string $ownerUserId, string $dataId, array $otherUserIds,
                             VirgilPublicKeyCollection $publicKeys): void
    {
        ValidationUtils::checkNull($otherUserIds, "otherUserIds");
        ValidationUtils::checkNull($publicKeys, "publicKeys");

        ValidationUtils::checkNullOrEmpty($ownerUserId, "ownerUserId");
        ValidationUtils::checkNullOrEmpty($dataId, "dataId");

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

    public function createRole(string $roleName, array $userIds): void
    {
        $rkp = $this->pureCrypto->generateRoleKey();
        $rpkData = $this->pureCrypto->exportPublicKey($rkp->getPublicKey());
        $rskData = $this->pureCrypto->exportPrivateKey($rkp->getPrivateKey());

        $role = new Role($roleName, $rpkData);

        $this->storage->insertRole($role);

        $this->assignRole_($roleName, $rkp->getPublicKey()->getIdentifier(), $rskData, $userIds);
    }

    public function deleteRole(string $roleName, bool $cascade = true): void
    {
        $this->storage->deleteRole($roleName, $cascade);
    }

    public function assignRole(string $roleName, PureGrant $grant, array $userIds): void
    {
        $roleAssignment = $this->storage->selectRoleAssignment($roleName, $grant->getUserId());

        $rskData = $this->pureCrypto->decryptRolePrivateKey($roleAssignment->getEncryptedRsk(), $grant->getUkp()->getPrivateKey(),
            $this->oskp->getPublicKey());

        $this->assignRole_($roleName, $roleAssignment->getPublicKeyId(), $rskData, $userIds);
    }

    private function assignRole_(string $roleName, string $publicKeyId, string $rskData, array $userIds): void
    {
        $userRecords = $this->storage->selectUsers($userIds);

        $roleAssignments = new RoleAssignmentCollection();

        foreach ($userRecords->getAsArray() as $userRecord) {
            $upk = $this->pureCrypto->importPublicKey($userRecord->getUpk());

            $encryptedRsk = $this->pureCrypto->encryptRolePrivateKey($rskData, $upk, $this->oskp->getPrivateKey());

            $roleAssignments->add(new RoleAssignment($roleName, $userRecord->getUserId(), $publicKeyId, $encryptedRsk));
        }

        $this->storage->insertRoleAssignments($roleAssignments);
    }

    public function unassignRole(string $roleName, array $userIds): void
    {
        $this->storage->deleteRoleAssignments($roleName, $userIds);
    }


    private function _registerUserInternal(string $userId, string $password): RegistrationResult
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($password, "password");

        $passwordHash = $this->pureCrypto->computePasswordHash($password);

        $encryptedPwdHash = $this->pureCrypto->encryptForBackup($passwordHash, $this->buppk, $this->oskp->getPrivateKey
        ());

        $pwdRecoveryData = $this->kmsManager->generatePwdRecoveryData($passwordHash);

        // [enrollment_record, account_key]
        $pheResult = $this->pheManager->getEnrollment($passwordHash);

        $ukp = $this->pureCrypto->generateUserKey();

        $uskData = $this->pureCrypto->exportPrivateKey($ukp->getPrivateKey());

        $encryptedUsk = $this->pureCrypto->encryptSymmetricWithNewNonce($uskData, "", $pheResult[1]);

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

        $this->getStorage()->insertUser($userRecord);

        return new RegistrationResult($userRecord, $ukp, $pheResult[1]);
    }

    private function _authenticateUserInternal(UserRecord $userRecord, VirgilKeyPair $ukp, string $phek, string
$sessionId = null, int $ttl): AuthResult
    {
        $creationDate = new \DateTime("now");
        $ts = $creationDate->getTimestamp() + ($ttl * 1000);
        $expirationDate = new \DateTime("@$ts");

        $grant = new PureGrant($ukp, $userRecord->getUserId(), $sessionId, $creationDate, $expirationDate);

        $grantKeyRaw = $this->pureCrypto->generateSymmetricOneTimeKey();
        $keyId = $this->pureCrypto->computeSymmetricKeyId($grantKeyRaw);

        $headerBuilder = (new ProtoEncryptedGrantHeader)
            ->setCreationDate($grant->getCreationDate()->getTimestamp() / 1000)
            ->setExpirationDate($grant->getExpirationDate()->getTimestamp() / 1000)
            ->setUserId($grant->getUserId())
            ->setKeyId($keyId);

        if (!is_null($sessionId))
            $headerBuilder->setSessionId($sessionId);

        $headerBytes = $headerBuilder->serializeToString();

        $grantWrap = $this->kmsManager->generateGrantKeyEncryptionData($grantKeyRaw, $headerBytes);

        $grantKey = new GrantKey($userRecord->getUserId(),
        $keyId, $this->currentVersion,
        $grantWrap->getWrap(),
        $grantWrap->getBlob(),
        $creationDate, $expirationDate);

        $this->getStorage()->insertGrantKey($grantKey);

        $encryptedPhek = $this->pureCrypto->encryptSymmetricWithOneTimeKey($phek, $headerBytes, $grantKeyRaw);

        $encryptedGrantData = (new ProtoEncryptedGrant)
            ->setVersion($this->currentGrantVersion)
            ->setHeader($headerBytes)
            ->setEncryptedPhek($encryptedPhek);

        $encryptedGrant = base64_encode($encryptedGrantData->serializeToString());

        return new AuthResult($grant, $encryptedGrant);
    }

    /**
     * @param UserRecord $userRecord
     * @param string $privateKeyData
     * @param string $newPassword
     * @throws PureCryptoException
     */
    private function _changeUserPasswordInternal(UserRecord $userRecord, string $privateKeyData, string $newPassword):
    void
    {
        try {
            ValidationUtils::checkNullOrEmpty($newPassword, "newPassword");

            $newPasswordHash = $this->pureCrypto->computePasswordHash($newPassword);

            // [enrollment_record, account_key]
            $enrollResult = $this->pheManager->getEnrollment($newPasswordHash);

            $pwdRecoveryData = $this->kmsManager->generatePwdRecoveryData($newPasswordHash);

            $newEncryptedUsk = $this->pureCrypto->encryptSymmetricWithNewNonce($privateKeyData, "",
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
                                    array $otherUserIds): VirgilPublicKeyCollection
    {
        $otherUserRecords = $this->storage->selectUsers($otherUserIds);

        if (!empty($otherUserRecords->getAsArray())) {
            foreach ($otherUserRecords->getAsArray() as $record) {
                $otherUpk = $this->pureCrypto->importPublicKey($record->getUpk());
                $publicKeys->add($otherUpk);
            }
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

    public function getBuppk(): VirgilPublicKey
    {
        return $this->buppk;
    }

    public function getOskp(): VirgilKeyPair
    {
        return $this->oskp;
    }

    public function getExternalPublicKeys(): VirgilPublicKeyMap
    {
        return $this->externalPublicKeys;
    }
}