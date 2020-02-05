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

use PurekitV3Crypto\EnrollmentRecord as ProtoEnrollmentRecord;
use PurekitV3Storage\GrantKey as ProtoGrantKey;
use PurekitV3Storage\GrantKeySigned as ProtoGrantKeySigned;
use PurekitV3Storage\UserRecord as ProtoUserRecord;
use PurekitV3Storage\CellKey as ProtoCellKey;
use PurekitV3Storage\CellKeySigned as ProtoCellKeySigned;
use PurekitV3Storage\Role as ProtoRole;
use PurekitV3Storage\RoleAssignment as ProtoRoleAssignment;
use PurekitV3Storage\RoleAssignmentSigned as ProtoRoleAssignmentSigned;
use PurekitV3Storage\RoleSigned as ProtoRoleSigned;
use PurekitV3Storage\UserRecordSigned as ProtoUserRecordSigned;
use Virgil\Crypto\Core\VirgilKeyPair;
use Virgil\Crypto\VirgilCrypto;
use Virgil\PureKit\Pure\Exception\Enum\ErrorStatus;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\Util\ValidateUtil;

/**
 * Class PureModelSerializer
 * @package Virgil\PureKit\Pure
 */
class PureModelSerializer
{
    private const CURRENT_USER_VERSION = 1;
    private const CURRENT_USER_SIGNED_VERSION = 1;
    private const CURRENT_CELL_KEY_VERSION = 1;
    private const CURRENT_CELL_KEY_SIGNED_VERSION = 1;
    private const CURRENT_ROLE_VERSION = 1;
    private const CURRENT_ROLE_SIGNED_VERSION = 1;
    private const CURRENT_ROLE_ASSIGNMENT_VERSION = 1;
    private const CURRENT_ROLE_ASSIGNMENT_SIGNED_VERSION = 1;
    private const CURRENT_GRANT_KEY_VERSION = 1;
    private const CURRENT_GRANT_KEY_SIGNED_VERSION = 1;

    /**
     * @var VirgilCrypto
     */
    private $crypto;
    /**
     * @var VirgilKeyPair
     */
    private $signingKey;

    /**
     * PureModelSerializer constructor.
     * @param VirgilCrypto $crypto
     * @param VirgilKeyPair $signingKey
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     */
    public function __construct(VirgilCrypto $crypto, VirgilKeyPair $signingKey)
    {
        ValidateUtil::checkNull($crypto, "crypto");
        ValidateUtil::checkNull($signingKey, "signingKey");

        $this->crypto = $crypto;
        $this->signingKey = $signingKey;
    }

    /**
     * @param string $model
     * @return string
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    private function generateSignature(string $model): string
    {
        try {
            return $this->crypto->generateSignature($model, $this->signingKey->getPrivateKey());
        } catch (SigningException $exception) {
            throw new PureStorageGenericException(ErrorStatus::SIGNING_EXCEPTION());
        }
    }

    /**
     * @param string $signature
     * @param string $model
     * @return void
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    private function verifySignature(string $signature, string $model): void
    {
        try {
            $verified = $this->crypto->verifySignature($signature, $model, $this->signingKey->getPublicKey());
        } catch (VerificationException $exception) {
            throw new PureStorageGenericException(ErrorStatus::VERIFICATION_EXCEPTION());
        }

        if (!$verified)
            throw new PureStorageGenericException(ErrorStatus::STORAGE_SIGNATURE_VERIFICATION_FAILED());
    }

    /**
     * @param UserRecord $userRecord
     * @return ProtoUserRecord
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function serializeUserRecord(UserRecord $userRecord): ProtoUserRecord
    {
        try {
            $enrollmentRecord = (new ProtoEnrollmentRecord)->mergeFromString($userRecord->getPheRecord());
        } catch (InvalidProtocolBufferException $exception) {
            throw new PureStorageGenericException(ErrorStatus::INVALID_PROTOBUF());
        }

        $userRecordSigned = (new ProtoUserRecordSigned)
            ->setVersion(self::CURRENT_USER_SIGNED_VERSION)
            ->setUserId($userRecord->getUserId())
            ->setPheRecordNc($enrollmentRecord->getNc())
            ->setPheRecordNs($enrollmentRecord->getNs())
            ->setUpk($userRecord->getUpk())
            ->setEncryptedUsk($userRecord->getEncryptedUsk())
            ->setEncryptedUskBackup($userRecord->getEncryptedUskBackup())
            ->setBackupPwdHash($userRecord->getBackupPwdHash())
            ->setPasswordRecoveryBlob($userRecord->getPasswordRecoveryBlob())
            ->serializeToString();

        $signature = $this->crypto->generateSignature($userRecordSigned, $this->signingKey->getPrivateKey());

        return (new ProtoUserRecord)
            ->setVersion(self::CURRENT_USER_VERSION)
            ->setUserRecordSigned($userRecordSigned)
            ->setSignature($signature)
            ->setPheRecordT0($enrollmentRecord->getT0())
            ->setPheRecordT1($enrollmentRecord->getT1())
            ->setRecordVersion($userRecord->getRecordVersion())
            ->setPasswordRecoveryWrap($userRecord->getPasswordRecoveryWrap());
    }

    public function parseUserRecord(ProtoUserRecord $protobufRecord): UserRecord
    {
        $this->verifySignature($protobufRecord->getSignature(), $protobufRecord->getUserRecordSigned());

        try {
            $recordSigned = (new ProtoUserRecordSigned)->mergeFromString($protobufRecord->getUserRecordSigned());
        } catch (InvalidProtocolBufferException $exception) {
            throw new PureStorageInvalidProtobufException($exception);
        }

        $pheRecord = (new ProtoEnrollmentRecord)
            ->setNc($recordSigned->getPheRecordNc())
            ->setNs($recordSigned->getPheRecordNs())
            ->setT0($protobufRecord->getPheRecordT0())
            ->setT1($protobufRecord->getPheRecordT1())
            ->serializeToString();

        return new UserRecord(
            $recordSigned->getUserId(),
            $pheRecord,
            $protobufRecord->getRecordVersion(),
            $recordSigned->getUpk(),
            $recordSigned->getEncryptedUsk(),
            $recordSigned->getEncryptedUskBackup(),
            $recordSigned->getBackupPwdHash(),
            $protobufRecord->getPasswordRecoveryWrap(),
            $recordSigned->getPasswordRecoveryBlob()
        );
    }

    /**
     * @param CellKey $cellKey
     * @return ProtoCellKey
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function serializeCellKey(CellKey $cellKey): ProtoCellKey
    {
        $cellKeySigned = (new ProtoCellKeySigned)
            ->setVersion(self::CURRENT_CELL_KEY_SIGNED_VERSION)
            ->setUserId($cellKey->getUserId())
            ->setDataId($cellKey->getDataId())
            ->setCpk($cellKey->getCpk())
            ->setEncryptedCskCms($cellKey->getEncryptedCskCms())
            ->setEncryptedCskBody($cellKey->getEncryptedCskBody())
            ->serializeToString();

        $signature = $this->generateSignature($cellKeySigned);

        return (new ProtoCellKey)
            ->setVersion(self::CURRENT_CELL_KEY_VERSION)
            ->setCellKeySigned($cellKeySigned)
            ->setSignature($signature);
    }

    /**
     * @param ProtoCellKey $protobufRecord
     * @return CellKey
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function parseCellKey(ProtoCellKey $protobufRecord): CellKey
    {
        $this->verifySignature($protobufRecord->getSignature(), $protobufRecord->getCellKeySigned());

        try {
            $keySigned = (new ProtoCellKeySigned)->mergeFromString($protobufRecord->getCellKeySigned());
        } catch (InvalidProtocolBufferException $exception) {
            throw new PureStorageInvalidProtobufException($exception);
        }

        return new CellKey($keySigned->getUserId(), $keySigned->getDataId(),
            $keySigned->getCpk(),
            $keySigned->getEncryptedCskCms(),
            $keySigned->getEncryptedCskBody()
        );
    }

    /**
     * @param Role $role
     * @return ProtoRole
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function serializeRole(Role $role): ProtoRole
    {
        $roleSigned = (new ProtoRoleSigned)
            ->setVersion(self::CURRENT_ROLE_SIGNED_VERSION)
            ->setName($role->getRoleName())
            ->setRpk($role->getRpk())
            ->serializeToString();

        $signature = $this->generateSignature($roleSigned);

        return (new ProtoRole)
            ->setVersion(self::CURRENT_ROLE_VERSION)
            ->setRoleSigned($roleSigned)
            ->setSignature($signature);
    }

    /**
     * @param ProtoRole $protobufRecord
     * @return Role
     * @throws PureLogicException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function parseRole(ProtoRole $protobufRecord): Role
    {
        $this->verifySignature($protobufRecord->getSignature(), $protobufRecord->getRoleSigned());

        try {
            $roleSigned = (new ProtoRoleSigned)->mergeFromString($protobufRecord->getRoleSigned());
        } catch (InvalidProtocolBufferException $exception) {
            throw new PureStorageInvalidProtobufException($exception);
        }

        return new Role($roleSigned->getName(), $roleSigned->getRpk());
    }

    /**
     * @param RoleAssignment $roleAssignment
     * @return ProtoRoleAssignment
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function serializeRoleAssignment(RoleAssignment $roleAssignment): ProtoRoleAssignment
    {
        $roleAssignmentSigned = (new ProtoRoleAssignmentSigned)
            ->setVersion(self::CURRENT_ROLE_ASSIGNMENT_SIGNED_VERSION)
            ->setRoleName($roleAssignment->getRoleName())
            ->setUserId($roleAssignment->getUserId())
            ->setEncryptedRsk($roleAssignment->getEncryptedRsk())
            ->setPublicKeyId($roleAssignment->getPublicKeyId())
            ->serializeToString();

        $signature = $this->generateSignature($roleAssignmentSigned);

        return (new ProtoRoleAssignment)
            ->setVersion(self::CURRENT_ROLE_ASSIGNMENT_VERSION)
            ->setRoleAssignmentSigned($roleAssignmentSigned)
            ->setSignature($signature);
    }

    /**
     * @param ProtoRoleAssignment $protobufRecord
     * @return RoleAssignment
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function parseRoleAssignment(ProtoRoleAssignment $protobufRecord): RoleAssignment
    {
        $this->verifySignature($protobufRecord->getSignature(), $protobufRecord->getRoleAssignmentSigned());

        try {
            $roleAssignmentSigned = (new ProtoRoleAssignmentSigned)
                ->mergeFromString($protobufRecord->getRoleAssignmentSigned());
        } catch (InvalidProtocolBufferException $exception) {
            throw new PureStorageInvalidProtobufException($exception);
        }

        return new RoleAssignment(
            $roleAssignmentSigned->getRoleName(),
            $roleAssignmentSigned->getUserId(),
            $roleAssignmentSigned->getPublicKeyId(), $roleAssignmentSigned->getEncryptedRsk());
    }

    /**
     * @param GrantKey $grantKey
     * @return ProtoGrantKey
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function serializeGrantKey(GrantKey $grantKey): ProtoGrantKey
    {
        $grantKeySigned = (new ProtoGrantKeySigned)
            ->setVersion(self::CURRENT_GRANT_KEY_SIGNED_VERSION)
            ->setUserId($grantKey->getUserId())
            ->setKeyId($grantKey->getKeyId())
            ->setEncryptedGrantKey($grantKey->getEncryptedGrantKey())
            ->setCreationDate($grantKey->getCreationDate()/1000)
            ->setExpirationDate($grantKey->getExpirationDate()/1000)
            ->serializeToString();

        $signature = $this->generateSignature($grantKeySigned);

        return (new ProtoGrantKey)
            ->setVersion(self::CURRENT_GRANT_KEY_VERSION)
            ->setGrantKeySigned($grantKeySigned)
            ->setSignature($signature);
    }

    public function parseGrantKey(ProtoGrantKey $protobufRecord): GrantKey
    {
        $this->verifySignature($protobufRecord->getSignature(), $protobufRecord->getGrantKeySigned());

        try {
            $grantKeySigned = (new ProtoGrantKeySigned)->mergeFromString($protobufRecord->getGrantKeySigned());
        } catch (InvalidProtocolBufferException $exception) {
            throw new PureStorageInvalidProtobufException($exception->getMessage(), $exception->getCode());
        }

        return new GrantKey($grantKeySigned->getUserId(), $grantKeySigned->getKeyId(),
            $grantKeySigned->getEncryptedGrantKey(),
            new \DateTime($grantKeySigned->getCreationDate() * 1000),
            new \DateTime($grantKeySigned->getExpirationDate() * 1000));
    }
}