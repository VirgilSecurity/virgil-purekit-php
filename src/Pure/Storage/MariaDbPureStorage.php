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

namespace Virgil\PureKit\Pure\Storage;

use PDO;
use PDOException;
use PurekitV3Storage\UserRecord as ProtoUserRecord;
use PurekitV3Storage\CellKey as ProtoCellKey;
use PurekitV3Storage\GrantKey as ProtoGrantKey;
use PurekitV3Storage\Role as ProtoRole;
use PurekitV3Storage\RoleAssignment as ProtoRoleAssignment;
use Virgil\PureKit\Pure\Collection\GrantKeyCollection;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureStorageGenericErrorStatus;
use Virgil\PureKit\Pure\Exception\MariaDbOperationNotSupportedException;
use Virgil\PureKit\Pure\Exception\MariaDbSqlException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKEyAlreadyExistsException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKeyNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageGenericException;
use Virgil\PureKit\Pure\Exception\PureStorageGrantKeyNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageRoleAssignmentNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageRoleNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageUserNotFoundException;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\PureModelSerializer;
use Virgil\PureKit\Pure\PureModelSerializerDependent;
use Virgil\PureKit\Pure\Util\ValidationUtils;

/**
 * Class MariaDbPureStorage
 * @package Virgil\PureKit\Pure\Storage
 */
class MariaDbPureStorage implements PureStorage, PureModelSerializerDependent
{
    /**
     * @var string
     */
    private $host;
    /**
     * @var string
     */
    private $login;
    /**
     * @var string
     */
    private $password;
    /**
     * @var PureModelSerializer
     */
    private $pureModelSerializer;

    public const ER_DUP_ENTRY = 1062;

    /**
     * MariaDbPureStorage constructor.
     * @param string $host
     * @param string $login
     * @param string $password
     */
    public function __construct(string $host, string $login, string $password)
    {
        $this->host = $host;
        $this->login = $login;
        $this->password = $password;
    }

    /**
     * @return PureModelSerializer
     */
    public function getPureModelSerializer(): PureModelSerializer
    {
        return $this->pureModelSerializer;
    }

    /**
     * @param PureModelSerializer $pureModelSerializer
     */
    public function setPureModelSerializer(PureModelSerializer $pureModelSerializer): void
    {
        $this->pureModelSerializer = $pureModelSerializer;
    }

    /**
     * @return PDO
     */
    private function getConnection()
    {
        return new PDO($this->host, $this->login, $this->password);
    }

    /**
     * @param UserRecord $userRecord
     * @throws PureStorageGenericException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function insertUser(UserRecord $userRecord): void
    {
        $protobuf = $this->getPureModelSerializer()->serializeUserRecord($userRecord);

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "INSERT INTO virgil_users (" .
                "user_id," .
                "record_version," .
                "protobuf) " .
                "VALUES (?, ?, ?);"
            );

            $userId = $userRecord->getUserId();
            $recordVersion = $userRecord->getRecordVersion();
            $protobufString = $protobuf->serializeToString();

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $recordVersion);
            $stmt->bindParam(3, $protobufString);
            $stmt->execute();

        } catch (PDOException $exception) {
            if ($exception->getCode() != self::ER_DUP_ENTRY)
                throw $exception;

            throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ALREADY_EXISTS());
        }
    }

    /**
     * @param UserRecord $userRecord
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws PureStorageUserNotFoundException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function updateUser(UserRecord $userRecord): void
    {
        $protobuf = $this->getPureModelSerializer()->serializeUserRecord($userRecord);

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "UPDATE virgil_users " .
                "SET record_version=?, protobuf=? " .
                "WHERE user_id=?;"
            );

            $recordVersion = $userRecord->getRecordVersion();
            $protobufString = $protobuf->serializeToString();
            $userId = $userRecord->getUserId();

            $stmt->bindParam(1, $recordVersion);
            $stmt->bindParam(2, $protobufString);
            $stmt->bindParam(3, $userId);

            $rows = $stmt->execute();

            if ($rows != 1)
                throw new PureStorageUserNotFoundException([$userRecord->getUserId()]);

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param UserRecordCollection $userRecords
     * @param int $previousPheVersion
     * @throws MariaDbSqlException
     */
    public function updateUsers(UserRecordCollection $userRecords, int $previousPheVersion): void
    {
        try {
            $conn = $this->getConnection();

            $conn->beginTransaction();

            $stmt = $conn->prepare(
                "UPDATE virgil_users " .
                "SET record_version=?," .
                "protobuf=? " .
                "WHERE user_id=? AND record_version=?;"
            );

            if (!empty($userRecords->getAsArray())) {
                foreach ($userRecords->getAsArray() as $userRecord) {
                    $protobuf = $this->getPureModelSerializer()->serializeUserRecord($userRecord);

                    $recordVersion = $userRecord->getRecordVersion();
                    $protobufString = $protobuf->serializeToString();
                    $userId = $userRecord->getUserId();

                    $stmt->bindParam(1, $recordVersion);
                    $stmt->bindParam(2, $protobufString);
                    $stmt->bindParam(3, $userId);
                    $stmt->bindParam(4, $previousPheVersion);

                    $stmt->execute();
                }
            }

            $conn->commit();

        } catch (PDOException $exception) {
            $conn->rollBack();
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        } catch (\Exception $exception) {
            $conn->rollBack();
            throw $exception;
        }
    }

    /**
     * @param string $rs
     * @return UserRecord
     * @throws MariaDbSqlException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    private function parseUserRecord(string $rs): UserRecord
    {
        try {
            $protobuf = new ProtoUserRecord();
            $protobuf->mergeFromString($rs);
        } catch (\Exception $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }

        return $this->getPureModelSerializer()->parseUserRecord($protobuf);
    }

    /**
     * @param string $userId
     * @return UserRecord
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws PureStorageUserNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectUser(string $userId): UserRecord
    {
        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "SELECT protobuf " .
                "FROM virgil_users " .
                "WHERE user_id=?;"
            );

            $stmt->bindParam(1, $userId);

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $result = $stmt->fetchAll();

            if (empty($result))
                throw new PureStorageUserNotFoundException([$userId]);

            $userRecord = $this->parseUserRecord($result[0]['protobuf']);

            if ($userId != $userRecord->getUserId())
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());

            return $userRecord;

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param array $userIds
     * @return UserRecordCollection
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws PureStorageUserNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectUsers(array $userIds): UserRecordCollection
    {
        if (empty($userIds))
            return new UserRecordCollection();

        try {
            $conn = $this->getConnection();

            $idsSet = $userIds;

            $sbSql = "SELECT protobuf FROM virgil_users WHERE user_id in (";

            for ($i = 0; $i < count($userIds); $i++) {
                if ($i > 0)
                    $sbSql .= ",";

                $sbSql .= "?";
            }

            $sbSql .= ");";

            $stmt = $conn->prepare($sbSql);

            $j = 1;
            foreach ($userIds as &$userId) {
                $stmt->bindParam($j++, $userId);
            }

            $userRecords = new UserRecordCollection();

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);

            $result = $stmt->fetchAll();

            foreach ($result as $rs) {
                $userRecord = $this->parseUserRecord($rs['protobuf']);

                if (!in_array($userRecord->getUserId(), $idsSet))
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());

                if (($key = array_search($userRecord->getUserId(), $idsSet)) !== false) {
                    unset($idsSet[$key]);
                    $idsSet = array_values($idsSet);
                }

                $userRecords->add($userRecord);
            }

            if (!empty($idsSet))
                throw new PureStorageUserNotFoundException([$idsSet]);

            return $userRecords;

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param int $recordVersion
     * @return UserRecordCollection
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectUsers_(int $recordVersion): UserRecordCollection
    {
        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "SELECT protobuf " .
                "FROM virgil_users " .
                "WHERE record_version=? " .
                "LIMIT 1000;"
            );

            $stmt->bindParam(1, $recordVersion);

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);

            $userRecords = new UserRecordCollection();

            while ($result = $stmt->fetch()) {
                $userRecord = $this->parseUserRecord($result['protobuf']);

                if ($recordVersion != $userRecord->getRecordVersion())
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::RECORD_VERSION_MISMATCH());

                $userRecords->add($userRecord);
            }

            return $userRecords;

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $userId
     * @param bool $cascade
     * @throws MariaDbOperationNotSupportedException
     * @throws MariaDbSqlException
     * @throws PureStorageUserNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function deleteUser(string $userId, bool $cascade): void
    {
        ValidationUtils::checkNullOrEmpty($userId, "roleName");

        if (!$cascade) {
            throw new MariaDbOperationNotSupportedException();
        }

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "DELETE FROM virgil_users WHERE user_id = ?;"
            );

            $stmt->bindParam(1, $userId);

            $rows = $stmt->execute();

            if ($rows != 1)
                throw new PureStorageUserNotFoundException([$userId]);

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $rs
     * @return CellKey
     * @throws MariaDbSqlException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    private function parseCellKey(string $rs): CellKey
    {
        try {
            $protobuf = new ProtoCellKey();
            $protobuf->mergeFromString($rs);
        } catch (\Exception $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }

        return $this->getPureModelSerializer()->parseCellKey($protobuf);
    }

    /**
     * @param string $userId
     * @param string $dataId
     * @return CellKey
     * @throws MariaDbSqlException
     * @throws PureStorageCellKeyNotFoundException
     * @throws PureStorageGenericException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectCellKey(string $userId, string $dataId): CellKey
    {
        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "SELECT protobuf " .
                "FROM virgil_keys " .
                "WHERE user_id=? AND data_id=?;"
            );

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $dataId);

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $result = $stmt->fetchAll();

            if (!empty($result)) {
                $cellKey = $this->parseCellKey($result[0]['protobuf']);

                if ($userId != $cellKey->getUserId() || $dataId != $cellKey->getDataId())
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::CELL_KEY_ID_MISMATCH());

                return $cellKey;
            } else {
                throw new PureStorageCellKeyNotFoundException();
            }

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param CellKey $cellKey
     * @throws PureStorageCellKEyAlreadyExistsException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function insertCellKey(CellKey $cellKey): void
    {
        $protobuf = $this->getPureModelSerializer()->serializeCellKey($cellKey);

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "INSERT INTO virgil_keys (" .
                "user_id," .
                "data_id," .
                "protobuf) " .
                "VALUES (?, ?, ?);"
            );

            $userId = $cellKey->getUserId();
            $dataId = $cellKey->getDataId();
            $protobufString = $protobuf->serializeToString();

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $dataId);
            $stmt->bindParam(3, $protobufString);
            $stmt->execute();

        } catch (PDOException $exception) {
            if ($exception->getCode() != self::ER_DUP_ENTRY)
                throw $exception;

            throw new PureStorageCellKEyAlreadyExistsException();
        }
    }

    /**
     * @param CellKey $cellKey
     * @throws MariaDbSqlException
     * @throws PureStorageCellKeyNotFoundException
     * @throws PureStorageGenericException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function updateCellKey(CellKey $cellKey): void
    {
        ValidationUtils::checkNull($cellKey, "cellKey");

        $protobuf = $this->getPureModelSerializer()->serializeCellKey($cellKey);

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "UPDATE virgil_keys " .
                "SET protobuf=? " .
                "WHERE user_id=? AND data_id=?;"
            );

            $protobufString = $protobuf->serializeToString();
            $userId = $cellKey->getUserId();
            $dataId = $cellKey->getDataId();

            $stmt->bindParam(1, $protobufString);
            $stmt->bindParam(2, $userId);
            $stmt->bindParam(3, $dataId);

            $rows = $stmt->execute();

            if ($rows != 1)
                throw new PureStorageCellKeyNotFoundException();

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $userId
     * @param string $dataId
     * @throws MariaDbSqlException
     * @throws PureStorageCellKeyNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function deleteCellKey(string $userId, string $dataId): void
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($dataId, "dataId");

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "DELETE FROM virgil_keys WHERE user_id = ? AND data_id = ?;"
            );

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $dataId);

            $rows = $stmt->execute();

            if ($rows != 1)
                throw new PureStorageCellKeyNotFoundException();

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param Role $role
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function insertRole(Role $role): void
    {
        ValidationUtils::checkNull($role, "role");
        $protobuf = $this->getPureModelSerializer()->serializeRole($role);

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "INSERT INTO virgil_roles (" .
                "role_name," .
                "protobuf) " .
                "VALUES (?, ?);"
            );

            $roleName = $role->getRoleName();
            $protobufString = $protobuf->serializeToString();

            $stmt->bindParam(1, $roleName);
            $stmt->bindParam(2, $protobufString);

            try {
                $stmt->execute();
            } catch (PDOException $exception) {
                if ($exception->getCode() != self::ER_DUP_ENTRY)
                    throw $exception;

                throw new PureStorageGenericException(PureStorageGenericErrorStatus::ROLE_ALREADY_EXISTS());
            }

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $rs
     * @return Role
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    private function parseRole(string $rs): Role
    {
        try {
            $protobuf = new ProtoRole();
            $protobuf->mergeFromString($rs);
        } catch (\Exception $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }

        return $this->getPureModelSerializer()->parseRole($protobuf);
    }

    /**
     * @param array $roleNames
     * @return RoleCollection
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws PureStorageRoleNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectRoles(array $roleNames): RoleCollection
    {
        $roleCollection = new RoleCollection();

        if (empty($roleNames))
            return $roleCollection;

        try {
            $conn = $this->getConnection();

            $namesSet = $roleNames;

            // TODO: Proper StringBuilder size

            $sbSql = "SELECT protobuf FROM virgil_roles WHERE role_name in (";

            for ($i = 0; $i < count($roleNames); $i++) {
                if ($i > 0)
                    $sbSql .= ",";

                $sbSql .= "?";
            }

            $sbSql .= ");";

            $stmt = $conn->prepare($sbSql);

            $j = 1;

            foreach ($roleNames as &$roleName) {
                $stmt->bindParam($j++, $roleName);
            }

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $result = $stmt->fetchAll();

            foreach ($result as $rs) {
                $role = $this->parseRole($rs['protobuf']);

                if (!in_array($role->getRoleName(), $namesSet))
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::ROLE_NAME_MISMATCH());

                if (($key = array_search($role->getRoleName(), $namesSet)) !== false) {
                    unset($namesSet[$key]);
                    $namesSet = array_values($namesSet);
                }

                $roleCollection->add($role);
            }

            if (!empty($namesSet))
                throw new PureStorageRoleNotFoundException($namesSet);

            return $roleCollection;

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param RoleAssignmentCollection $roleAssignments
     * @throws MariaDbSqlException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function insertRoleAssignments(RoleAssignmentCollection $roleAssignments): void
    {
        ValidationUtils::checkNull($roleAssignments, "role");

        if (empty($roleAssignments->getAsArray()))
            return;

        try {
            $conn = $this->getConnection();
            $conn->beginTransaction();

            $stmt = $conn->prepare(
                "INSERT INTO virgil_role_assignments (" .
                "role_name," .
                "user_id," .
                "protobuf) " .
                "VALUES (?, ?, ?);"
            );

            foreach ($roleAssignments->getAsArray() as $roleAssignment) {
                $protobuf = $this->getPureModelSerializer()->serializeRoleAssignment($roleAssignment);

                $roleName = $roleAssignment->getRoleName();
                $userId = $roleAssignment->getUserId();
                $protobufString = $protobuf->serializeToString();

                $stmt->bindParam(1, $roleName);
                $stmt->bindParam(2, $userId);
                $stmt->bindParam(3, $protobufString);

                try {
                    $stmt->execute();
                } catch (PDOException $exception) {
                    if ($exception->getCode() != self::ER_DUP_ENTRY)
                        throw $exception;

                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::ROLE_ASSIGNMENT_ALREADY_EXISTS());
                }
            }

            $conn->commit();

        } catch (PDOException $exception) {
            $conn->rollBack();
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        } catch (\Exception $exception) {
            $conn->rollBack();
            throw $exception;
        }
    }

    /**
     * @param string $rs
     * @return RoleAssignment
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    private function parseRoleAssignment(string $rs): RoleAssignment
    {
        try {
            $protobuf = new ProtoRoleAssignment();
            $protobuf->mergeFromString($rs);
        } catch (\Exception $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }

        return $this->getPureModelSerializer()->parseRoleAssignment($protobuf);
    }

    /**
     * @param string $userId
     * @return RoleAssignmentCollection
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectRoleAssignments(string $userId): RoleAssignmentCollection
    {
        $roleAssignments = new RoleAssignmentCollection();

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "SELECT protobuf " .
                "FROM virgil_role_assignments " .
                "WHERE user_id=?;"
            );

            $stmt->bindParam(1, $userId);

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $result = $stmt->fetchAll();

            foreach ($result as $rs) {

                $roleAssignment = $this->parseRoleAssignment($rs['protobuf']);

                if ($roleAssignment->getUserId() != $userId) {
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::ROLE_USER_ID_MISMATCH());
                }

                $roleAssignments->add($roleAssignment);
            }

            return $roleAssignments;

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $roleName
     * @param string $userId
     * @return RoleAssignment
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws PureStorageRoleAssignmentNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectRoleAssignment(string $roleName, string $userId): RoleAssignment
    {
        ValidationUtils::checkNullOrEmpty($roleName, "roleName");
        ValidationUtils::checkNullOrEmpty($userId, "userId");

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "SELECT protobuf " .
                "FROM virgil_role_assignments " .
                "WHERE user_id=? AND role_name=?;"
            );

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $roleName);

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $result = $stmt->fetchAll();

            if (empty($result))
                throw new PureStorageRoleAssignmentNotFoundException($userId, $roleName);

            foreach ($result as $rs) {
                $roleAssignment = $this->parseRoleAssignment($rs['protobuf']);

                if ($roleAssignment->getUserId() != $userId || $roleAssignment->getRoleName() != $roleName) {
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::ROLE_NAME_USER_ID_MISMATCH());
                }

                return $roleAssignment;
            }
        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $roleName
     * @param array $userIds
     * @throws MariaDbSqlException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function deleteRoleAssignments(string $roleName, array $userIds): void
    {
        ValidationUtils::checkNullOrEmpty($roleName, "roleName");
        ValidationUtils::checkNull($userIds, "userIds");

        if (empty($userIds))
            return;

        $userIdsArray = [];

        try {
            $conn = $this->getConnection();

            $conn->beginTransaction();

            $stmt = $conn->prepare("
                DELETE FROM virgil_role_assignments WHERE role_name=? AND user_id=?
            ");

            $j = 0;

            foreach ($userIds as $userId) {
                $stmt->bindParam(1, $roleName);
                $stmt->bindParam(2, $userId);
                $userIdsArray[$j++] = $userId;

                $stmt->execute();
            }

            if ($j != count($userIds))
                throw new MariaDbOperationNotSupportedException();

            // TODO! Add throwable
            // PureStorageRoleAssignmentNotFoundException($userIdsArray[$i], $roleName);

        } catch (PDOException $exception) {
            $conn->rollBack();
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        } catch (\Exception $exception) {
            $conn->rollBack();
            throw $exception;
        }
    }

    /**
     * @param GrantKey $grantKey
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function insertGrantKey(GrantKey $grantKey): void
    {
        $protobuf = $this->getPureModelSerializer()->serializeGrantKey($grantKey);

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "INSERT INTO virgil_grant_keys (" .
                "user_id," .
                "key_id," .
                "record_version," .
                "expiration_date," .
                "protobuf) " .
                "VALUES (?, ?, ?, ?, ?);"
            );

            $userId = $grantKey->getUserId();
            $keyId = $grantKey->getKeyId();
            $recordVersion = $grantKey->getRecordVersion();
            $expirationDate = $grantKey->getExpirationDate()->getTimestamp();
            $protobufString = $protobuf->serializeToString();

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $keyId);
            $stmt->bindParam(3, $recordVersion);
            $stmt->bindParam(4, $expirationDate);
            $stmt->bindParam(5, $protobufString);

            try {
                $stmt->execute();
            } catch (PDOException $exception) {
                if ($exception->getCode() != self::ER_DUP_ENTRY)
                    throw $exception;

                throw new PureStorageGenericException(PureStorageGenericErrorStatus::GRANT_KEY_ALREADY_EXISTS());
            }
        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $userId
     * @param string $keyId
     * @return GrantKey
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws PureStorageGrantKeyNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function selectGrantKey(string $userId, string $keyId): GrantKey
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($keyId, "keyId");

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "SELECT protobuf " .
                "FROM virgil_grant_keys " .
                "WHERE user_id=? AND key_id=?;"
            );

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $keyId);

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $result = $stmt->fetchAll();

            if (empty($result))
                throw new PureStorageGrantKeyNotFoundException($userId, $keyId);

            $grantKey = $this->parseGrantKey($result[0]['protobuf']);

            if ($userId != $grantKey->getUserId())
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());

            if ($keyId != $grantKey->getKeyId())
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::GRANT_KEY_ID_MISMATCH());

            return $grantKey;

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $rs
     * @return GrantKey
     * @throws MariaDbSqlException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    private function parseGrantKey(string $rs): GrantKey
    {
        try {
            $protobuf = new ProtoGrantKey();
            $protobuf->mergeFromString($rs);
        } catch (\Exception $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }

        return $this->getPureModelSerializer()->parseGrantKey($protobuf);
    }

    /**
     * @param string $userId
     * @param string $keyId
     * @throws MariaDbSqlException
     * @throws PureStorageGrantKeyNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function deleteGrantKey(string $userId, string $keyId): void
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($keyId, "keyId");

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "DELETE FROM virgil_grant_keys WHERE user_id = ? AND key_id = ?;"
            );

            $stmt->bindParam(1, $userId);
            $stmt->bindParam(2, $keyId);

            $rows = $stmt->execute();

            if ($rows != 1)
                throw new PureStorageGrantKeyNotFoundException($userId, $keyId);

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $roleName
     * @throws MariaDbOperationNotSupportedException
     * @throws MariaDbSqlException
     * @throws PureStorageRoleNotFoundException
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function deleteRole(string $roleName): void
    {
        ValidationUtils::checkNullOrEmpty($roleName, "roleName");

        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "DELETE FROM virgil_roles WHERE role_name = ?;"
            );

            $stmt->bindParam(1, $roleName);

            $rows = $stmt->execute();

            if ($rows != 1)
                throw new PureStorageRoleNotFoundException([$roleName]);

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param int $recordVersion
     * @return GrantKeyCollection
     * @throws MariaDbSqlException
     * @throws PureStorageGenericException
     * @throws \Virgil\PureKit\Pure\Exception\PureStorageInvalidProtobufException
     */
    public function selectGrantKeys(int $recordVersion): GrantKeyCollection
    {
        try {
            $conn = $this->getConnection();

            $stmt = $conn->prepare(
                "SELECT protobuf " .
                "FROM virgil_grant_keys " .
                "WHERE record_version=? " .
                "LIMIT 1000;"
            );

            $stmt->bindParam(1, $recordVersion);

            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);

            $grantKeys = new GrantKeyCollection();

            while ($result = $stmt->fetch()) {
                $grantKey = $this->parseGrantKey($result['protobuf']);

                if ($recordVersion != $grantKey->getRecordVersion())
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::RECORD_VERSION_MISMATCH());

                $grantKeys->add($grantKey);
            }

            return $grantKeys;

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param GrantKeyCollection $grantKeys
     * @throws MariaDbSqlException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function updateGrantKeys(GrantKeyCollection $grantKeys): void
    {
        ValidationUtils::checkNull($grantKeys, "grantKeys");

        try {
            $conn = $this->getConnection();

            $conn->beginTransaction();

            $stmt = $conn->prepare(
                "UPDATE virgil_grant_keys " .
                "SET record_version=?," .
                "protobuf=? " .
                "WHERE key_id=? AND user_id=?;"
            );

            if (!empty($grantKeys->getAsArray())) {
                foreach ($grantKeys->getAsArray() as $grantKey) {
                    $protobuf = $this->getPureModelSerializer()->serializeGrantKey($grantKey);

                    $recordVersion = $grantKey->getRecordVersion();
                    $protobufString = $protobuf->serializeToString();
                    $keyId = $grantKey->getKeyId();
                    $userId = $grantKey->getUserId();

                    $stmt->bindParam(1, $recordVersion);
                    $stmt->bindParam(2, $protobufString);
                    $stmt->bindParam(3, $keyId);
                    $stmt->bindParam(4, $userId);

                    $stmt->execute();
                }
            }

            $conn->commit();

        } catch (PDOException $exception) {
            $conn->rollBack();
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        } catch (\Exception $exception) {
            $conn->rollBack();
            throw $exception;
        }
    }

    /**
     * @throws MariaDbSqlException
     */
    public function cleanDb(): void
    {
        try {
            $conn = $this->getConnection();

            $conn->query(
                "DROP TABLE IF EXISTS virgil_grant_keys, virgil_role_assignments, virgil_roles, virgil_keys, virgil_users;"
            );

            $conn->query("DROP EVENT IF EXISTS delete_expired_grant_keys;");
        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param int $cleanGrantKeysIntervalSeconds
     * @throws MariaDbSqlException
     */
    public function initDb(int $cleanGrantKeysIntervalSeconds): void
    {
        try {
            $conn = $this->getConnection();

            $conn->query("CREATE TABLE virgil_users (" .
                "user_id CHAR(36) NOT NULL PRIMARY KEY," .
                "record_version INTEGER NOT NULL," .
                "    INDEX record_version_index(record_version)," .
                "    UNIQUE INDEX user_id_record_version_index(user_id, record_version)," .
                "protobuf VARBINARY(2048) NOT NULL" .
                ");");

            $conn->query(
                "CREATE TABLE virgil_keys (" .
                "user_id CHAR(36) NOT NULL," .
                "    FOREIGN KEY (user_id)" .
                "        REFERENCES virgil_users(user_id)" .
                "        ON DELETE CASCADE," .
                "data_id VARCHAR(128) NOT NULL," .
                "protobuf VARBINARY(32768) NOT NULL, /* Up to 125 recipients */" .
                "    PRIMARY KEY(user_id, data_id)" .
                ");"
            );

            $conn->query(
                "CREATE TABLE virgil_roles (" .
                "role_name VARCHAR(64) NOT NULL PRIMARY KEY," .
                "protobuf VARBINARY(256) NOT NULL" .
                ");"
            );

            $conn->query(
                "CREATE TABLE virgil_role_assignments (" .
                "role_name VARCHAR(64) NOT NULL," .
                "    FOREIGN KEY (role_name)" .
                "        REFERENCES virgil_roles(role_name)" .
                "        ON DELETE CASCADE," .
                "user_id CHAR(36) NOT NULL," .
                "    FOREIGN KEY (user_id)" .
                "        REFERENCES virgil_users(user_id)" .
                "        ON DELETE CASCADE," .
                "    INDEX user_id_index(user_id)," .
                "protobuf VARBINARY(1024) NOT NULL," .
                "    PRIMARY KEY(role_name, user_id)" .
                ");"
            );

            $conn->query(
                "CREATE TABLE virgil_grant_keys (" .
                "record_version INTEGER NOT NULL," .
                "    INDEX record_version_index(record_version)," .
                "user_id CHAR(36) NOT NULL," .
                "    FOREIGN KEY (user_id)" .
                "        REFERENCES virgil_users(user_id)" .
                "        ON DELETE CASCADE," .
                "key_id BINARY(64) NOT NULL," .
                "expiration_date BIGINT NOT NULL," .
                "    INDEX expiration_date_index(expiration_date)," .
                "protobuf VARBINARY(512) NOT NULL," .
                "    PRIMARY KEY(user_id, key_id)" .
                ");"
            );

            $conn->query("SET @@global.event_scheduler = 1;");

            $conn->query(
                "CREATE EVENT delete_expired_grant_keys ON SCHEDULE EVERY $cleanGrantKeysIntervalSeconds SECOND" .
                "    DO" .
                "        DELETE FROM virgil_grant_keys WHERE expiration_date < UNIX_TIMESTAMP();");

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param string $sql
     * @throws MariaDbSqlException
     */
    public function executeSql(string $sql): void
    {
        try {
            $conn = $this->getConnection();
            $stmt = $conn->query($sql);

        } catch (PDOException $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }
}