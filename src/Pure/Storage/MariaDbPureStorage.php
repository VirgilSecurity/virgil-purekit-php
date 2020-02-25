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

namespace Virgil\PureKit\Pure\Storage;

use PurekitV3Storage\UserRecord as ProtoUserRecord;
use PurekitV3Storage\UserRecords;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureStorageGenericErrorStatus;
use Virgil\PureKit\Pure\Exception\MariaDbSqlException;
use Virgil\PureKit\Pure\Exception\PureStorageGenericException;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\PureModelSerializer;
use Virgil\PureKit\Pure\PureModelSerializerDependent;

class MariaDbPureStorage implements PureStorage, PureModelSerializerDependent
{
    private $host;
    private $userName;
    private $password;
    private $dbName;
    private $pureModelSerializer;

    public function __construct(string $host, string $userName, string $password, string $dbName)
    {
        $this->host = $host;
        $this->userName = $userName;
        $this->password = $password;
        $this->dbName = $dbName;
    }

    public function getPureModelSerializer(): PureModelSerializer
    {
        return $this->pureModelSerializer;
    }

    public function setPureModelSerializer(PureModelSerializer $pureModelSerializer): void
    {
        $this->pureModelSerializer = $pureModelSerializer;
    }

    private function getConnection()
    {
        return mysqli_connect($this->host, $this->userName, $this->password, $this->dbName);
    }

    public function insertUser(UserRecord $userRecord): void
    {
        $protobuf = $this->getPureModelSerializer()->serializeUserRecord($userRecord);

        $conn = $this->getConnection();
        if (!$conn)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->prepare(
            "INSERT INTO virgil_users (" .
            "user_id," .
            "phe_record_version," .
            "protobuf) " .
            "VALUES (?, ?, ?);"
        );

        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $userId = $userRecord->getUserId();
        $recordVersion = $userRecord->getRecordVersion();
        $protobufString = $protobuf->serializeToString();

        $stmt->bind_param("sis", $userId, $recordVersion, $protobufString);

        try {
            $stmt->execute();
        }
        catch (\mysqli_sql_exception $exception) {
            if ($exception->getCode() != 1062) {
                throw $exception;
            }

            throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ALREADY_EXISTS());
        }
    }

    public function updateUser(UserRecord $userRecord): void
    {
        $protobuf = $this->getPureModelSerializer()->serializeUserRecord($userRecord);

        $conn = $this->getConnection();
        if (!$conn)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->prepare(
            "UPDATE virgil_users " .
            "SET phe_record_version=?, protobuf=? " .
            "WHERE user_id=?;"
        );

        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $recordVersion = $userRecord->getRecordVersion();
        $protobufString = $protobuf->serializeToString();
        $userId = $userRecord->getUserId();

        $stmt->bind_param("iss",$recordVersion, $protobufString, $userId);

        $rows = $stmt->execute();
        if (!$rows)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        if ($rows != 1)
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_NOT_FOUND());
    }

    public function updateUsers(UserRecordCollection $userRecords, int $previousPheVersion): void
    {
        $conn = $this->getConnection();

        if (!$conn)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $conn->autocommit(false);

        $stmt = $conn->prepare(
            "UPDATE virgil_users " .
            "SET phe_record_version=?," .
            "protobuf=? " .
            "WHERE user_id=? AND phe_record_version=?;"
        );

        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        if (!empty($userRecords->getAsArray())) {
            foreach ($userRecords->getAsArray() as $userRecord) {
                $protobuf = $this->getPureModelSerializer()->serializeUserRecord($userRecord);
                $protobufString = $protobuf->serializeToString();

                $stmt->bind_param("issi",$recordVersion, $protobufString, $userId);
                try {
                    $stmt->execute();
                }
                catch (\mysqli_sql_exception $exception) {
                    throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
                }
            }
        }

        $conn->autocommit(true);
    }

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

    public function selectUser(string $userId): UserRecord
    {
        $conn = $this->getConnection();

        if (!$conn)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->prepare(
            "SELECT protobuf " .
            "FROM virgil_users " .
            "WHERE user_id=?;"
        );

        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt->bind_param("s",$userId);
        try {
            $stmt->execute();

            $stmt->bind_result($rs);
            $stmt->fetch();

            if ($rs) {
                $userRecord = $this->parseUserRecord($rs);

                if ($userId != $userRecord->getUserId())
                    throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());

                return $userRecord;
            } else {
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_NOT_FOUND());
            }
        }
        catch (\mysqli_sql_exception $exception) {
            throw new MariaDbSqlException($exception->getMessage(), $exception->getCode());
        }
    }

    public function selectUsers(array $userIds): UserRecordCollection
    {
        // TODO:
    }

    public function selectUsers_(int $pheRecordVersion): UserRecords
    {
        $conn = $this->getConnection();

        if (!$conn)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->prepare(
            "SELECT protobuf " .
            "FROM virgil_users " .
            "WHERE phe_record_version=? " .
            "LIMIT 1000;"
        );

        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt->bind_param("i",$pheRecordVersion);
    }

    public function deleteUser(string $userId, bool $cascade): void
    {
        // TODO: Implement deleteUser() method.
    }

    private function parseCellKey(array $rs): CellKey
    {

    }

    public function selectCellKey(string $userId, string $dataId): CellKey
    {
        // TODO: Implement selectCellKey() method.
    }

    public function insertCellKey(CellKey $cellKey): void
    {
        // TODO: Implement insertCellKey() method.
    }

    public function updateCellKey(CellKey $cellKey): void
    {
        // TODO: Implement updateCellKey() method.
    }

    public function deleteCellKey(string $userId, string $dataId): void
    {
        // TODO: Implement deleteCellKey() method.
    }

    public function insertRole(Role $role): void
    {
        // TODO: Implement insertRole() method.
    }

    private function parseRole(array $rs): Role
    {

    }

    public function selectRoles(array $roleNames): RoleCollection
    {
        // TODO: Implement selectRoles() method.
    }

    public function insertRoleAssignments(RoleAssignmentCollection $roleAssignments): void
    {
        // TODO: Implement insertRoleAssignments() method.
    }

    private function parseRoleAssignment(array $rs): RoleAssignment
    {

    }

    public function selectRoleAssignments(string $userId): RoleAssignmentCollection
    {
        // TODO: Implement selectRoleAssignments() method.
    }

    public function selectRoleAssignment(string $roleName, string $userId): RoleAssignment
    {
        // TODO: Implement selectRoleAssignment() method.
    }

    public function deleteRoleAssignments(string $roleName, array $userIds): void
    {
        // TODO: Implement deleteRoleAssignments() method.
    }

    public function insertGrantKey(GrantKey $grantKey): void
    {
        // TODO: Implement insertGrantKey() method.
    }

    public function selectGrantKey(string $userId, string $keyId): GrantKey
    {
        // TODO: Implement selectGrantKey() method.
    }

    private function parseGrantKey(array $rs): GrantKey
    {

    }

    public function deleteGrantKey(string $userId, string $keyId): void
    {
        // TODO: Implement deleteGrantKey() method.
    }

    public function cleanDb(): void
    {
        $conn = $this->getConnection();
        $stmt = $conn->query(
            "DROP TABLE IF EXISTS virgil_grant_keys, virgil_role_assignments, virgil_roles, virgil_keys, virgil_users;"
        );
        $stmt = $conn->query("DROP EVENT IF EXISTS delete_expired_grant_keys;");
    }

    public function initDb(int $cleanGrantKeysIntervalSeconds): void {
        $conn = $this->getConnection();

        $stmt = $conn->query(
            "CREATE TABLE virgil_users (" .
            "user_id CHAR(36) NOT NULL PRIMARY KEY," .
            "phe_record_version INTEGER NOT NULL," .
            "    INDEX phe_record_version_index(phe_record_version)," .
            "    UNIQUE INDEX user_id_phe_record_version_index(user_id, phe_record_version)," .
            "protobuf VARBINARY(2048) NOT NULL" .
            ");");
        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->query(
            "CREATE TABLE virgil_keys (" .
            "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY," .
            "user_id CHAR(36) NOT NULL," .
            "    FOREIGN KEY (user_id)" .
            "        REFERENCES virgil_users(user_id)" .
            "        ON DELETE CASCADE," .
            "data_id VARCHAR(128) NOT NULL," .
            "    UNIQUE INDEX user_id_data_id_index(user_id, data_id)," .
            "protobuf VARBINARY(32768) NOT NULL /* FIXME Up to 128 recipients */" .
            ");");
        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->query(
            "CREATE TABLE virgil_roles (".
            "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,".
            "role_name VARCHAR(64) NOT NULL,".
            "    INDEX role_name_index(role_name),".
            "protobuf VARBINARY(196) NOT NULL".
            ");");
        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->query(
            "CREATE TABLE virgil_role_assignments (" .
            "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY," .
            "role_name VARCHAR(64) NOT NULL," .
            "    FOREIGN KEY (role_name)" .
            "        REFERENCES virgil_roles(role_name)" .
            "        ON DELETE CASCADE," .
            "user_id CHAR(36) NOT NULL," .
            "    FOREIGN KEY (user_id)" .
            "        REFERENCES virgil_users(user_id)" .
            "        ON DELETE CASCADE," .
            "    INDEX user_id_index(user_id)," .
            "    UNIQUE INDEX user_id_role_name_index(user_id, role_name)," .
            "protobuf VARBINARY(1024) NOT NULL" .
            ");");
        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->query(
            "CREATE TABLE virgil_grant_keys (" .
            "user_id CHAR(36) NOT NULL," .
            "    FOREIGN KEY (user_id)" .
            "        REFERENCES virgil_users(user_id)" .
            "        ON DELETE CASCADE," .
            "key_id BINARY(64) NOT NULL," .
            "expiration_date TIMESTAMP NOT NULL," .
            "    INDEX expiration_date_index(expiration_date)," .
            "protobuf VARBINARY(1024) NOT NULL," .
            "    PRIMARY KEY(user_id, key_id)" .
            ");");
        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->query("SET @@global.event_scheduler = 1;");
        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);

        $stmt = $conn->query(
            "CREATE EVENT delete_expired_grant_keys ON SCHEDULE EVERY $cleanGrantKeysIntervalSeconds SECOND" .
            "    DO" .
            "        DELETE FROM virgil_grant_keys WHERE expiration_date < CURRENT_TIMESTAMP;");
        if (!$stmt)
            throw new MariaDbSqlException($conn->error, $conn->errno);
    }
}