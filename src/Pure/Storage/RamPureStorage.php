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

use Ev;
use EvTimer;
use Virgil\PureKit\Pure\Collection\GrantKeyCollection;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureStorageGenericErrorStatus;
use Virgil\PureKit\Pure\Exception\PureStorageCellKeyNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageGenericException;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;

/**
 * Class RamPureStorage
 * @package Virgil\PureKit\Pure\Storage
 */
class RamPureStorage implements PureStorage
{
    /**
     * @var array
     */
    private $users;
    /**
     * @var array
     */
    private $keys;
    /**
     * @var array
     */
    private $roles;
    /**
     * @var array
     */
    private $roleAssignments;
    /**
     * @var array
     */
    private $grantKeys;

    public const GRANT_KEYS_CLEAN_INTERVAL = 20000;

    /**
     * RamPureStorage constructor.
     */
    public function __construct()
    {
        $this->users = [];
        $this->keys = [];
        $this->roles = [];
        $this->roleAssignments = [];
        $this->grantKeys = [];

        new EvTimer(self::GRANT_KEYS_CLEAN_INTERVAL, 0, function () {
            $this->cleanGrantKeys();
        });

        Ev::run();
    }

    /**
     *
     */
    private function cleanGrantKeys() {
        $currentDate = new \DateTime();

        foreach ($this->grantKeys as $grantKey) {
            if ($grantKey->getValue()->getExpirationDate() < $currentDate->getTimestamp()) {
                unset($grantKey);
            }
        }
    }

    /**
     * @param UserRecord $userRecord
     */
    public function insertUser(UserRecord $userRecord): void
    {
        $this->users = [$userRecord->getUserId() => $userRecord];
    }

    /**
     * @param UserRecord $userRecord
     */
    public function updateUser(UserRecord $userRecord): void
    {
        $this->users = [$userRecord->getUserId() => $userRecord];
    }

    /**
     * @param UserRecordCollection $userRecords
     * @param int $previousPheVersion
     */
    public function updateUsers(UserRecordCollection $userRecords, int $previousPheVersion): void
    {
        foreach ($userRecords->getAsArray() as $userRecord) {
            $this->updateUser($userRecord);
        }
    }

    /**
     * @param string $userId
     * @return UserRecord
     * @throws PureStorageGenericException
     */
    public function selectUser(string $userId): UserRecord
    {
        $userRecord = $this->users[$userId];

        if (is_null($userRecord))
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_NOT_FOUND());

        return $userRecord;
    }

    /**
     * @param array $userIds
     * @return UserRecordCollection
     * @throws PureStorageGenericException
     */
    public function selectUsers(array $userIds): UserRecordCollection
    {
        $userRecords = new UserRecordCollection();

        foreach ($userIds as $userId) {
            $userRecord = $this->users[$userId];

            if (is_null($userRecord))
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_NOT_FOUND());

            $userRecords->add($userRecord);
        }

        return $userRecords;
    }

    /**
     * @param int $pheRecordVersion
     * @return UserRecordCollection
     */
    public function selectUsers_(int $pheRecordVersion): UserRecordCollection
    {
        $res = new UserRecordCollection();

        $records = array_values($this->users);

        $i = 0;

        foreach ($records as $record) {
            if($record->getRecordVersion() == $pheRecordVersion) {
                $res->add($record);
                $i++;

                if (10 == $i)
                    break;
            }
        }

        return $res;
    }

    /**
     * @param string $userId
     * @param bool $cascade
     * @throws PureStorageGenericException
     */
    public function deleteUser(string $userId, bool $cascade): void
    {
        if(!array_key_exists($userId, $this->users))
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_NOT_FOUND());

        unset($this->users[$userId]);

        if ($cascade)
            unset($this->keys[$userId]);
    }

    /**
     * @param string $userId
     * @param string $dataId
     * @return CellKey
     * @throws PureStorageCellKeyNotFoundException
     */
    public function selectCellKey(string $userId, string $dataId): CellKey
    {
        $map = $this->keys['userId'];

        if (is_null($map))
            throw new PureStorageCellKeyNotFoundException();

        $cellKey = $map[$dataId];

        if (is_null($cellKey))
            throw new PureStorageCellKeyNotFoundException();

        return $cellKey;
    }

    /**
     * @param CellKey $cellKey
     */
    public function insertCellKey(CellKey $cellKey): void
    {
        var_dump("R1");
        die;
    }

    /**
     * @param CellKey $cellKey
     * @throws PureStorageCellKeyNotFoundException
     */
    public function updateCellKey(CellKey $cellKey): void
    {
        $map = $this->keys[$cellKey->getUserId()];

        if (!in_array($cellKey->getDataId(), $map))
            throw new PureStorageCellKeyNotFoundException();

        $map[$cellKey->getDataId()] = $cellKey;
    }

    /**
     * @param string $userId
     * @param string $dataId
     * @throws PureStorageCellKeyNotFoundException
     */
    public function deleteCellKey(string $userId, string $dataId): void
    {
        $keys = $this->keys[$userId];

        if (is_null($keys))
            throw new PureStorageCellKeyNotFoundException();

        if(!array_key_exists($dataId, $keys))
            throw new PureStorageCellKeyNotFoundException();

        unset($keys[$dataId]);
    }

    /**
     * @param Role $role
     */
    public function insertRole(Role $role): void
    {
        $this->roles[$role->getRoleName()] = $role;
    }

    /**
     * @param array $roleNames
     * @return RoleCollection
     */
    public function selectRoles(array $roleNames): RoleCollection
    {
        // TODO: Implement selectRoles() method.
    }

    /**
     * @param string $roleName
     * @param bool $cascade
     */
    public function deleteRole(string $roleName, bool $cascade): void
    {
        unset($this->roles[$roleName]);

        if ($cascade)
            unset($this->roleAssignments[$roleName]);
    }

    /**
     * @param RoleAssignmentCollection $roleAssignments
     */
    public function insertRoleAssignments(RoleAssignmentCollection $roleAssignments): void
    {
        foreach ($roleAssignments->getAsArray() as $roleAssignment) {
            $map = $this->roleAssignments[$roleAssignment->getRoleName()];

            $map[$roleAssignment->getUserId()] = $roleAssignment;

            $this->roleAssignments[$roleAssignment->getRoleName()] = $map;
        }
    }

    /**
     * @param string $roleName
     * @param string $userId
     * @return RoleAssignment
     */
    public function selectRoleAssignment(string $roleName, string $userId): RoleAssignment
    {
        var_dump("R2");
        die;
    }

    /**
     * @param string $userId
     * @return RoleAssignmentCollection
     */
    public function selectRoleAssignments(string $userId): RoleAssignmentCollection
    {
        var_dump("R3");
        die;
    }

    /**
     * @param string $roleName
     * @param array $userIds
     */
    public function deleteRoleAssignments(string $roleName, array $userIds): void
    {
        var_dump("R4");
        die;
    }

    /**
     * @param GrantKey $grantKey
     */
    public function insertGrantKey(GrantKey $grantKey): void
    {
        var_dump("R5");
        die;
    }

    /**
     * @param string $userId
     * @param string $keyId
     * @return GrantKey
     */
    public function selectGrantKey(string $userId, string $keyId): GrantKey
    {
        var_dump("R6");
        die;
    }

    /**
     * @param int $recordVersion
     * @return GrantKeyCollection
     */
    public function selectGrantKeys(int $recordVersion): GrantKeyCollection
    {
        var_dump("R7");
        die;
    }

    /**
     * @param GrantKeyCollection $grantKeys
     */
    public function updateGrantKeys(GrantKeyCollection $grantKeys): void
    {
        var_dump("R8");
        die;
    }

    /**
     * @param string $userId
     * @param string $keyId
     */
    public function deleteGrantKey(string $userId, string $keyId): void
    {
        var_dump("R9");
        die;
    }
}