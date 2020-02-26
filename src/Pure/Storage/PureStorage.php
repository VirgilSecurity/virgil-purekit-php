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

use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;

/**
 * Interface PureStorage
 * @package Virgil\PureKit\Pure\Storage\_
 */
interface PureStorage
{
    /**
     * @param UserRecord $userRecord
     */
    public function insertUser(UserRecord $userRecord): void;

    /**
     * @param UserRecord $userRecord
     */
    public function updateUser(UserRecord $userRecord): void;

    /**
     * @param UserRecordCollection $userRecords
     * @param int $previousPheVersion
     */
    public function updateUsers(UserRecordCollection $userRecords, int $previousPheVersion): void;

    /**
     * @param string $userId
     * @return UserRecord
     */
    public function selectUser(string $userId): UserRecord;

    /**
     * @param array $userIds
     * @return UserRecordCollection
     */
    public function selectUsers(array $userIds): UserRecordCollection;

    /**
     * @param int $pheRecordVersion
     * @return UserRecordCollection
     */
    public function selectUsers_(int $pheRecordVersion): UserRecordCollection;

    /**
     * @param string $userId
     * @param bool $cascade
     */
    public function deleteUser(string $userId, bool $cascade): void;

    /**
     * @param string $userId
     * @param string $dataId
     * @return CellKey
     */
    public function selectCellKey(string $userId, string $dataId): CellKey;

    /**
     * @param CellKey $cellKey
     */
    public function insertCellKey(CellKey $cellKey): void;

    /**
     * @param CellKey $cellKey
     */
    public function updateCellKey(CellKey $cellKey): void;

    /**
     * @param string $userId
     * @param string $dataId
     */
    public function deleteCellKey(string $userId, string $dataId): void;

    /**
     * @param Role $role
     */
    public function insertRole(Role $role): void;

    /**
     * @param array $roleNames
     * @return RoleCollection
     */
    public function selectRoles(array $roleNames): RoleCollection;

    /**
     * @param RoleAssignmentCollection $roleAssignments
     */
    public function insertRoleAssignments(RoleAssignmentCollection $roleAssignments): void;

    /**
     * @param string $userId
     * @return RoleAssignmentCollection
     */
    public function selectRoleAssignments(string $userId): RoleAssignmentCollection;

    /**
     * @param string $roleName
     * @param string $userId
     * @return RoleAssignment
     */
    public function selectRoleAssignment(string $roleName, string $userId): RoleAssignment;

    /**
     * @param string $roleName
     * @param array $userIds
     */
    public function deleteRoleAssignments(string $roleName, array $userIds): void;

    /**
     * @param GrantKey $grantKey
     */
    public function insertGrantKey(GrantKey $grantKey): void;

    /**
     * @param string $userId
     * @param string $keyId
     * @return GrantKey
     */
    public function selectGrantKey(string $userId, string $keyId): GrantKey;

    /**
     * @param string $userId
     * @param string $keyId
     */
    public function deleteGrantKey(string $userId, string $keyId): void;
}