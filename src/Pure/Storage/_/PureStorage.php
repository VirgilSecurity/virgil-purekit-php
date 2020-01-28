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

namespace Virgil\PureKit\Pure\Storage\_;

use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;

interface PureStorage
{
    public function insertUser(UserRecord $userRecord): void;

    public function updateUser(UserRecord $userRecord): void;

    public function updateUsers(UserRecordCollection $userRecords, int $previousPheVersion): void;

    public function selectUser(string $userId): UserRecord;

    public function selectUsers(string ...$userIds): UserRecordCollection;

    // TODO!
    // public function selectUsers(int $pheRecordVersion): UserRecords;

    public function deleteUser(string $userId, bool $cascade): void;

    public function selectCellKey(string $userId, string $dataId): CellKey;

    public function insertCellKey(CellKey $cellKey): void;

    public function updateCellKey(CellKey $cellKey): void;

    public function deleteCellKey(string $userId, string $dataId): void;

    public function insertRole(Role $role): void;

    public function selectRoles(string ...$roleNames): RoleCollection;

    public function insertRoleAssignments(RoleAssignmentCollection $roleAssignments): void;

    public function selectRoleAssignments(string $userId): RoleAssignmentCollection;

    public function selectRoleAssignment(string $roleName, string $userId): RoleAssignment;

    public function deleteRoleAssignments(string $roleName, string ...$userIds): void;
}