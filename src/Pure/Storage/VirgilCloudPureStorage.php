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


use Virgil\Crypto\VirgilCrypto;
use Virgil\PureKit\Http\_\AvailableHttpMethod;
use Virgil\PureKit\Http\_\AvailableRequest;
use Virgil\PureKit\Http\HttpPureClient;
use Virgil\PureKit\Http\Request\InsertUserRequest;
use Virgil\PureKit\Http\Request\UpdateUserRequest;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\PureModelSerializer;
use Virgil\PureKit\Pure\PureModelSerializerDependent;
use Virgil\PureKit\Pure\Storage\_\PureStorage;
use Virgil\PureKit\Pure\Util\ValidateUtil;

class VirgilCloudPureStorage implements PureStorage, PureModelSerializerDependent
{
    private $pureModelSerializer;
    private $client;

    /**
     * VirgilCloudPureStorage constructor.
     * @param VirgilCrypto $crypto
     * @param HttpPureClient $client
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function __construct(VirgilCrypto $crypto, HttpPureClient $client)
    {
        ValidateUtil::checkNull($crypto, "crypto");
        ValidateUtil::checkNull($client, "client");

        $this->client = $client;
    }

    public function getPureModelSerializer(): PureModelSerializer
    {
        return $this->pureModelSerializer;
    }

    public function setPureModelSerializer(PureModelSerializer $pureModelSerializer): void
    {
        $this->pureModelSerializer = $pureModelSerializer;
    }

    public function insertUser(UserRecord $userRecord): void
    {
        $this->_sendUser($userRecord, true);
    }

    public function updateUser(UserRecord $userRecord): void
    {
        $this->_sendUser($userRecord, false);
    }

    public function selectCellKey(string $userId, string $dataId): CellKey
    {
        // TODO: Implement selectCellKey() method.
    }

    public function selectRoleAssignment(string $roleName, string $userId): RoleAssignment
    {
        // TODO: Implement selectRoleAssignment() method.
    }

    public function selectRoleAssignments(string $userId): RoleAssignmentCollection
    {
        // TODO: Implement selectRoleAssignments() method.
    }

    public function selectRoles(string ...$roleNames): RoleCollection
    {
        // TODO: Implement selectRoles() method.
    }

    public function selectUser(string $userId): UserRecord
    {
        // TODO: Implement selectUser() method.
    }

    public function selectUsers(string ...$userIds): UserRecordCollection
    {
        // TODO: Implement selectUsers() method.
    }

    public function deleteRoleAssignments(string $roleName, string ...$userIds): void
    {
        // TODO: Implement deleteRoleAssignments() method.
    }

    public function deleteCellKey(string $userId, string $dataId): void
    {
        // TODO: Implement deleteCellKey() method.
    }

    public function deleteUser(string $userId, bool $cascade): void
    {
        // TODO: Implement deleteUser() method.
    }

    public function insertCellKey(CellKey $cellKey): void
    {
        // TODO: Implement insertCellKey() method.
    }

    public function insertRole(Role $role): void
    {
        // TODO: Implement insertRole() method.
    }

    public function insertRoleAssignments(RoleAssignmentCollection $roleAssignments): void
    {
        // TODO: Implement insertRoleAssignments() method.
    }

    public function updateCellKey(CellKey $cellKey): void
    {
        // TODO: Implement updateCellKey() method.
    }

    public function updateUsers(UserRecordCollection $userRecords, int $previousPheVersion): void
    {
        // TODO: Implement updateUsers() method.
    }

    private function _sendUser(UserRecord $userRecord, bool $isInsert): void
    {
        $protobufRecord = $this->getPureModelSerializer()->serializeUserRecord($userRecord);

        if ($isInsert) {

            $request = new InsertUserRequest(AvailableRequest::INSERT_USER(), AvailableHttpMethod::POST(), $protobufRecord);

            $this->client->insertUser($request);
        } else {

            $request = new UpdateUserRequest(AvailableRequest::UPDATE_USER(), AvailableHttpMethod::PUT(),
                $protobufRecord, $userRecord->getUserId());
            $this->client->updateUser($request);
        }
    }
}