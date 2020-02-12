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

use PurekitV3Client\DeleteRoleAssignments as ProtoDeleteRoleAssignments;
use PurekitV3Client\GetRoleAssignment as ProtoGetRoleAssignment;
use PurekitV3Client\GetRoleAssignments as ProtoGetRoleAssignments;
use PurekitV3Client\GrantKeyDescriptor;
use PurekitV3Storage\RoleAssignments as ProtoRoleAssignments;
use PurekitV3Storage\UserRecords;
use Virgil\PureKit\Http\_\AvailableRequest;
use Virgil\PureKit\Http\HttpPureClient;
use Virgil\PureKit\Http\Request\Pure\DeleteCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\DeleteUserRequest;
use Virgil\PureKit\Http\Request\Pure\GetRoleAssignmentsRequest;
use Virgil\PureKit\Http\Request\Pure\InsertCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetRolesRequest;
use Virgil\PureKit\Http\Request\Pure\GetUsersRequest;
use Virgil\PureKit\Http\Request\Pure\GetCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetUserRequest;
use Virgil\PureKit\Http\Request\Pure\InsertGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\InsertRoleAssignmentsRequest;
use Virgil\PureKit\Http\Request\Pure\InsertRoleRequest;
use Virgil\PureKit\Http\Request\Pure\InsertUserRequest;
use Virgil\PureKit\Http\Request\Pure\UpdateCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\UpdateUserRequest;
use Virgil\PureKit\Pure\Collection\RoleAssignmentCollection;
use Virgil\PureKit\Pure\Collection\RoleCollection;
use Virgil\PureKit\Pure\Collection\UserRecordCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureStorageGenericErrorStatus;
use Virgil\PureKit\Pure\Exception\ProtocolException;
use Virgil\PureKit\Pure\Exception\ProtocolHttpException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKEyAlreadyExistsException;
use Virgil\PureKit\Pure\Exception\PureStorageCellKeyNotFoundException;
use Virgil\PureKit\Pure\Exception\PureStorageGenericException;
use Virgil\PureKit\Pure\Exception\ErrorStatus\ServiceErrorCode;
use Virgil\PureKit\Pure\Exception\VirgilCloudStorageException;
use Virgil\PureKit\Pure\Model\CellKey;
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\Role;
use Virgil\PureKit\Pure\Model\RoleAssignment;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\PureModelSerializer;
use Virgil\PureKit\Pure\PureModelSerializerDependent;
use Virgil\PureKit\Pure\Util\ValidateUtil;

class VirgilCloudPureStorage implements PureStorage, PureModelSerializerDependent
{
    private $pureModelSerializer;
    private $client;

    /**
     * VirgilCloudPureStorage constructor.
     * @param HttpPureClient $client
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function __construct(HttpPureClient $client)
    {
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

    public function updateUsers(UserRecordCollection $userRecords, int $previousPheVersion): void
    {
        throw new UnsupportedOperationException("This method always throws UnsupportedOperationException, as in case of using Virgil Cloud storage, rotation happens on the Virgil side");
    }

    public function selectUser(string $userId): UserRecord
    {
        try {
            $request = new GetUserRequest(AvailableRequest::GET_USER(), $userId);
            $protobufRecord = $this->client->getUser($request);
        } catch (ProtocolException $exception) {
            if ($exception->getCode() == ServiceErrorCode::USER_NOT_FOUND()->getCode()) {
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_NOT_FOUND());
            }

            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }

        $userRecord = $this->pureModelSerializer->parseUserRecord($protobufRecord);

        if ($userRecord->getUserId() != $userId)
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());


        return $userRecord;
    }

    public function selectUsers(array $userIds): UserRecordCollection
    {
        $userRecords = new UserRecordCollection();

        if (empty($userIds))
            return $userRecords;

        $idsSet = $userIds;

        try {
            $request = new GetUsersRequest(AvailableRequest::GET_USERS(), $userIds);

            $protoRecords = $this->client->getUsers($request);
        } catch (ProtocolException $exception) {
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }

        if (count($protoRecords->getUserRecords()) != count($userIds)) {
            throw new PureStorageGenericException( PureStorageGenericErrorStatus::DUPLICATE_USER_ID());
        }

        foreach ($protoRecords->getUserRecords() as $protobufRecord) {
            $userRecord = $this->pureModelSerializer->parseUserRecord($protobufRecord);

            if (!in_array($userRecord->getUserId(), $idsSet))
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());

            if (($key = array_search($userRecord->getUserId(), $idsSet)) !== false) {
                unset($idsSet[$key]);
                $idsSet = array_values($idsSet);
            }

            $userRecords->add($userRecord);
        }

        return $userRecords;
    }

    public function selectUsers_(int $pheRecordVersion): UserRecords
    {
        throw new UnsupportedOperationException("This method always throws UnsupportedOperationException, as in case of using Virgil Cloud storage, rotation happens on the Virgil side");
    }

    public function deleteUser(string $userId, bool $cascade): void
    {
        try {
            $request = new DeleteUserRequest(AvailableRequest::DELETE_USER(), $userId, $cascade);
            $this->client->deleteUser($request);
        } catch (ProtocolException $exception) {
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }
    }

    public function selectCellKey(string $userId, string $dataId): CellKey
    {
        try {
            $request = new GetCellKeyRequest(AvailableRequest::GET_CELL_KEY(), $userId, $dataId);
            $protobufRecord = $this->client->getCellKey($request);
        }
        catch (ProtocolException $exception) {
            if ($exception->getCode() == ServiceErrorCode::CELL_KEY_NOT_FOUND()->getCode()) {
                throw new PureStorageCellKeyNotFoundException();
            }
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }

        $cellKey = $this->pureModelSerializer->parseCellKey($protobufRecord);


        if (($userId != $cellKey->getUserId()) || $dataId != $cellKey->getDataId()) {
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::CELL_KEY_ID_MISMATCH());
        }

        return $cellKey;
    }

    public function insertCellKey(CellKey $cellKey): void
    {
        $this->insertKey($cellKey, true);
    }

    public function updateCellKey(CellKey $cellKey): void
    {
        $this->insertKey($cellKey, false);
    }

    public function deleteCellKey(string $userId, string $dataId): void
    {
        try {
            $request = new DeleteCellKeyRequest(AvailableRequest::DELETE_CELL_KEY(), $userId, $dataId);

            $this->client->deleteCellKey($request);
        } catch (ProtocolException $exception) {
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }
    }

    public function insertRole(Role $role): void
    {
        $protobufRecord = $this->pureModelSerializer->serializeRole($role);
        $request = new InsertRoleRequest(AvailableRequest::INSERT_ROLE(), $protobufRecord);

        try {
            $this->client->insertRole($request);
        } catch (ProtocolException $exception) {
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }
    }

    public function selectRoles(array $roleNames): RoleCollection
    {
        $roles = new RoleCollection();
        $namesSet = $roleNames;

        if (empty($roleNames))
            return $roles;

        try {
            $request = new GetRolesRequest(AvailableRequest::GET_ROLES(), $roleNames);
            $protoRecords = $this->client->getRoles($request);
        } catch (ProtocolException $exception) {
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }

        if (count($protoRecords->getRoles()) != count($roleNames)) {
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::DUPLICATE_ROLE_NAME());
        }

        foreach ($protoRecords->getRoles() as $protobufRecord) {
            $role = $this->pureModelSerializer->parseRole($protobufRecord);

            if (!in_array($role->getRoleName(), $namesSet))
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::ROLE_NAME_MISMATCH());

            if (($key = array_search($role->getRoleName(), $namesSet)) !== false) {
                unset($namesSet[$key]);
                $namesSet = array_values($namesSet);
            }
            $roles->add($role);
        }

        return $roles;
    }

    public function insertRoleAssignments(RoleAssignmentCollection $roleAssignments): void
    {
        $protobufBuilder = new ProtoRoleAssignments();
        $ra = [];

        if (!empty($roleAssignments->getAsArray())) {
            foreach ($roleAssignments->getAsArray() as $roleAssignment) {
                $ra[] = $this->pureModelSerializer->serializeRoleAssignment($roleAssignment);
            }
        }

        $protobufBuilder->setRoleAssignments($ra);
        $protobufRecord = $protobufBuilder;

        $request = new InsertRoleAssignmentsRequest(AvailableRequest::INSERT_ROLE_ASSIGNMENTS(), $protobufRecord);

        try {
            $this->client->insertRoleAssignments($request);
        } catch (ProtocolException $exception) {
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }
    }

    public function selectRoleAssignments(string $userId): RoleAssignmentCollection
    {
        $roleAssignments = new RoleAssignmentCollection();
        $request = new GetRoleAssignmentsRequest(AvailableRequest::GET_ROLE_ASSIGNMENTS(), $userId);
        $protoRecords = null;
        try {
            $protoRecords = $this->client->getRoleAssignments($request);
        } catch (ProtocolException $exception) {
            throw new VirgilCloudStorageException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new VirgilCloudStorageException($exception);
        }

        foreach ($protoRecords->getRoleAssignments() as $protobufRecord) {
            $roleAssignment = $this->pureModelSerializer->parseRoleAssignment($protobufRecord);

            if ($roleAssignment->getUserId() != $userId)
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());

            $roleAssignments->add($roleAssignment);
        }

        return $roleAssignments;
    }

    public function selectRoleAssignment(string $roleName, string $userId): RoleAssignment
    {
        $request = (new ProtoGetRoleAssignment)
            ->setUserId($userId)
            ->setRoleName($roleName);

        $protobufRecord = null;

        try {
            $protobufRecord = $this->client->getRoleAssignment($request);
        } catch (ProtocolException $e) {
            throw new VirgilCloudStorageException($e);
        } catch (ProtocolHttpException $e) {
            throw new VirgilCloudStorageException($e);
        }

        return $this->pureModelSerializer->parseRoleAssignment($protobufRecord);
    }

    public function deleteRoleAssignments(string $roleName, array $userIds): void
    {
        var_dump(993939393939, $userIds);
        die;

        if (empty($userIds))
            return;

        var_dump(11111);
        die;

        $request = (new ProtoDeleteRoleAssignments)
            ->setUserIds($userIds)
            ->setRoleName($roleName);

        try {
            $this->client->deleteRoleAssignments($request);
        } catch (ProtocolException $e) {
            throw new VirgilCloudStorageException($e);
        } catch (ProtocolHttpException $e) {
            throw new VirgilCloudStorageException($e);
        }
    }

    public function insertGrantKey(GrantKey $grantKey): void
    {
        $protobufRecord = $this->pureModelSerializer->serializeGrantKey($grantKey);

        $request = new InsertGrantKeyRequest(AvailableRequest::INSERT_GRANT_KEY(), $protobufRecord);

        try {
            $this->client->insertGrantKey($request);
        } catch (ProtocolException $e) {
            var_dump(666);
            die;
            throw new VirgilCloudStorageException($e);
        } catch (ProtocolHttpException $e) {
            var_dump($e->getMessage(), $e->getCode());
            die;
            throw new VirgilCloudStorageException($e);
        } catch (\Exception $e) {
            var_dump(777, $e->getMessage(), $e->getCode());
            die;
        }
    }

    public function selectGrantKey(string $userId, string $keyId): GrantKey
    {
        $request = new GetGrantKeyRequest(AvailableRequest::GET_GRANT_KEY(), $userId, $keyId);

        try {
            $protobufRecord = $this->client->getGrantKey($request);
        }
        catch (ProtocolException $e) {
            if ($e->getErrorCode() == ServiceErrorCode::GRANT_KEY_NOT_FOUND()->getCode())
                throw new PureStorageGenericException(PureStorageGenericErrorStatus::GRANT_KEY_NOT_FOUND());

            throw new VirgilCloudStorageException($e);
        } catch (ProtocolHttpException $e) {
            throw new VirgilCloudStorageException($e);
        }

        $grantKey = $this->pureModelSerializer->parseGrantKey($protobufRecord);

        if ($grantKey->getUserId() != $userId) {
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::USER_ID_MISMATCH());
        }
        if ($grantKey->getKeyId() != $keyId) {
            throw new PureStorageGenericException(PureStorageGenericErrorStatus::KEY_ID_MISMATCH());
        }

        return $grantKey;
    }

    public function deleteGrantKey(string $userId, string $keyId): void
    {
        $request = (new GrantKeyDescriptor)
            ->setUserId($userId)
            ->setKeyId($keyId);

        try {
            $this->client->deleteGrantKey($request);
        } catch (ProtocolException $e) {
            throw new VirgilCloudStorageException($e);
        } catch (ProtocolHttpException $e) {
            throw new VirgilCloudStorageException($e);
        }
    }

    /**
     * @param UserRecord $userRecord
     * @param bool $isInsert
     * @throws ProtocolException
     * @throws PureStorageGenericException
     */
    private function _sendUser(UserRecord $userRecord, bool $isInsert): void
    {
        $protobufRecord = $this->getPureModelSerializer()->serializeUserRecord($userRecord);

        if ($isInsert) {

            $request = new InsertUserRequest(AvailableRequest::INSERT_USER(), $protobufRecord);
            $this->client->insertUser($request);
        } else {

            $request = new UpdateUserRequest(AvailableRequest::UPDATE_USER(),
                $protobufRecord, $userRecord->getUserId());
            $this->client->updateUser($request);
        }
    }

    private function insertKey(CellKey $cellKey, bool $isInsert): void
    {
        $protobufRecord = $this->pureModelSerializer->serializeCellKey($cellKey);

        try {
            if ($isInsert) {
                try {
                    $request = new InsertCellKeyRequest(AvailableRequest::INSERT_CELL_KEY(), $protobufRecord);
                    $this->client->insertCellKey($request);
                } catch (ProtocolException $e) {
                    if ($e->getErrorCode() == ServiceErrorCode::CELL_KEY_ALREADY_EXISTS()->getCode()) {
                        throw new PureStorageCellKeyAlreadyExistsException();
                    }
                    throw $e;
                }
            } else {
                $request = new UpdateCellKeyRequest(AvailableRequest::UPDATE_CELL_KEY(), $cellKey->getUserId(),
                    $cellKey->getDataId(), $protobufRecord);
                $this->client->updateCellKey($request);
            }
        } catch (ProtocolException $e) {
            throw new VirgilCloudStorageException($e);
        } catch (ProtocolHttpException $e) {
            throw new VirgilCloudStorageException($e);
        }
    }
}