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

namespace Virgil\PureKit\Http;

use PurekitV3Storage\CellKey as ProtoCellKey;
use PurekitV3Storage\GrantKey as ProtoGrantKey;
use PurekitV3Storage\RoleAssignment as ProtoRoleAssignment;
use PurekitV3Storage\RoleAssignments as ProtoRoleAssignments;
use PurekitV3Storage\Roles as ProtoRoles;
use PurekitV3Storage\UserRecord as ProtoUserRecord;
use PurekitV3Storage\UserRecords as ProtoUserRecords;
use Virgil\PureKit\Http\Request\Pure\DeleteCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\DeleteRoleAssignmentsRequest;
use Virgil\PureKit\Http\Request\Pure\DeleteRoleRequest;
use Virgil\PureKit\Http\Request\Pure\DeleteUserRequest;
use Virgil\PureKit\Http\Request\Pure\GetCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetRoleAssignmentRequest;
use Virgil\PureKit\Http\Request\Pure\GetRoleAssignmentsRequest;
use Virgil\PureKit\Http\Request\Pure\InsertRoleAssignmentsRequest;
use Virgil\PureKit\Http\Request\Pure\DeleteGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetRolesRequest;
use Virgil\PureKit\Http\Request\Pure\GetUserRequest;
use Virgil\PureKit\Http\Request\Pure\GetUsersRequest;
use Virgil\PureKit\Http\Request\Pure\InsertCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\InsertGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\InsertRoleRequest;
use Virgil\PureKit\Http\Request\Pure\InsertUserRequest;
use Virgil\PureKit\Http\Request\Pure\UpdateCellKeyRequest;
use Virgil\PureKit\Http\Request\Pure\UpdateUserRequest;
use Virgil\PureKit\Pure\Util\ValidationUtils;

/**
 * Class HttpPureClient
 * @package Virgil\PureKit\Http
 */
class HttpPureClient extends HttpBaseClient
{
    public const SERVICE_ADDRESS = "https://api.virgilsecurity.com/pure/v1/";

    /**
     * HttpPureClient constructor.
     * @param string $appToken
     * @param string $serviceBaseUrl
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function __construct(string $appToken, string $serviceBaseUrl = self::SERVICE_ADDRESS)
    {
        ValidationUtils::checkNullOrEmpty($appToken, "appToken");
        ValidationUtils::checkNullOrEmpty($serviceBaseUrl, "serviceAddress");

        parent::__construct($serviceBaseUrl, $appToken);
    }

    /**
     * @param InsertUserRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function insertUser(InsertUserRequest $request): void
    {
        $this->_send($request, "/insert-user");
    }

    /**
     * @param UpdateUserRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function updateUser(UpdateUserRequest $request): void
    {
        $this->_send($request, "/update-user");
    }

    /**
     * @param GetUserRequest $request
     * @return ProtoUserRecord
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException | \Exception
     */
    public function getUser(GetUserRequest $request): ProtoUserRecord
    {
        $r = $this->_send($request, "/get-user");

        $res = new ProtoUserRecord();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param GetUsersRequest $request
     * @return ProtoUserRecords
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException | \Exception
     */
    public function getUsers(GetUsersRequest $request): ProtoUserRecords
    {
        $r = $this->_send($request, "/get-users");

        $res = new ProtoUserRecords();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param DeleteUserRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function deleteUser(DeleteUserRequest $request): void
    {
        $this->_send($request, "/delete-user");
    }

    /**
     * @param InsertCellKeyRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function insertCellKey(InsertCellKeyRequest $request): void
    {
        $this->_send($request, "/insert-cell-key");
    }

    /**
     * @param UpdateCellKeyRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function updateCellKey(UpdateCellKeyRequest $request): void
    {
        $this->_send($request, "/update-cell-key");
    }

    /**
     * @param GetCellKeyRequest $request
     * @return ProtoCellKey
     * @throws \Exception
     */
    public function getCellKey(GetCellKeyRequest $request): ProtoCellKey
    {
        $r = $this->_send($request, "/get-cell-key");

        $res = new ProtoCellKey();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param DeleteCellKeyRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function deleteCellKey(DeleteCellKeyRequest $request): void
    {
        $this->_send($request, "/delete-cell-key");
    }

    /**
     * @param InsertRoleRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function insertRole(InsertRoleRequest $request): void
    {
        $this->_send($request, "/insert-role");
    }

    /**
     * @param GetRolesRequest $request
     * @return ProtoRoles
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException | \Exception
     */
    public function getRoles(GetRolesRequest $request): ProtoRoles
    {
        $r = $this->_send($request, "/get-roles");

        $res = new ProtoRoles();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param InsertRoleAssignmentsRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function insertRoleAssignments(InsertRoleAssignmentsRequest $request): void
    {
        $this->_send($request, "/role-assignments");
    }

    /**
     * @param GetRoleAssignmentsRequest $request
     * @return ProtoRoleAssignments
     * @throws \Exception
     */
    public function getRoleAssignments(GetRoleAssignmentsRequest $request): ProtoRoleAssignments
    {
        $r = $this->_send($request, "/get-role-assignments");

        $res = new ProtoRoleAssignments();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param GetRoleAssignmentRequest $request
     * @return ProtoRoleAssignment
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException | \Exception
     */
    public function getRoleAssignment(GetRoleAssignmentRequest $request): ProtoRoleAssignment
    {
        $r = $this->_send($request, "/get-role-assignment");

        $res = new ProtoRoleAssignment();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param DeleteRoleAssignmentsRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function deleteRoleAssignments(DeleteRoleAssignmentsRequest $request): void
    {
        $this->_send($request, "/delete-role-assignments");
    }

    /**
     * @param InsertGrantKeyRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function insertGrantKey(InsertGrantKeyRequest $request): void
    {
        $this->_send($request, "/insert-grant-key");
    }

    /**
     * @param GetGrantKeyRequest $request
     * @return ProtoGrantKey
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     * @throws \Exception
     */
    public function getGrantKey(GetGrantKeyRequest $request): ProtoGrantKey
    {
        $r = $this->_send($request, "/get-grant-key");

        $res = new ProtoGrantKey();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param DeleteGrantKeyRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function deleteGrantKey(DeleteGrantKeyRequest $request): void
    {
        $this->_send($request, "/delete-grant-key");
    }

    /**
     * @param DeleteRoleRequest $request
     * @throws \Virgil\PureKit\Pure\Exception\ProtocolException
     */
    public function deleteRole(DeleteRoleRequest $request): void
    {
        $this->_send($request, "/delete-role");
    }
}