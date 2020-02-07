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

namespace Virgil\PureKit\Http;

use PurekitV3Storage\CellKey as ProtoCellKey;
use PurekitV3Storage\GrantKey as ProtoGrantKey;
use PurekitV3Storage\RoleAssignment as ProtoRoleAssignment;
use PurekitV3Storage\RoleAssignments as ProtoRoleAssignments;
use PurekitV3Storage\Roles as ProtoRoles;
use PurekitV3Storage\UserRecord as ProtoUserRecord;
use PurekitV3Storage\UserRecords as ProtoUserRecords;
use Virgil\PureKit\Http\Request\DeleteCellKeyRequest;
use Virgil\PureKit\Http\Request\DeleteRoleAssignmentRequest;
use Virgil\PureKit\Http\Request\DeleteUserRequest;
use Virgil\PureKit\Http\Request\Pure\GetCellKeyRequest;
use Virgil\PureKit\Http\Request\GetRoleAssignmentRequest;
use Virgil\PureKit\Http\Request\GetRoleAssignmentsRequest;
use Virgil\PureKit\Http\Request\GetRolesRequest;
use Virgil\PureKit\Http\Request\GetUsersRequest;
use Virgil\PureKit\Http\Request\InsertCellKeyRequest;
use Virgil\PureKit\Http\Request\InsertRoleAssignmentsRequest;
use Virgil\PureKit\Http\Request\Pure\DeleteGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\GetUserRequest;
use Virgil\PureKit\Http\Request\Pure\InsertGrantKeyRequest;
use Virgil\PureKit\Http\Request\Pure\InsertRoleRequest;
use Virgil\PureKit\Http\Request\Pure\InsertUserRequest;
use Virgil\PureKit\Http\Request\Pure\UpdateUserRequest;
use Virgil\PureKit\Pure\Util\ValidateUtil;

class HttpPureClient extends HttpBaseClient
{
    public const SERVICE_ADDRESS = "https://api.virgilsecurity.com/pure/v1/";

    /**
     * HttpPureClient constructor.
     * @param string $appToken
     * @param string $serviceBaseUrl
     * @param bool $debug
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function __construct(string $appToken, string $serviceBaseUrl = self::SERVICE_ADDRESS, bool $debug = false)
    {
        ValidateUtil::checkNullOrEmpty($appToken, "appToken");
        ValidateUtil::checkNullOrEmpty($serviceBaseUrl, "serviceAddress");

        parent::__construct($serviceBaseUrl, $appToken, $debug);
    }

    public function insertUser(InsertUserRequest $request): void
    {
        $this->_send($request, 201);
    }

    public function updateUser(UpdateUserRequest $request): void
    {
        $this->_send($request);
    }

    public function getUser(GetUserRequest $request): ProtoUserRecord
    {
        $r = $this->_send($request);

        $res = new ProtoUserRecord();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param GetUsersRequest $request
     * @return ProtoUserRecords
     * @throws \Exception
     */
    public function getUsers(GetUsersRequest $request): ProtoUserRecords
    {
        $r = $this->_send($request);

        $res = new ProtoUserRecords();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    public function deleteUser(DeleteUserRequest $request): void
    {
        $this->_send($request);
    }

    public function insertCellKey(InsertCellKeyRequest $request): void
    {
        $this->_send($request);
    }

    public function updateCellKey(UpdateUserRequest $request): void
    {
        $this->_send($request);
    }

    /**
     * @param GetCellKeyRequest $request
     * @return ProtoCellKey
     * @throws \Exception
     */
    public function getCellKey(GetCellKeyRequest $request): ProtoCellKey
    {
        $r = $this->_send($request);

        $res = new ProtoCellKey();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    public function deleteCellKey(DeleteCellKeyRequest $request): void
    {
        $this->_send($request);
    }

    public function insertRole(InsertRoleRequest $request): void
    {
        $this->_send($request);
    }

    /**
     * @param GetRolesRequest $request
     * @return ProtoRoles
     * @throws \Exception
     */
    public function getRoles(GetRolesRequest $request): ProtoRoles
    {
        $r = $this->_send($request);

        $res = new ProtoRoles();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    public function insertRoleAssignments(InsertRoleAssignmentsRequest $request): void
    {
        $this->_send($request);
    }

    /**
     * @param GetRoleAssignmentsRequest $request
     * @return ProtoRoleAssignments
     * @throws \Exception
     */
    public function getRoleAssignments(GetRoleAssignmentsRequest $request): ProtoRoleAssignments
    {
        $r = $this->_send($request);

        $res = new ProtoRoleAssignments();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param GetRoleAssignmentRequest $request
     * @return ProtoRoleAssignment
     * @throws \Exception
     */
    public function getRoleAssignment(GetRoleAssignmentRequest $request): ProtoRoleAssignment
    {
        $r = $this->_send($request);

        $res = new ProtoRoleAssignment();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    public function deleteRoleAssignment(DeleteRoleAssignmentRequest $request): void
    {
        $this->_send($request);
    }

    public function insertGrantKey(InsertGrantKeyRequest $request): void
    {
        $this->_send($request, 201);
    }

    public function getGrantKey(GetGrantKeyRequest $request): ProtoGrantKey
    {
        $r = $this->_send($request, 204);

        $res = new ProtoGrantKey();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    public function deleteGrantKey(DeleteGrantKeyRequest $request): void
    {
        $this->_send($request);
    }
}