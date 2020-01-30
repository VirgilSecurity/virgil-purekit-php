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


use Virgil\PureKit\Client\AvailableRequests;
use Virgil\PureKit\Credentials\UpdateToken;
use Virgil\PureKit\Http\HttpClient;
use Virgil\PureKit\Http\Request\GetUsersRequest;
use Virgil\PureKit\Http\Request\InsertUserRequest;
use Virgil\PureKit\Http\Request\UpdateUserRequest;
use Virgil\PureKit\Pure\Util\ValidateUtil;
use PurekitV3Storage\UserRecords as ProtoUserRecords;

class HttpPureClient
{
    private $appToken;
    private $client;

    public const SERVICE_ADDRESS = "https://api.virgilsecurity.com/pure/v1/";
    public const KEY_CASCADE = "cascade";

    public function __construct(string $appToken, string $serviceAddress)
    {
        ValidateUtil::checkNullOrEmpty($appToken, "appToken");
        ValidateUtil::checkNullOrEmpty($serviceAddress, "serviceAddress");

        $this->appToken = $appToken;
        $this->client = new HttpClient($serviceAddress);
    }

    public function insertUser(InsertUserRequest $request): void
    {
        $this->client->send($request, AvailableRequests::INSERT_USER(), $this->appToken);
    }

    public function updateUser(UpdateUserRequest $request): void
    {
        $this->client->send($request, AvailableRequests::UPDATE_USER(), $this->appToken);
    }

    // TODO!
    public function getUsers(GetUsersRequest $request): ProtoUserRecords
    {
        return $this->client->send($request, AvailableRequests::GET_USERS(), $this->appToken);
    }
}