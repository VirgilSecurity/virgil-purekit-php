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

use Purekit\EnrollmentRequest as ProtoEnrollmentRequest;
use Purekit\EnrollmentResponse as ProtoEnrollmentResponse;
use Purekit\VerifyPasswordRequest as ProtoVerifyPasswordRequest;
use Purekit\VerifyPasswordResponse as ProtoVerifyPasswordResponse;
use Virgil\PureKit\Client\AvailableRequests;
use Virgil\PureKit\Http\BaseHttpClient;
use Virgil\PureKit\Http\Request\EnrollRequest;
use Virgil\PureKit\Http\Request\TttRequest;
use Virgil\PureKit\Http\Request\VerifyPasswordRequest;
use Virgil\PureKit\Pure\Util\ValidateUtil;

class HttpPheClient extends BaseHttpClient
{
    protected $appToken;
    private $client;

    public const SERVICE_ADDRESS = "https://api.virgilsecurity.com/phe/v1";

    public function __construct(string $appToken, string $sa = self::SERVICE_ADDRESS)
    {
        ValidateUtil::checkNullOrEmpty($appToken, "appToken");
        ValidateUtil::checkNullOrEmpty(self::SERVICE_ADDRESS, "serviceAddress");

        parent::__construct(self::SERVICE_ADDRESS, $appToken);
    }

    public function test(TttRequest $request)
    {
        return $this->send($request);
    }

    public function enrollAccount(EnrollRequest $request): ProtoEnrollmentResponse
    {
        $response = $this->send($request);
        $response->getBody();
        return $response->getBody();
    }

    public function verifyPassword(VerifyPasswordRequest $request): ProtoVerifyPasswordResponse
    {
        return $this->client->send($request, AvailableRequests::VERIFY_PASSWORD(), $this->appToken);
    }
}