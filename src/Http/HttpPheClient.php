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

use Purekit\EnrollmentResponse as ProtoEnrollmentResponse;
use Purekit\VerifyPasswordResponse as ProtoVerifyPasswordResponse;
use Virgil\PureKit\Http\Request\Phe\EnrollRequest;
use Virgil\PureKit\Http\Request\Phe\VerifyPasswordRequest;
use Virgil\PureKit\Pure\Util\ValidationUtils;

/**
 * Class HttpPheClient
 * @package Virgil\PureKit\Http
 */
class HttpPheClient extends HttpBaseClient
{
    public const SERVICE_ADDRESS = "https://api.virgilsecurity.com/phe/v1/";

    /**
     * HttpPheClient constructor.
     * @param string $appToken
     * @param string $serviceBaseUrl
     * @param bool $debug
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function __construct(string $appToken, string $serviceBaseUrl = self::SERVICE_ADDRESS, bool $debug = false)
    {
        ValidationUtils::checkNullOrEmpty($appToken, "appToken");
        ValidationUtils::checkNullOrEmpty($serviceBaseUrl, "serviceAddress");

        parent::__construct($serviceBaseUrl, $appToken, $debug);
    }

    /**
     * @param EnrollRequest $request
     * @return ProtoEnrollmentResponse
     * @throws \Exception
     */
    public function enrollAccount(EnrollRequest $request): ProtoEnrollmentResponse
    {
        ValidationUtils::checkNull($request, "request");

        $r = $this->_send($request, "/enroll");

        $res = new ProtoEnrollmentResponse();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }

    /**
     * @param VerifyPasswordRequest $request
     * @return ProtoVerifyPasswordResponse
     * @throws \Exception
     */
    public function verifyPassword(VerifyPasswordRequest $request): ProtoVerifyPasswordResponse
    {
        ValidationUtils::checkNull($request, "request");

        $r = $this->_send($request, "/verify-password");

        $res = new ProtoVerifyPasswordResponse();
        $res->mergeFromString($r->getBody()->getContents());

        return $res;
    }
}