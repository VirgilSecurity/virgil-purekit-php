<?php
/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

namespace passw0rd\Http;

use passw0rd\Common\AvailableEndpoints;
use passw0rd\Common\RequestNamespace;
use GuzzleHttp\Client as GuzzleClient;
use passw0rd\Http\Request\BaseHttpRequest;
use passw0rd\Protocol\ProtocolContext;

class HttpClient implements AvailableEndpoints, RequestNamespace
{
    const BASE_URI = 'https://api.passw0rd.io/phe/v1/';

    private $context;
    private $client;

    /**
     * HttpClient constructor.
     * @param ProtocolContext $context
     */
    public function __construct(ProtocolContext $context)
    {
        $this->context = $context;

        $this->client = new GuzzleClient([
            'base_uri' => self::BASE_URI,
        ]);
    }

    public function endpoint(string $request): BaseHttpRequest
    {
        $className = RequestNamespace::NAMESPACE.$request."Request";
        return new $className();
    }

//    public function enroll(): EnrollResponse
//    {
//        $response = $this->client->request('POST', $this->context->getAppId() . "/enroll",
//            RequestParamsHelper::format(["Authorization" => $this->context->getAccessToken()]));
//        return new EnrollResponse($response);
//    }
//
//    public function verifyPassword(): VerifyPasswordResponse
//    {
//        $response = $this->client->request('POST', $this->context->getAppId() . "/verify-password",
//            RequestParamsHelper::format());
//        return new VerifyPasswordResponse($response);
//    }
}