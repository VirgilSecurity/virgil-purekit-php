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

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ClientException;
use Psr\Http\Message\ResponseInterface;
use Purekit\HttpError as ProtoHttpError;
use Virgil\PureKit\Http\Request\BaseRequest;
use Virgil\PureKit\Http\Request\Pure\GetCellKeyRequest;
use Virgil\PureKit\Pure\Exception\ProtocolException;
use Virgil\PureKit\Pure\Exception\ProtocolHttpException;

/**
 * Class HttpClient
 * @package Virgil\PureKit\Http
 */
class HttpBaseClient
{
    /**
     * @var GuzzleClient
     */
    private $httpClient;
    /**
     * @var string
     */
    private $serviceBaseUrl;
    /**
     * @var bool
     */
    private $debug;
    /**
     * @var string
     */
    private $appToken;

    /**
     * BaseHttpClient constructor.
     * @param string $serviceBaseUrl
     * @param string $appToken
     * @param bool $debug
     */
    public function __construct(string $serviceBaseUrl, string $appToken, bool $debug = false)
    {
        $this->serviceBaseUrl = $serviceBaseUrl;
        $this->appToken = $appToken;
        $this->debug = $debug;

        $this->httpClient = new GuzzleClient(['base_uri' => $this->_getServiceBaseUrl()]);
    }

    protected function _send(BaseRequest $request): ResponseInterface
    {
        try {
            return $this->httpClient->request($request->getMethod(), "." . $request->getEndpoint(),
                [
                    "headers" => $request->getOptionsHeader($this->appToken),
                    "body" => $request->getOptionsBody(),
                    'debug' => $this->debug
                ]);
        } catch (ClientException $exception) {

            $protoBody =  $exception->getResponse()->getBody()->getContents();

            $protoHttpErr = new ProtoHttpError();
            $protoHttpErr->mergeFromString($protoBody);

            $code = $protoHttpErr->getCode();
            $msg = $protoHttpErr->getMessage();

            throw new ProtocolException($msg, $code);
        }
    }

    /**
     * @return string
     */
    private function _getServiceBaseUrl(): string
    {
        return $this->serviceBaseUrl;
    }
}