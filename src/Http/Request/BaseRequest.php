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

namespace Virgil\PureKit\Http\Request;

use Virgil\PureKit\Http\_\AvailableRequest;
use Virgil\PureKit\Http\_\HttpVirgilAgent;

/**
 * Class BaseRequest
 * @package Virgil\PureKit\Http\Request
 */
abstract class BaseRequest
{
    private $endpoint;

    protected $params = null;

    /**
     * @var AvailableRequest
     */
    protected $request;

    /**
     * @param string $appToken
     * @return array
     */
    public function getOptionsHeader(string $appToken): array
    {
        return ["virgil-agent" => HttpVirgilAgent::getFormatted(), "AppToken" => $appToken];
    }

    /**
     * @return string
     */
    public function getMethod(): string
    {
        return $this->request->getMethod();
    }

    /**
     * @return string
     */
    public function getEndpoint(): string
    {
        return $this->endpoint ? $this->endpoint : $this->request->getEndpoint();
    }

    /**
     * @param AvailableRequest $request
     * @param string ...$args
     */
    public function setFormattedEndpoint(AvailableRequest $request, string ...$args)
    {
        $this->endpoint = sprintf($request->getEndpoint(), ...$args);
    }

    public function setParams(array $params)
    {
        $this->params = "?".http_build_query($params);
    }

    public function getParams(): ?string
    {
        return $this->params;
    }

    /**
     * @return string
     */
    abstract function getOptionsBody(): string;
}