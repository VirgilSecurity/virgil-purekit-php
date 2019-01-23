<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
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

namespace passw0rd\Credentials;

use passw0rd\Exeptions\UpdateTokenException;

/**
 * Class UpdateToken
 * @package passw0rd\Credentials
 */
class UpdateToken
{
    private $updateToken;
    private $version;
    private $value;

    const PREFIX = "UT";

    /**
     * UpdateToken constructor.
     * @param string $updateToken
     * @throws UpdateTokenException
     */
    public function __construct(string $updateToken)
    {
        if($updateToken == "")
            throw new UpdateTokenException("Empty update token value");
        $this->validateAndSet($updateToken);
    }

    /**
     * @param string $updateToken
     * @throws UpdateTokenException
     */
    private function validateAndSet(string $updateToken): void
    {
        $parts = explode(".", $updateToken);

        if (count($parts) !== 3 || $parts[0] !== self::PREFIX)
            throw new UpdateTokenException("Invalid string: $this->updateToken");

        if ((int)$parts[1] < 1)
            throw new UpdateTokenException("Invalid version: $parts[1]");

        if(strlen($parts[2])!==92)
            throw new UpdateTokenException("Invalid token base64 string len: $parts[2]");

        $this->version = $parts[1];
        $this->value = base64_decode($parts[2]);
    }

    /**
     * @return int
     */
    public function getVersion(): int
    {
        return (int) $this->version;
    }

    /**
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }

}