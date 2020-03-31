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

namespace Virgil\PureKit\Pure\Model;

use Virgil\Crypto\Core\VirgilKeys\VirgilKeyPair;
use Virgil\PureKit\Pure\Util\ValidationUtils;

/**
 * Class PureGrant
 * @package Virgil\PureKit\Pure\Model
 */
class PureGrant
{
    /**
     * @var VirgilKeyPair
     */
    private $ukp;
    /**
     * @var string
     */
    private $userId;
    /**
     * @var string
     */
    private $sessionId;
    /**
     * @var \DateTime
     */
    private $creationDate;
    /**
     * @var \DateTime
     */
    private $expirationDate;

    /**
     * PureGrant constructor.
     * @param VirgilKeyPair $ukp
     * @param string $userId
     * @param string|null $sessionId
     * @param \DateTime $creationDate
     * @param \DateTime $expirationDate
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function __construct(VirgilKeyPair $ukp, string $userId, string $sessionId = null, \DateTime $creationDate,
                                \DateTime $expirationDate)
    {
        ValidationUtils::checkNull($ukp, "ukp");
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNull($creationDate, "creationDate");
        ValidationUtils::checkNull($expirationDate, "expirationDate");

        $this->ukp = $ukp;
        $this->userId = $userId;
        $this->sessionId = $sessionId;
        $this->creationDate = $creationDate;
        $this->expirationDate = $expirationDate;
    }

    /**
     * @return VirgilKeyPair
     */
    public function getUkp(): VirgilKeyPair
    {
        return $this->ukp;
    }

    /**
     * @return string
     */
    public function getUserId(): string
    {
        return $this->userId;
    }

    /**
     * @return null|string
     */
    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    /**
     * @return \DateTime
     */
    public function getCreationDate(): \DateTime
    {
        return $this->creationDate;
    }

    /**
     * @return \DateTime
     */
    public function getExpirationDate(): \DateTime
    {
        return $this->expirationDate;
    }
}