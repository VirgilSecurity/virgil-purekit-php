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

namespace Virgil\PureKit\Pure\Exception;

use RuntimeException;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\CryptoWrapper\Foundation\Exception\FoundationException;
use Virgil\CryptoWrapper\Phe\Exception\PheException;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureCryptoErrorStatus;

class PureCryptoException extends PureException
{
    private $cryptoException;
    private $foundationException;
    private $pheException;
    private $errorStatus;

    public function __construct($e)
    {
        $this->errorStatus = null;
        $this->cryptoException = null;
        $this->foundationException = null;
        $this->pheException = null;

        switch ($e) {
            case ($e instanceof PureCryptoErrorStatus):
                parent::__construct($e->getMessage());

                if ($e == PureCryptoErrorStatus::UNDERLYING_FOUNDATION_EXCEPTION()
                    || $e == PureCryptoErrorStatus::UNDERLYING_PHE_EXCEPTION()) {
                    throw new RuntimeException("Underlying foundation/phe exception");
                }

                $this->errorStatus = $e;
                break;
            case ($e instanceof VirgilCryptoException):
                parent::__construct($e);
                $this->errorStatus = PureCryptoErrorStatus::UNDERLYING_CRYPTO_EXCEPTION();
                $this->cryptoException = $e;
                break;
            case ($e instanceof FoundationException):
                parent::__construct($e);
                $this->errorStatus = PureCryptoErrorStatus::UNDERLYING_FOUNDATION_EXCEPTION();
                $this->foundationException = $e;
                break;
            case ($e instanceof PheException):
                parent::__construct($e);
                $this->errorStatus = PureCryptoErrorStatus::UNDERLYING_PHE_EXCEPTION();
                $this->pheException = $e;
                break;
            default:
                var_dump("_1: Invalid type of exception", $e->getMessage(), $e->getCode(), $e->getFile(), get_class
                ($e), $e->getLine());
                die;
        }
    }

    public function getErrorStatus(): PureCryptoErrorStatus
    {
        return $this->errorStatus;
    }

    /**
     * @return null|VirgilCryptoException
     */
    public function getCryptoException(): ?VirgilCryptoException
    {
        return $this->cryptoException;
    }

    /**
     * @return null|FoundationException
     */
    public function getFoundationException(): ?FoundationException
    {
        return $this->foundationException;
    }

    /**
     * @return null|PheException
     */
    public function getPheException(): ?PheException
    {
        return $this->pheException;
    }
}