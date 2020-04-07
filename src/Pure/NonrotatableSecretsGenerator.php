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

namespace Virgil\PureKit\Pure;

use Virgil\Crypto\VirgilCrypto;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\CryptoWrapper\Foundation\KeyMaterialRng;

/**
 * Class NonrotatableSecretsGenerator
 * @package Virgil\PureKit\Pure
 */
class NonrotatableSecretsGenerator
{
    private const NONROTATABLE_MASTER_SECRET_LENGTH = 32;

    /**
     * @param string $masterSecret
     * @return NonrotableSecrets
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureCryptoException
     * @throws PureLogicException
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public static function generateSecrets(string $masterSecret): NonrotableSecrets
    {
        if (self::NONROTATABLE_MASTER_SECRET_LENGTH != strlen($masterSecret))
            throw new PureLogicException(ErrorStatus::NONROTABLE_MASTER_SECRET_INVALID_LENGTH());

        $rng = new KeyMaterialRng();
        $rng->resetKeyMaterial($masterSecret);

        $crypto = new VirgilCrypto(null, false, $rng);

        try {
            $vskp = $crypto->generateKeyPair();
            $oskp = $crypto->generateKeyPair();
        } catch (CryptoException $exception) {
            throw new PureCryptoException($exception);
        }


        return new NonrotableSecrets($vskp, $oskp);
    }
}