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

namespace passw0rd\Credentials;

use passw0rd\Exeptions\InputCredentialsCheckerException;

/**
 * Class InputCredentialsChecker
 * @package passw0rd\credentials
 */
class InputCredentialsChecker implements AvailableCredentials
{
    private $credentials;

    /**
     * @param array $credentials
     * @return void
     */
    private function setCredentials(array $credentials): void
    {
        $this->credentials = $credentials;
    }

    /**
     * @param array $credentials
     * @throws InputCredentialsCheckerException
     * @return bool
     */
    public function check(array $credentials): bool
    {
        $this->setCredentials($credentials);

        foreach (AvailableCredentials::KEYS as $credentialKey)
        {
            if(!$this->checkKeyExists($credentialKey))
                throw new InputCredentialsCheckerException("Credential key does not exists: $credentialKey");

            if(!$this->checkValue($credentialKey))
                throw new InputCredentialsCheckerException("Incorrect or empty value for credential key: $credentialKey");
        }

        return true;
    }

    /**
     * @param string $credentialKey
     * @return bool
     */
    private function checkKeyExists(string $credentialKey): bool
    {
        return array_key_exists($credentialKey, $this->credentials);
    }

    /**
     * @param string $credentialKey
     * @return bool
     */
    private function checkValue(string $credentialKey): bool
    {
        return (is_string($this->credentials[$credentialKey]) && $this->credentials[$credentialKey] !== '');
    }
}