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

namespace Virgil\PureKit\Phe;

use Virgil\PureKit\Http\_\AvailableHttpMethod;
use Virgil\PureKit\Http\_\AvailableRequest;
use Virgil\PureKit\Http\HttpPheClient;
use Virgil\PureKit\Phe\Exceptions\ProtocolException;
use Virgil\PureKit\Http\Request\Phe\EnrollRequest;
use Virgil\PureKit\Http\Request\Phe\VerifyPasswordRequest;
use Virgil\CryptoWrapper\Phe\PheCipher;
use Virgil\CryptoWrapper\Phe\PheClient;
use Virgil\PureKit\Protobuf\DatabaseRecord;

/**
 *
 * Protocol implements passw0rd client-server protocol
 *
 * Class Protocol
 * @package Virgil\PureKit\Protocol
 */
class Protocol
{
    private $httpClient;

    private $PHECipher;

    private $context;

    public function __construct(ProtocolContext $context)
    {
        $this->httpClient = new HttpPheClient($context->getAppToken());
        $this->PHECipher = new PheCipher();
        $this->context = $context;
    }

    /**
     * @param string $name
     * @param string $argument
     * @throws ProtocolException
     */
    public function __call(string $name, string $argument)
    {
        throw new ProtocolException("Incorrect endpoint: $name");
    }

    /**
     * @param string $password
     * @return array
     * @throws ProtocolException
     */
    public function enrollAccount(string $password): array
    {
        if("" == $password)
            throw new ProtocolException("Empty password");

        $request = new EnrollRequest(AvailableRequest::ENROLL(), AvailableHttpMethod::POST(), $this->getVersion());

        $response = $this->httpClient->enrollAccount($request);
        $enrollmentResponse = $response->getResponse();

        try {
            $enroll = $this->getPHEClient()->enrollAccount($enrollmentResponse, $password);
            $enroll[0] = DatabaseRecord::setup($enroll[0], (int) $response->getVersion());
        }
        catch(\Exception $e) {
            throw new ProtocolException("Invalid proof");
        }

        return $enroll; // [record, enrollment key]
    }

    /**
     * @param string $password
     * @param string $record
     * @return string
     * @throws ProtocolException
     */
    public function verifyPassword(string $password, string $record): string
    {
        // PHE Request
        try {
            if ((int) DatabaseRecord::getValue($record, "version") != (int) $this->getVersion())
                throw new ProtocolException("Invalid User Version");

            $record = DatabaseRecord::getValue($record, "record");
            $verifyPasswordRequest = $this->getPHEClient()->createVerifyPasswordRequest($password, $record);
        }
        catch(\Exception $e) {
            throw new ProtocolException($e->getMessage());
        }

        $request = new VerifyPasswordRequest(
            AvailableRequest::VERIFY_PASSWORD(),
            AvailableHttpMethod::POST(),
            $verifyPasswordRequest,
            $this->getVersion());

        $response = $this->httpClient->verifyPassword($request);
        $verifyPasswordResponse = $response->getResponse();

        try {
            $encryptionKey = $this->getPHEClient()->checkResponseAndDecrypt($password, $record, $verifyPasswordResponse);

            if(strlen($encryptionKey)!==32)
                throw new ProtocolException("Authentication failed (invalid password)");
        }
        catch(\Exception $e) {
            throw new ProtocolException($e->getMessage());
        }

        return $encryptionKey;
    }

    /**
     * @param string $plainText
     * @param string $accountKey
     * @return string
     * @throws \Exception
     */
    public function encrypt(string $plainText, string $accountKey): string
    {
        $this->getPHECipher()->setupDefaults();
        return $this->getPheCipher()->encrypt($plainText, $accountKey);
    }

    /**
     * @param string $cipherText
     * @param string $accountKey
     * @return string
     * @throws \Exception
     */
    public function decrypt(string $cipherText, string $accountKey): string
    {
        return $this->getPheCipher()->decrypt($cipherText, $accountKey);
    }

    /**
     * @return PheCipher
     */
    private function getPHECipher(): PheCipher
    {
        return $this->PHECipher;
    }

    /**
     * @return int
     */
    public function getVersion(): int
    {
        return $this->context->getVersion();
    }

    /**
     * @return PheClient
     */
    private function getPHEClient(): PheClient
    {
        return $this->context->getPHEImpl();
    }

    /**
     * @return array|null
     */
    public function getNewRawKeys()
    {
        return $this->context->getNewRawKeys();
    }
}