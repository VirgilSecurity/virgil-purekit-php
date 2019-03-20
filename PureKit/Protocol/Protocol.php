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

namespace Virgil\PureKit\Protocol;

use Virgil\PureKit\Core\PHECipher;
use Virgil\PureKit\Core\PHEClient;
use Virgil\PureKit\Core\Protobuf\DatabaseRecord;
use Purekit\EnrollmentResponse;
use Virgil\PureKit\Exceptions\ProtocolException;
use Virgil\PureKit\Helpers\ArrayHelperTrait;
use Virgil\PureKit\Http\HttpClient;
use Virgil\PureKit\Http\Request\EnrollRequest;
use Virgil\PureKit\Http\Request\VerifyPasswordRequest;
use Purekit\VerifyPasswordResponse;

/**
 *
 * Protocol implements passw0rd client-server protocol
 *
 * Class Protocol
 * @package Virgil\PureKit\Protocol
 */
class Protocol implements AvailableProtocol
{
    use ArrayHelperTrait;

    /**
     * @var HttpClient
     */
    private $httpClient;

    /**
     * @var PHECipher
     */
    private $PHECipher;

    /**
     * @var ProtocolContext
     */
    private $context;

    /**
     *
     * NewProtocol initializes new protocol instance with proper Context
     *
     * Protocol constructor.
     * @param ProtocolContext $context
     * @throws \Exception
     */
    public function __construct(ProtocolContext $context)
    {
        $this->httpClient = new HttpClient();
        $this->PHECipher = new PHECipher();
        $this->context = $context;
    }

    /**
     * @param string $name
     * @param array $arguments
     * @throws ProtocolException
     */
    public function __call(string $name, array $arguments)
    {
        if(!in_array($name, AvailableProtocol::ENDPOINTS))
            throw new ProtocolException("Incorrect endpoint: $name. Correct endpoints: {$this->toString(AvailableProtocol::ENDPOINTS)}");

        return;
    }

    /**
     *
     * EnrollAccount requests pseudo-random data from server and uses it to protect password and daa encryption key
     *
     * @param string $password
     * @return array
     * @throws ProtocolException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function enrollAccount(string $password): array
    {
        if(""==$password)
            throw new ProtocolException("Empty password");

        // API Request
        $enrollRequest = new EnrollRequest('enroll', $this->getVersion(), $this->context->getAppToken());
        $this->httpClient->setRequest($enrollRequest);

        // API Response
        $response = $this->httpClient->getResponse(false);

        if($response->getStatusCode() !== 200)
            throw new ProtocolException("Api error. Status code: {$response->getStatusCode()}");

        $protobufResponse = $response->getBody()->getContents();

        // Protobuf Response
        $protoEnrollmentResponse = new EnrollmentResponse();
        $protoEnrollmentResponse->mergeFromString($protobufResponse);
        $enrollmentResponse = $protoEnrollmentResponse->getResponse();

        // PHE Response
        try {
            $enroll = $this->getPHEClient()->enrollAccount($enrollmentResponse, $password);
            $enroll[0] = DatabaseRecord::setup($enroll[0], (int) $protoEnrollmentResponse->getVersion());
        }
        catch(\Exception $e) {
            throw new ProtocolException("Invalid proof");
        }

        return $enroll; // [record, enrollment key]
    }

    /**
     *
     * VerifyPassword verifies a password against enrollment record using passw0rd service
     *
     * @param string $password
     * @param string $record
     * @return string
     * @throws ProtocolException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function verifyPassword(string $password, string $record): string
    {
        // PHE Request
        try {
            if((int)DatabaseRecord::getValue($record, "version") !== (int)$this->getVersion())
                throw new ProtocolException("Invalid User Version");

            $record = DatabaseRecord::getValue($record, "record");
            $verifyPasswordRequest = $this->getPHEClient()->createVerifyPasswordRequest($password, $record);
        }
        catch(\Exception $e) {
            throw new ProtocolException($e->getMessage());
        }

        // API Request
        $verifyPassword = new VerifyPasswordRequest('verify-password', $verifyPasswordRequest, $this->getVersion(),
            $this->context->getAppToken());

        $this->httpClient->setRequest($verifyPassword);

        // API Response
        $response = $this->httpClient->getResponse(false);

        if($response->getStatusCode() !== 200)
            throw new ProtocolException("Api error. Status code: {$response->getStatusCode()}");

        $protobufResponse = $response->getBody()->getContents();

        // Protobuf Response
        $protoVerifyPasswordResponse = new VerifyPasswordResponse();
        $protoVerifyPasswordResponse->mergeFromString($protobufResponse);
        $verifyPasswordResponse = $protoVerifyPasswordResponse->getResponse();

        // PHE Response
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
     */
    public function encrypt(string $plainText, string $accountKey): string
    {
        $this->getPHECipher()->setupDefaults();
        return $this->getPHECipher()->encrypt($plainText, $accountKey);
    }

    /**
     * @param string $cipherText
     * @param string $accountKey
     * @return string
     */
    public function decrypt(string $cipherText, string $accountKey): string
    {
        return $this->getPHECipher()->decrypt($cipherText, $accountKey);
    }

    /**
     * @return PHECipher
     */
    private function getPHECipher(): PHECipher
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
     * @return PHEClient
     */
    private function getPHEClient(): PHEClient
    {
        return $this->context->getPHEImpl();
    }

    /**
     * @return array|null
     */
    public function getNewRawKeys(): ?array
    {
        return $this->context->getNewRawKeys();
    }
}