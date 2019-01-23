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

namespace passw0rd\Protocol;

use passw0rd\Core\PHECipher;
use passw0rd\Core\PHEClient;
use passw0rd\Core\Protobuf\DatabaseRecord;
use Passw0rd\EnrollmentResponse;
use passw0rd\Exeptions\ProtocolContextException;
use passw0rd\Exeptions\ProtocolException;
use passw0rd\Helpers\ArrayHelperTrait;
use passw0rd\Http\HttpClient;
use passw0rd\Http\Request\EnrollRequest;
use passw0rd\Http\Request\VerifyPasswordRequest;
use Passw0rd\VerifyPasswordResponse;

/**
 * Class Protocol
 * @package passw0rd\Protocol
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
        $enrollRequest = new EnrollRequest('enroll', $this->getVersion());
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
        $verifyPassword = new VerifyPasswordRequest('verify-password', $verifyPasswordRequest, $this->getVersion());

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
     * @param string $record
     * @param bool $encodeToBase64
     * @return string
     * @throws ProtocolContextException
     * @throws ProtocolException
     */
    public function updateEnrollmentRecord(string $record, bool $encodeToBase64 = false): string
    {
        if(is_null($this->context->getUpdateToken()))
            throw new ProtocolContextException("Empty update token");

        // PHE Response
        try {
            if((int)DatabaseRecord::getValue($record, "version") == (int)$this->getVersion()) {
                throw new ProtocolException("Already migrated");
            }
            else {
                $record = DatabaseRecord::getValue($record, "record");

                $updatedRecord = $this->getPHEClient()->updateEnrollmentRecord($record,
                    $this->context->getUpdateToken());

                $updatedRecord = DatabaseRecord::setup($updatedRecord, $this->getVersion());
            }
        }
        catch(\Exception $e) {
            throw new ProtocolException(__METHOD__.": {$e->getMessage()}, {$e->getCode()}");
        }

        return $encodeToBase64==true ? base64_encode($updatedRecord) : $updatedRecord;
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
}