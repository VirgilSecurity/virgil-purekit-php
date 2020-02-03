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

namespace Virgil\PureKit\Pure;

use Purekit\EnrollmentRequest as ProtoEnrollmentRequest;
use Purekit\VerifyPasswordRequest as ProtoVerifyPasswordRequest;
use Virgil\Crypto\Core\HashAlgorithms;
use Virgil\CryptoWrapper\Phe\PheClient;
use Virgil\PureKit\Pure\Exception\NullPointerException;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\Util\ValidateUtil;

class PheManager
{
    private $crypto;
    private $currentVersion;
    private $currentClient;
    private $updateToken;
    private $previousClient;
    private $httpClient;

    public function __construct(PureContext $context)
    {
        $this->crypto = $context->getCrypto();

        $this->currentClient = new PheClient();
        $this->currentClient->useOperationRandom($this->crypto->getRng());
        $this->currentClient->useRandom($this->crypto->getRng());

        if (!is_null($context->getUpdateToken())) {
            $this->currentVersion = $context->getPublicKey()->getVersion() + 1;
            $this->updateToken = $context->getUpdateToken()->getPayload1();
            $this->previousClient = new PheClient();
            $this->previousClient->useOperationRandom($this->crypto->getRng());
            $this->previousClient->useRandom($this->crypto->getRng());
            $this->previousClient->setKeys($context->getSecretKey()->getPayload1(),
                $context->getPublicKey()->getPayload1());

            $rotateKeysResult = $this->previousClient->rotateKeys($context->getUpdateToken()->getPayload1());
            $this->currentClient->setKeys($rotateKeysResult->getNewClientPrivateKey(),
                $rotateKeysResult->getNewServerPublicKey());

        } else {
            $this->currentVersion = $context->getPublicKey()->getVersion();
            $this->updateToken = null;
            $this->currentClient->setKeys($context->getSecretKey()->getPayload1(), $context->getPublicKey()
                ->getPayload1());
            $this->previousClient = null;
        }

        $this->httpClient = $context->getPheClient();
    }

    private function getPheClient(int $pheVersion): PheClient
    {
        if ($this->currentVersion == $pheVersion) {
            return $this->currentClient;
        } elseif ($this->currentVersion == $pheVersion + 1) {
            return $this->previousClient;
        } else {
            throw new NullPointerException("pheClient");
        }
    }

    public function computePheKey(UserRecord $userRecord, string $password): string
    {
        $passwordHash = $this->crypto->computeHash($password, HashAlgorithms::SHA512());

        return $this->computePheKey_($userRecord, $passwordHash);
    }

    public function computePheKey_(UserRecord $userRecord, string $passwordHash): string
    {
        try {
            $client = $this->getPheClient($userRecord->getPheRecordVersion());

                $pheVerifyRequest = $client->createVerifyPasswordRequest($passwordHash,
                    $userRecord->getPheRecord());

                $request = (new ProtoVerifyPasswordRequest)
                ->setVersion($userRecord->getRecordVersion())
                ->setRequest($pheVerifyRequest);

                $response = $this->httpClient->verifyPassword($request);

                $phek = $this->client->checkResponseAndDecrypt($passwordHash,
                    $userRecord->getPheRecord(),
                    $response->getResponse());

                if (strlen($phek) == 0)
                    throw new PureLogicException(ErrorStatus::INVALID_PASSWORD());

                return $phek;
            }
        catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    public function performRotation(string $enrollmentRecord): string {
        ValidateUtil::checkNull($this->updateToken, "pheUpdateToken");

        return $this->previousClient->updateEnrollmentRecord($enrollmentRecord, $this->updateToken);
    }

    public function getEnrollment(string $passwordHash): PheClientEnrollAccountResult
    {
        $request = (new ProtoEnrollmentRequest)
            ->setVersion($this->currentVersion);

        $response = $this->httpClient->enrollAccount($request);

        return $this->currentClient->enrollAccount(
                $response->getResponse(),
                $passwordHash
            );
    }
}