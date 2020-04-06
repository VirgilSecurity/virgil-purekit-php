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

use Virgil\Crypto\Core\Enum\HashAlgorithms;
use Virgil\CryptoWrapper\Phe\PheClient;
use Virgil\PureKit\Http\Request\Phe\EnrollRequest;
use Virgil\PureKit\Http\Request\Phe\VerifyPasswordRequest;
use Virgil\PureKit\Pure\Exception\ErrorStatus\PureLogicErrorStatus;
use Virgil\PureKit\Pure\Exception\NullPointerException;
use Virgil\PureKit\Pure\Exception\PheClientException;
use Virgil\PureKit\Pure\Exception\ProtocolException;
use Virgil\PureKit\Pure\Exception\ProtocolHttpException;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\PureKit\Pure\Exception\PureLogicException;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\Util\ValidationUtils;

/**
 * Class PheManager
 * @package Virgil\PureKit\Pure
 */
class PheManager
{
    /**
     * @var \Virgil\Crypto\VirgilCrypto
     */
    private $crypto;
    /**
     * @var int
     */
    private $currentVersion;
    /**
     * @var PheClient
     */
    private $currentClient;
    /**
     * @var null
     */
    private $updateToken;
    /**
     * @var null
     */
    private $previousClient;
    /**
     * @var \Virgil\PureKit\Http\HttpPheClient
     */
    private $httpClient;

    /**
     * PheManager constructor.
     * @param PureContext $context
     * @throws PureCryptoException
     */
    public function __construct(PureContext $context)
    {
        try {
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

                // [new_client_private_key, new_server_public_key]
                $rotateKeysResult = $this->previousClient->rotateKeys($context->getUpdateToken()->getPayload1());
                $this->currentClient->setKeys($rotateKeysResult[0],
                    $rotateKeysResult[1]);

            } else {
                $this->currentVersion = $context->getPublicKey()->getVersion();
                $this->updateToken = null;
                $this->currentClient->setKeys($context->getSecretKey()->getPayload1(), $context->getPublicKey()
                    ->getPayload1());
                $this->previousClient = null;
            }

            $this->httpClient = $context->getPheClient();
        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param int $pheVersion
     * @return PheClient
     * @throws NullPointerException
     */
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

    /**
     * @param UserRecord $userRecord
     * @param string $password
     * @return string
     * @throws NullPointerException
     * @throws PheClientException
     * @throws PureCryptoException
     * @throws PureLogicException
     */
    public function computePheKey(UserRecord $userRecord, string $password): string
    {
        $passwordHash = $this->crypto->computeHash($password, HashAlgorithms::SHA512());

        return $this->computePheKey_($userRecord, $passwordHash);
    }

    /**
     * @param UserRecord $userRecord
     * @param string $passwordHash
     * @return string
     * @throws NullPointerException
     * @throws PheClientException
     * @throws PureCryptoException
     * @throws PureLogicException
     */
    public function computePheKey_(UserRecord $userRecord, string $passwordHash): string
    {
        try {
            $client = $this->getPheClient($userRecord->getRecordVersion());

                $pheVerifyRequest = $client->createVerifyPasswordRequest($passwordHash,
                    $userRecord->getPheRecord());

                $request = new VerifyPasswordRequest($pheVerifyRequest, $userRecord->getRecordVersion());

                $response = $this->httpClient->verifyPassword($request);

                $phek = $client->checkResponseAndDecrypt($passwordHash,
                    $userRecord->getPheRecord(),
                    $response->getResponse());

                if (strlen($phek) == 0)
                    throw new PureLogicException(PureLogicErrorStatus::INVALID_PASSWORD());

                return $phek;
            }
        catch (\PheException $exception) {
            throw new PureCryptoException($exception);
        }
        catch (ProtocolException | ProtocolHttpException $exception) {
            throw new PheClientException($exception);
        }
    }

    /**
     * @param string $enrollmentRecord
     * @return string
     * @throws Exception\IllegalStateException
     * @throws Exception\NullArgumentException
     * @throws PureCryptoException
     */
    public function performRotation(string $enrollmentRecord): string {

        ValidationUtils::checkNull($this->updateToken, "pheUpdateToken");

        try {
            return $this->previousClient->updateEnrollmentRecord($enrollmentRecord, $this->updateToken);
        } catch (\PheException $exception) {
            throw new PureCryptoException($exception);
        }

    }

    /**
     * @param string $passwordHash
     * @return array
     * @throws PheClientException
     * @throws PureCryptoException
     */
    public function getEnrollment(string $passwordHash): array
    {
        $request = new EnrollRequest($this->currentVersion);

        try {
            $response = $this->httpClient->enrollAccount($request);
        } catch (ProtocolException | ProtocolHttpException $exception) {
            throw new PheClientException($exception);
        }

        try {
            // [enrollment_record, account_key]
            return $this->currentClient->enrollAccount(
                $response->getResponse(),
                $passwordHash
            );
        } catch (\PheException $exception) {
            throw new PureCryptoException($exception);
        }
    }
}