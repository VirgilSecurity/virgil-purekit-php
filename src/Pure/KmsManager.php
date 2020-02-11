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


use PurekitV3Client\DecryptRequest as ProtoDecryptRequest;
use Virgil\CryptoWrapper\Phe\Exception\PheException;
use Virgil\CryptoWrapper\Phe\UokmsClient;
use Virgil\CryptoWrapper\Phe\UokmsWrapRotation;
use Virgil\PureKit\Http\_\AvailableRequest;
use Virgil\PureKit\Http\Request\Kms\DecryptRequest;
use Virgil\PureKit\Pure\Exception\KmsClientException;
use Virgil\PureKit\Pure\Exception\NullPointerException;
use Virgil\PureKit\Pure\Exception\ProtocolException;
use Virgil\PureKit\Pure\Exception\ProtocolHttpException;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\Util\ValidateUtil;

class KmsManager
{
    public const RECOVER_PWD_ALIAS = "RECOVERY_PASSWORD";

    private $currentVersion;
    private $pureCrypto;
    private $currentClient;
    private $previousClient;
    private $httpClient;
    private $kmsRotation;

    public function __construct(PureContext $context)
    {
        try {
            $this->pureCrypto = new PureCrypto($context->getCrypto());
            $this->currentClient = new UokmsClient();
            $this->currentClient->useOperationRandom($context->getCrypto()->getRng());
            $this->currentClient->useRandom($context->getCrypto()->getRng());

            if (!is_null($context->getUpdateToken())) {
                $this->currentVersion = $context->getPublicKey()->getVersion() + 1;
                $updateToken = $context->getUpdateToken()->getPayload2();
                $this->kmsRotation = new UokmsWrapRotation();
                $this->kmsRotation->useOperationRandom($context->getCrypto()->getRng());
                $this->kmsRotation->setUpdateToken($updateToken);
                $this->previousClient = new UokmsClient();
                $this->previousClient->useOperationRandom($context->getCrypto()->getRng());
                $this->previousClient->useRandom($context->getCrypto()->getRng());
                $this->previousClient->setKeys($context->getSecretKey()->getPayload2(),
                    $context->getPublicKey()->getPayload2());

                $rotateKeysResult = $this->previousClient->rotateKeys($context->getUpdateToken()->getPayload2());
                $this->currentClient->setKeys($rotateKeysResult->getNewClientPrivateKey(),
                    $rotateKeysResult->getNewServerPublicKey());

            } else {
                $this->currentVersion = $context->getPublicKey()->getVersion();
                $this->kmsRotation = null;
                $this->previousClient = null;
                $this->currentClient->setKeys($context->getSecretKey()->getPayload2(), $context->getPublicKey()
                    ->getPayload2());
            }

            $this->httpClient = $context->getKmsClient();
        }
        catch (PheException $exception) {
            throw new PureCryptoException($exception);
        }
    }

    private function getKmsClient(int $kmsVersion): UokmsClient
    {
        if ($this->currentVersion == $kmsVersion) {
            return $this->currentClient;
        } elseif ($this->currentVersion == $kmsVersion + 1) {
            return $this->previousClient;
        } else {
            throw new NullPointerException("kmsClient");
        }
    }


    private function recoverSecret(UserRecord $userRecord): string
    {
        try {
            $kmsClient = $this->getKmsClient($userRecord->getRecordVersion());

            // [deblind_factor, decrypt_request]
            $uokmsClientGenerateDecryptRequestResult = $kmsClient->generateDecryptRequest(
                $userRecord->getPasswordRecoveryWrap());

            $decryptRequest = (new ProtoDecryptRequest)
                ->setVersion($userRecord->getRecordVersion())
                ->setAlias(self::RECOVER_PWD_ALIAS)
                ->setRequest($uokmsClientGenerateDecryptRequestResult[1]);

            $request = new DecryptRequest(AvailableRequest::DECRYPT_REQUEST(), $decryptRequest);

            $decryptResponse = $this->httpClient->decrypt($request);

            return $kmsClient->processDecryptResponse($userRecord->getPasswordRecoveryWrap(),
                $uokmsClientGenerateDecryptRequestResult[1],
                $decryptResponse->getResponse(),
                $uokmsClientGenerateDecryptRequestResult[0],
                PureCrypto::DERIVED_SECRET_LENGTH);
        } catch (PheException $exception) {
            throw new PureCryptoException($exception);
        } catch (ProtocolException $exception) {
            throw new KmsClientException($exception);
        } catch (ProtocolHttpException $exception) {
            throw new KmsClientException($exception);
        }

    }

    public function performRotation(string $wrap): string
    {
        try {
            ValidateUtil::checkNull($this->kmsRotation, "kmsUpdateToken");
            ValidateUtil::checkNull($wrap, "wrap");

            return $this->kmsRotation->updateWrap($wrap);
        } catch (PheException $exception) {
            throw new PureCryptoException($exception);
        }
    }

    public function recoverPwd(UserRecord $userRecord): string
    {
        $derivedSecret = $this->recoverSecret($userRecord);
        return $this->pureCrypto->decryptSymmetricOneTimeKey($userRecord->getPasswordRecoveryBlob(), "",
            $derivedSecret);
    }

    public function generatePwdRecoveryData(string $passwordHash): PwdRecoveryData
    {
        try {
            // @return [wrap, encryptionKey]
            $kmsResult = $this->currentClient->generateEncryptWrap(PureCrypto::DERIVED_SECRET_LENGTH);

            $derivedSecret = $kmsResult[1];

            $resetPwdBlob = $this->pureCrypto->encryptSymmetricOneTimeKey($passwordHash, "", $derivedSecret);

            return new PwdRecoveryData($kmsResult[0], $resetPwdBlob);
        } catch (PheException $exception) {
            throw new PureCryptoException($exception);
        } catch (\Exception $exception) {
            var_dump($exception);
            die;
        }
    }
}