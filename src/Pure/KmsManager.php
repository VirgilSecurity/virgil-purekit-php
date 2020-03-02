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
use Virgil\PureKit\Pure\Model\GrantKey;
use Virgil\PureKit\Pure\Model\UserRecord;
use Virgil\PureKit\Pure\Util\ValidateUtil;

class KmsManager
{
    public const RECOVER_PWD_ALIAS = "RECOVERY_PASSWORD";

    private $currentVersion;
    private $pureCrypto;
    private $pwdCurrentClient;
    private $pwdPreviousClient;
    private $grantCurrentClient;
    private $grantPreviousClient;
    private $httpClient;
    private $pwdKmsRotation;
    private $grantKmsRotation;

    public function __construct(PureContext $context)
    {
        try {
            $this->pureCrypto = new PureCrypto($context->getCrypto());
            $this->pwdCurrentClient = new UokmsClient();
            $this->pwdCurrentClient->useOperationRandom($context->getCrypto()->getRng());
            $this->pwdCurrentClient->useRandom($context->getCrypto()->getRng());
            $this->grantCurrentClient = new UokmsClient();
            $this->grantCurrentClient->useOperationRandom($context->getCrypto()->getRng());
            $this->grantCurrentClient->useRandom($context->getCrypto()->getRng());

            if (!is_null($context->getUpdateToken())) {
                $this->currentVersion = $context->getPublicKey()->getVersion() + 1;

                $pwdUpdateToken = $context->getUpdateToken()->getPayload2();
                $this->pwdKmsRotation = new UokmsWrapRotation();
                $this->pwdKmsRotation->useOperationRandom($context->getCrypto()->getRng());
                $this->pwdKmsRotation->setUpdateToken($pwdUpdateToken);
                $this->pwdPreviousClient = new UokmsClient();
                $this->pwdPreviousClient->useOperationRandom($context->getCrypto()->getRng());
                $this->pwdPreviousClient->useRandom($context->getCrypto()->getRng());
                $this->pwdPreviousClient->setKeys($context->getSecretKey()->getPayload2(),
                    $context->getPublicKey()->getPayload2());

                // [new_client_private_key, new_server_public_key]
                $rotateKeysResult = $this->pwdPreviousClient->rotateKeys($pwdUpdateToken);
                $this->pwdCurrentClient->setKeys($rotateKeysResult[0],
                    $rotateKeysResult[1]);

            } else {
                $this->currentVersion = $context->getPublicKey()->getVersion();
                $this->pwdKmsRotation = null;
                $this->pwdPreviousClient = null;
                $this->grantKmsRotation = null;
                $this->grantPreviousClient = null;
                $this->pwdCurrentClient->setKeys($context->getSecretKey()->getPayload2(), $context->getPublicKey()
                    ->getPayload2());
                $this->grantCurrentClient->setKeysOneparty($context->getSecretKey()->getPayload3());
            }

            $this->httpClient = $context->getKmsClient();
        }
        catch (PheException $exception) {
            throw new PureCryptoException($exception);
        }
    }

    private function getPwdClient(int $kmsVersion): UokmsClient
    {
        if ($this->currentVersion == $kmsVersion) {
            return $this->pwdCurrentClient;
        } elseif ($this->currentVersion == $kmsVersion + 1) {
            return $this->pwdPreviousClient;
        } else {
            throw new NullPointerException("kmsClient");
        }
    }

    private function getGrantClient(int $kmsVersion): UokmsClient
    {
        if ($this->currentVersion == $kmsVersion) {
            return $this->grantCurrentClient;
        } elseif ($this->currentVersion == $kmsVersion + 1) {
            return $this->grantPreviousClient;
        } else {
            throw new NullPointerException("kmsClient");
        }
    }

    private function recoverPwdSecret(UserRecord $userRecord): string
    {
        try {
            $kmsClient = $this->getPwdClient($userRecord->getRecordVersion());

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

    private function recoverGrantKeySecret(GrantKey $grantKey): string
    {
        try {
            $kmsClient = $this->getGrantClient($grantKey->getRecordVersion());

            return $kmsClient->decryptOneparty($grantKey->getEncryptedGrantKeyWrap(),
                PureCrypto::DERIVED_SECRET_LENGTH);
        }
        catch (PheException $exception) {
            throw new PureCryptoException($exception);
        }
    }

    public function performPwdRotation(string $wrap): string
    {
        try {
            ValidateUtil::checkNull($this->pwdKmsRotation, "kmsUpdateToken");
            ValidateUtil::checkNull($wrap, "wrap");

            return $this->pwdKmsRotation->updateWrap($wrap);
        } catch (PheException $exception) {
            throw new PureCryptoException($exception);
        }
    }

    public function performGrantRotation(string $wrap): string
    {
        try {
            ValidateUtil::checkNull($this->grantKmsRotation, "grantUpdateToken");
            ValidateUtil::checkNull($wrap, "wrap");

            return $this->grantKmsRotation->updateWrap($wrap);
        }
        catch (PheException $exception) {
            throw new PureCryptoException($exception);
        }
    }

    public function recoverPwd(UserRecord $userRecord): string
    {
        $derivedSecret = $this->recoverPwdSecret($userRecord);

        return $this->pureCrypto->decryptSymmetricWithOneTimeKey($userRecord->getPasswordRecoveryBlob(), "",
            $derivedSecret);
    }

    public function recoverGrantKey(GrantKey $grantKey, string $header): string
    {
        $derivedSecret = $this->recoverGrantKeySecret($grantKey);
        return $this->pureCrypto->decryptSymmetricWithOneTimeKey($grantKey->getEncryptedGrantKeyBlob(), $header,
                $derivedSecret);
    }

    public function generatePwdRecoveryData(string $passwordHash): KmsEncryptedData
    {
        return $this->generateEncryptionData($passwordHash, "", true);
    }

    public function generateGrantKeyEncryptionData(string $grantKey, string $header): KmsEncryptedData
    {
        return $this->generateEncryptionData($grantKey, $header, false);
    }

    private function generateEncryptionData(string $data, string $header, bool $isPwd): KmsEncryptedData
    {
        try {
            // @return [wrap, encryptionKey]
            $kmsResult = ($isPwd ? $this->pwdCurrentClient : $this->grantCurrentClient)->generateEncryptWrap
            (PureCrypto::DERIVED_SECRET_LENGTH);

            $derivedSecret = $kmsResult[1];

            $resetPwdBlob = $this->pureCrypto->encryptSymmetricWithOneTimeKey($data, $header, $derivedSecret);

            return new KmsEncryptedData($kmsResult[0], $resetPwdBlob);
        } catch (PheException $exception) {
            throw new PureCryptoException($exception);
        }
        // TODO!
        catch (\Exception $exception) {
            var_dump($exception);
            die;
        }
    }
}