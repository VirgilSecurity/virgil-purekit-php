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

use Virgil\CryptoImpl\Core\VirgilPrivateKey;
use Virgil\CryptoImpl\Core\VirgilPublicKey;
use Virgil\CryptoImpl\VirgilCrypto;
use Virgil\PureKit\Pure\Collection\VirgilPublicKeyCollection;
use Virgil\PureKit\Pure\Exception\ErrorStatus;
use Virgil\PureKit\Pure\Exception\PureCryptoException;
use VirgilCrypto\Foundation\Aes256Gcm;
use VirgilCrypto\Foundation\MessageInfoDerSerializer;
use VirgilCrypto\Foundation\MessageInfoEditor;
use VirgilCrypto\Foundation\RecipientCipher;
use VirgilCrypto\Foundation\Sha512;

/**
 * Class PureCrypto
 * @package Virgil\PureKit\Pure
 */
class PureCrypto
{
    /**
     * @var VirgilCrypto
     */
    private $crypto;

    /**
     * PureCrypto constructor.
     * @param VirgilCrypto $crypto
     */
    public function __construct(VirgilCrypto $crypto)
    {
        $this->crypto = $crypto;
    }

    /**
     * @param string $plainTextData
     * @param VirgilPrivateKey $signingKey
     * @param VirgilPublicKeyCollection $recipients
     * @return PureCryptoData
     * @throws PureCryptoException
     */
    public function encrypt(string $plainTextData, VirgilPrivateKey $signingKey, VirgilPublicKeyCollection
    $recipients): PureCryptoData
    {
        try {
            $aesGsm = new Aes256Gcm();
            $cipher = new RecipientCipher();

            $cipher->useEncryptionCipher($aesGsm);
            // TODO!
            $cipher->useRandom($this->crypto->getRng());

            $cipher->addSigner($signingKey->getIdentifier(), $signingKey->getPrivateKey());

            // TODO!
            foreach ($recipients->getAsArray() as $key) {
                $cipher->addKeyRecipient($key->getIdentifier(), $key->getPublicKey());
            }

            $cipher->useSignerHash(new Sha512());
            $cipher->startSignedEncryption(strlen($plainTextData));

            $cms = $cipher->packMessageInfo();
            $body1 = $cipher->processEncryption($plainTextData);
            $body2 = $cipher->finishEncryption();
            $body3 = $cipher->packMessageInfoFooter();

            $body = $this->concat($this->concat($body1, $body2), $body3);

            return new PureCryptoData($cms, $body);


        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param PureCryptoData $data
     * @param VirgilPublicKey $verifyingKey
     * @param VirgilPrivateKey $privateKey
     * @return string
     * @throws PureCryptoException
     */
    public function decrypt(PureCryptoData $data, VirgilPublicKey $verifyingKey, VirgilPrivateKey $privateKey): string
    {
        try {
            $cipher = new RecipientCipher();

            // TODO!
            $cipher->useRandom($this->crypto->getRng());

            // TODO!
            $cipher->startVerifiedDecryptionWithKey($privateKey->getIdentifier(), $privateKey->getPrivateKey(),
                $data->getBody(), 0);

            $body1 = $cipher->processDecryption($data->getBody());
            $body2 = $cipher->finishEncryption();

            if (!$cipher->isDataSigned())
                throw new PureCryptoException(ErrorStatus::SIGNATURE_IS_ABSENT());

            $signerInfoList = $cipher->signerInfos();

            if (!$signerInfoList->hasItem() && $signerInfoList->hasNext())
                throw new PureCryptoException(ErrorStatus::SIGNER_IS_ABSENT());

            $signerInfo = $signerInfoList->item();

            if ($signerInfo->signerId() != $verifyingKey->getIdentifier())
                throw new PureCryptoException(ErrorStatus::SIGNER_IS_ABSENT());

            if (!$cipher->verifySignerInfo($signerInfo, $verifyingKey->getPublicKey()))
                throw new PureCryptoException(ErrorStatus::SIGNATURE_VERIFICATION_FAILED());

            return $this->concat($body1, $body2);

        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param string $cms
     * @param VirgilPrivateKey $privateKey
     * @param VirgilPublicKeyCollection $publicKeys
     * @return string
     * @throws PureCryptoException
     */
    public function addRecipients(string $cms, VirgilPrivateKey $privateKey, VirgilPublicKeyCollection $publicKeys): string
    {
        try {
            $infoEditor = new MessageInfoEditor();
            $infoEditor->useRandom($this->crypto->getRng());

            $infoEditor->unpack($cms);
            $infoEditor->unlock($privateKey->getIdentifier(), $privateKey->getPrivateKey());

            foreach ($publicKeys->getAsArray() as $publicKey) {
                $infoEditor->addKeyRecipient($publicKey->getIdentifier(), $publicKey->getPublicKey());
            }

            return $infoEditor->pack();

        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param string $cms
     * @param VirgilPublicKeyCollection $publicKeys
     * @return string
     * @throws PureCryptoException
     */
    public function deleteRecipients(string $cms, VirgilPublicKeyCollection $publicKeys): string
    {
        try {
            $infoEditor = new MessageInfoEditor();

            $infoEditor->useRandom($this->crypto->getRng());
            $infoEditor->unpack($cms);

            foreach ($publicKeys->getAsArray() as $publicKey) {
                $infoEditor->removeKeyRecipient($publicKey->getIdentifier());
            }

            return $infoEditor->pack();

        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param string $cms
     * @return array
     * @throws PureCryptoException
     */
    public function extractPublicKeysIds(string $cms): array //: TODO!
    {
        try {
            $publicKeysIds = [];

            $messageInfoSerializer = new MessageInfoDerSerializer();
            $messageInfoSerializer->setupDefaults();

            $messageInfo = $messageInfoSerializer->deserialize($cms);
            $keyRecipientInfoList = $messageInfo->keyRecipientInfoList();

            while (!is_null($keyRecipientInfoList) && $keyRecipientInfoList->hasItem()) {
                $keyRecipientInfo = $keyRecipientInfoList->item();
                $publicKeysIds[] = $keyRecipientInfo->recipientId();

                $keyRecipientInfoList = $keyRecipientInfoList->hasNext() ? $keyRecipientInfoList->next() : null;
            }

            return $publicKeysIds;

        } catch (\Exception $exception) {
            throw new PureCryptoException($exception);
        }
    }

    /**
     * @param string $body1
     * @param string $body2
     * @return string
     */
    private function concat(string $body1, string $body2): string
    {
        // TODO!
        return $body1.$body2;
    }
}