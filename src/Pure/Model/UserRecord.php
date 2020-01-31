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

namespace Virgil\PureKit\Pure\Model;

/**
 * Class UserRecord
 * @package Virgil\PureKit\Pure\model
 */
class UserRecord
{
    /**
     * @var string
     */
    private $userId;
    /**
     * @var string
     */
    private $pheRecord;
    /**
     * @var int
     */
    private $pheRecordVersion;
    /**
     * @var string
     */
    private $upk;
    /**
     * @var string
     */
    private $encryptedUsk;
    /**
     * @var string
     */
    private $encryptedUskBackup;
    /**
     * @var string
     */
    private $encryptedPwdHash;
    /**
     * @var string
     */
    private $passwordResetWrap;
    /**
     * @var string
     */
    private $passwordResetBlob;

    /**
     * UserRecord constructor.
     * @param string $userId
     * @param string $pheRecord
     * @param int $pheRecordVersion
     * @param string $upk
     * @param string $encryptedUsk
     * @param string $encryptedUskBackup
     * @param string $encryptedPwdHash
     * @param string $passwordResetWrap
     * @param string $passwordResetBlob
     */
    public function __construct(string $userId, string $pheRecord, int $pheRecordVersion, string $upk,
                                string $encryptedUsk, string $encryptedUskBackup, string $encryptedPwdHash,
                                string $passwordResetWrap, string $passwordResetBlob)
    {
        $this->userId = $userId;
        $this->pheRecord = $pheRecord;
        $this->pheRecordVersion = $pheRecordVersion;
        $this->upk = $upk;
        $this->encryptedUsk = $encryptedUsk;
        $this->encryptedUskBackup = $encryptedUskBackup;
        $this->encryptedPwdHash = $encryptedPwdHash;
        $this->passwordResetWrap = $passwordResetWrap;
        $this->passwordResetBlob = $passwordResetBlob;
    }

    /**
     * Return user id.
     *
     * @return string
     */
    public function getUserId(): string
    {
        return $this->userId;
    }

    /**
     * Returns phe record.
     *
     * @return string
     */
    public function getPheRecord(): string
    {
        return $this->pheRecord;
    }

    /**
     * Returns phe record version.
     *
     * @return int
     */
    public function getPheRecordVersion(): int
    {
        return $this->pheRecordVersion;
    }

    /**
     * Returns user public key.
     *
     * @return string
     */
    public function getUpk(): string
    {
        return $this->upk;
    }

    /**
     * Returns encrypted user secret key.
     *
     * @return string
     */
    public function getEncryptedUsk(): string
    {
        return $this->encryptedUsk;
    }

    /**
     * Return encrypted for backup user secret key.
     *
     * @return string
     */
    public function getEncryptedUskBackup(): string
    {
        return $this->encryptedUskBackup;
    }

    /**
     * Returns encrypted for backup user password hash.
     *
     * @return string
     */
    public function getEncryptedPwdHash(): string
    {
        return $this->encryptedPwdHash;
    }

    /**
     * @return string
     */
    public function getPasswordResetWrap(): string
    {
        return $this->passwordResetWrap;
    }

    /**
     * @return string
     */
    public function getPasswordResetBlob(): string
    {
        return $this->passwordResetBlob;
    }
}