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

use Virgil\PureKit\Pure\Util\ValidationUtils;

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
    private $recordVersion;
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
    private $backupPwdHash;
    /**
     * @var string
     */
    private $passwordRecoveryWrap;
    /**
     * @var string
     */
    private $passwordRecoveryBlob;

    /**
     * UserRecord constructor.
     * @param string $userId
     * @param string $pheRecord
     * @param int $recordVersion
     * @param string $upk
     * @param string $encryptedUsk
     * @param string $encryptedUskBackup
     * @param string $backupPwdHash
     * @param string $passwordRecoveryWrap
     * @param string $passwordRecoveryBlob
     * @throws \Virgil\PureKit\Pure\Exception\EmptyArgumentException
     * @throws \Virgil\PureKit\Pure\Exception\IllegalStateException
     * @throws \Virgil\PureKit\Pure\Exception\NullArgumentException
     */
    public function __construct(string $userId, string $pheRecord, int $recordVersion, string $upk,
                                string $encryptedUsk, string $encryptedUskBackup, string $backupPwdHash,
                                string $passwordRecoveryWrap, string $passwordRecoveryBlob)
    {
        ValidationUtils::checkNullOrEmpty($userId, "userId");
        ValidationUtils::checkNullOrEmpty($pheRecord, "pheRecord");
        ValidationUtils::checkNullOrEmpty($upk, "upk");
        ValidationUtils::checkNullOrEmpty($encryptedUsk, "encryptedUsk");
        ValidationUtils::checkNullOrEmpty($encryptedUskBackup, "encryptedUskBackup");
        ValidationUtils::checkNullOrEmpty($backupPwdHash, "backupPwdHash");
        ValidationUtils::checkNullOrEmpty($passwordRecoveryWrap, "passwordRecoveryWrap");
        ValidationUtils::checkNullOrEmpty($passwordRecoveryBlob, "passwordRecoveryBlob");

        $this->userId = $userId;
        $this->pheRecord = $pheRecord;
        $this->recordVersion = $recordVersion;
        $this->upk = $upk;
        $this->encryptedUsk = $encryptedUsk;
        $this->encryptedUskBackup = $encryptedUskBackup;
        $this->backupPwdHash = $backupPwdHash;
        $this->passwordRecoveryWrap = $passwordRecoveryWrap;
        $this->passwordRecoveryBlob = $passwordRecoveryBlob;
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
    public function getRecordVersion(): int
    {
        return $this->recordVersion;
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
    public function getBackupPwdHash(): string
    {
        return $this->backupPwdHash;
    }

    /**
     * @return string
     */
    public function getPasswordRecoveryWrap(): string
    {
        return $this->passwordRecoveryWrap;
    }

    /**
     * @return string
     */
    public function getPasswordRecoveryBlob(): string
    {
        return $this->passwordRecoveryBlob;
    }
}