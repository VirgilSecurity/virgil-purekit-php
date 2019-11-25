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

use Virgil\PureKit\Core\Protobuf\DatabaseRecord;
use Virgil\PureKit\Credentials\UpdateToken;
use Virgil\PureKit\Exceptions\RecordUpdaterException;
use VirgilCrypto\Phe\PheClient;

/**
 *
 * RecordUpdater increments record version and updates it using provided update token
 *
 * Class RecordUpdater
 * @package Virgil\PureKit\Protocol
 */
class RecordUpdater
{
    private $pheClient;
    private $updateToken;
    private $version;

    /**
     * RecordUpdater constructor.
     * @param string $updateToken
     * @throws \Virgil\PureKit\Exceptions\UpdateTokenException
     */
    public function __construct(string $updateToken)
    {
        $this->pheClient = new PheClient();
        $this->pheClient->setupDefaults();
        $this->updateToken = new UpdateToken($updateToken);
    }

    /**
     * @param string $record
     * @return null|string
     * @throws RecordUpdaterException
     * @throws \Virgil\PureKit\Exceptions\ProtocolContextException
     */
    public function update(string $record)
    {
        if(true==$this->validate($record)) {

            $r = DatabaseRecord::getValue($record, "record");

            $updatedRecord = $this->pheClient->updateEnrollmentRecord($r, $this->updateToken->getValue());
            $res = DatabaseRecord::setup($updatedRecord, $this->getVersion());
        }
        else {
            $res = null;
        }

        return $res;
    }

    /**
     * @param string $record
     * @return bool
     * @throws RecordUpdaterException
     * @throws \Virgil\PureKit\Exceptions\ProtocolContextException
     */
    private function validate(string $record): bool
    {
        $recordVersion = (int) DatabaseRecord::getValue($record, "version");
        $utVersion = (int) $this->updateToken->getVersion();
        $this->version = $utVersion;

        if(($utVersion-$recordVersion) > 1 || $recordVersion > $utVersion)
            throw new RecordUpdaterException("Invalid version of updateToken($utVersion) or record($recordVersion)");

        if($utVersion==$recordVersion)
            $res = false;

        if($utVersion==$recordVersion + 1)
            $res = true;

        return $res;
    }

    /**
     * @return int
     */
    private function getVersion(): int
    {
        return $this->version;
    }
}