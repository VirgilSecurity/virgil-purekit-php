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

namespace Virgil\PureKit\Pure\Exception\Enum;

use MyCLabs\Enum\Enum;

class ErrorStatus extends Enum
{
    private const USER_NOT_FOUND_IN_STORAGE = [0, "User has not been found in the storage"];
    private const CELL_KEY_NOT_FOUND_IN_STORAGE = [1, "Cell key has not been found in the storage"];
    private const CELL_KEY_ALREADY_EXISTS_IN_STORAGE = [2, "Cell key already exists in the storage"];
    private const STORAGE_SIGNATURE_VERIFICATION_FAILED = [3, "Storage signature verification has been failed"];
    private const KEYS_VERSION_MISMATCH = [4, "Keys version mismatch"];
    private const UPDATE_TOKEN_VERSION_MISMATCH = [5, "Update token version mismatch"];
    private const NONROTABLE_MASTER_SECRET_INVALID_LENGTH = [6, "Nonrotatable master secret invalid length"];
    private const CREDENTIALS_PARSING_ERROR = [7, "Credentials parsing error"];
    private const USER_ID_MISMATCH = [8, "User Id mismatch"];
    private const KEY_ID_MISMATCH = [9, "Key id mismatch"];
    private const PHE_VERSION_MISMATCH = [10, "PHE version mismatch"];
    private const ROLE_NAME_MISMATCH = [11, "Role name mismatch"];
    private const ROLE_USER_ID_MISMATCH = [12, "Role user id mismatch"];
    private const ROLE_NAME_USER_ID_MISMATCH = [13, "Role name and user id mismatch"];
    private const DUPLICATE_USER_ID = [14, "Duplicate user Id"];
    private const INVALID_PASSWORD = [15, "Invalid password"];
    private const USER_HAS_NO_ACCESS_TO_DATA = [16, "User has no access to data"];
    private const DUPLICATE_ROLE_NAME = [17, "Duplicate role name"];
    private const UPDATE_TOKENS_MISMATCH = [18, "KMS and PHE rotation should be simultaneous"];

    public function getCode(): int
    {
        return $this->getValue()[0];
    }

    public function getMessage(): string
    {
        return $this->getValue()[1];
    }
}