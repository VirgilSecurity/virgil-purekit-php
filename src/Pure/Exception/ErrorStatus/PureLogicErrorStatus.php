<?php
/**
 * Copyright (c) 2015-2024 Virgil Security Inc.
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

namespace Virgil\PureKit\Pure\Exception\ErrorStatus;

/**
 * @method static NONROTABLE_MASTER_SECRET_INVALID_LENGTH()
 * @method static INVALID_PASSWORD()
 * @method static GRANT_INVALID_PROTOBUF()
 * @method static GRANT_IS_EXPIRED()
 * @method static USER_HAS_NO_ACCESS_TO_DATA()
 * @method static KEYS_VERSION_MISMATCH()
 * @method static CREDENTIALS_PARSING_ERROR()
 * @method static UPDATE_TOKEN_VERSION_MISMATCH()
 */
class PureLogicErrorStatus extends BaseErrorStatus
{
    private const array KEYS_VERSION_MISMATCH = [1, "Keys version mismatch"];
    private const array UPDATE_TOKEN_VERSION_MISMATCH = [2, "Update token version mismatch"];
    private const array NONROTABLE_MASTER_SECRET_INVALID_LENGTH = [3, "Nonrotatable master secret invalid length"];
    private const array CREDENTIALS_PARSING_ERROR = [4, "Credentials parsing error"];
    private const array INVALID_PASSWORD = [5, "Invalid password"];
    private const array USER_HAS_NO_ACCESS_TO_DATA = [6, "User has no access to data"];
    private const array GRANT_INVALID_PROTOBUF = [7, "Grant invalid protobuf"];
    private const array GRANT_IS_EXPIRED = [8, "Grant is expired"];
    private const array PASSWORD_RECOVER_REQUEST_THROTTLED = [9, "Password recover request was throttled"];
}
