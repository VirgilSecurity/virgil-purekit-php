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

namespace Virgil\PureKit\Pure\Exception\ErrorStatus;

class PureStorageGenericErrorStatus extends BaseErrorStatus
{
    private const USER_NOT_FOUND = [1, "User has not been found in the storage"];
    private const STORAGE_SIGNATURE_VERIFICATION_FAILED = [2, "Storage signature verification has been failed"];
    private const USER_ID_MISMATCH = [3, "User Id mismatch"];
    private const CELL_KEY_ID_MISMATCH = [4, "Cell key id mismatch"];
    private const RECORD_VERSION_MISMATCH = [5, "Record version mismatch"];
    private const ROLE_NAME_MISMATCH = [6, "Role name mismatch"];
    private const ROLE_USER_ID_MISMATCH = [7, "Role user id mismatch"];
    private const ROLE_NAME_USER_ID_MISMATCH = [8, "Role name and user id mismatch"];
    private const USER_COUNT_MISMATCH = [9, "User count mismatch"];
    private const DUPLICATE_ROLE_NAME = [10, "Duplicate role name"];
    private const GRANT_KEY_NOT_FOUND = [11, "Grant key has not been found in the storage"];
    private const GRANT_KEY_ID_MISMATCH = [12, "Grant key id mismatch"];
    private const INVALID_PROTOBUF = [13, "Invalid protobuf"];
    private const SIGNING_EXCEPTION = [14, "Signing exception"];
    private const VERIFICATION_EXCEPTION = [15, "Verification exception"];
    private const KEY_ID_MISMATCH = [16, "Key id mismatch"];
    private const ROLE_NOT_FOUND = [17, "Role not found"];
    private const ROLE_ASSIGNMENT_NOT_FOUND = [18, "Role assignment not found"];
    private const USER_ALREADY_EXISTS = [19, "User already exists"];
    private const ROLE_ALREADY_EXISTS = [20, "Role already exists"];
    private const ROLE_ASSIGNMENT_ALREADY_EXISTS = [21, "Role assignment already exists"];
    private const GRANT_KEY_ALREADY_EXISTS = [22, "Grant key already exists"];
}