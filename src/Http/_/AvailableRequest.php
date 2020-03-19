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

namespace Virgil\PureKit\Http\_;

use MyCLabs\Enum\Enum;

/**
 * Class AvailableRequest
 * @package Virgil\PureKit\Http\_
 */
class AvailableRequest extends Enum
{
    private const GET = "GET";
    private const POST = "POST";
    private const PUT = "PUT";
    private const DELETE = "DELETE";

    // PHE
    private const ENROLL = ["/enroll", self::POST];
    private const VERIFY_PASSWORD = ["/verify-password", self::POST];

    // PURE
    private const INSERT_USER = ["/insert-user", self::POST];
    private const UPDATE_USER = ["/update-user", self::POST];
    private const GET_USER = ["/get-user", self::POST];
    private const GET_USERS = ["/get-users", self::POST];
    private const DELETE_USER = ["/delete-user", self::POST];
    private const INSERT_CELL_KEY = ["/insert-cell-key", self::POST];
    private const UPDATE_CELL_KEY = ["/update-cell-key", self::POST];
    private const GET_CELL_KEY = ["/get-cell-key", self::POST];
    private const DELETE_CELL_KEY = ["/delete-cell-key", self::POST];
    private const INSERT_ROLE = ["/insert-roles", self::POST];
    private const GET_ROLES = ["/get-roles", self::POST];
    private const INSERT_ROLE_ASSIGNMENTS = ["/insert-role-assignments", self::POST];
    private const GET_ROLE_ASSIGNMENTS = ["/get-role-assignments", self::POST];
    private const GET_ROLE_ASSIGNMENT = ["/get-role-assignment", self::POST];
    private const DELETE_ROLE_ASSIGNMENTS = ["/delete-role-assignments", self::POST];
    private const INSERT_GRANT_KEY = ["/insert-grant-key", self::POST];
    private const GET_GRANT_KEY = ["/get-grant-key", self::POST];
    private const DELETE_GRANT_KEY = ["/delete-grant-key", self::POST];
    private const DELETE_ROLE = ["/delete-role", self::POST];

    // KMS
    private const DECRYPT_REQUEST = ["/decrypt", self::POST];

    /**
     * @return string
     */
    public function getEndpoint(): string
    {
        return $this->getValue()[0];
    }

    /**
     * @return string
     */
    public function getMethod(): string
    {
        return $this->getValue()[1];
    }
}