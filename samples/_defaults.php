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

printf("Restoring defaults\n");

$defaultsDir = '_defaults'.DIRECTORY_SEPARATOR;

$files = ['user_table.json', 'main_table.json'];
$recoveryPrivateKeyFile = 'recovery_private_key.pem';

if(in_array('--with-env', $argv))
{
    $envExampleFile = '.env.example';
    $envFile = '.env';

    if(!is_file($envExampleFile)) {
        printf("Error: no $envExampleFile file\n");
        exit();
    }

    copy($envExampleFile, $envFile);
    printf("Restoring empty $envFile\n");
}

foreach ($files as $file) {
    if(!is_dir($defaultsDir) || !is_file($defaultsDir.$file)) {
        printf("Error: no default files\n");
        exit();
    }

    copy($defaultsDir.$file, $file);
    printf("Restoring default file ($file)\n");
}

if(is_file($recoveryPrivateKeyFile)) {
    unlink($recoveryPrivateKeyFile);
    printf("Deleting $recoveryPrivateKeyFile\n");
}

printf("Finished.\n");