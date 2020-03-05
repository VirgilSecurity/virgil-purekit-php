
# Virgil PureKit PHP

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-purekit-go.png?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-purekit-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

<a href="https://developer.virgilsecurity.com"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/purekit/PureKit.png" align="left" hspace="1" vspace="3"></a>

## Introduction
[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a powerful and revolutionary cryptographic technology that provides stronger and more modern security, that secures users' data and lessens the security risks associated with weak passwords.

Virgil PureKit allows developers interacts with Virgil PHE Service to protect users' passwords and sensitive personal identifiable information (PII data) in a database from offline/online attacks and makes stolen passwords/data useless if your database has been compromised. Neither Virgil nor attackers know anything about users' passwords/data.

This technology can be used within any database or login system that uses a password, so it’s accessible for a company of any industry or size.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of users' passwords
- Passwords & data protection from online attacks
- Passwords & data protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key

## Content
- [Introduction](#introduction)
- [Features](#features)
- [Install and configure PureKit](#install-and-configure-purekit)
- [Usage Examples](#usage-examples)
  - [Generate user's Pure Record](#generate-users-pure-record)
  - [Verify user's password](#verify-users-password)
  - [Change user's password](#change-users-password)
  - [Data encryption & decryption](#data-encryption--decryption)
  - [Re-encrypt data when password is changed](#re-encrypt-data-when-password-is-changed)
  - [Rotate Keys and Records](#rotate-keys-and-records)
  - [Uninstall PureKit](#uninstall-purekit)
- [Docs](#docs)
- [License](#license)
- [Support](#support)

## Install and configure PureKit

This guide is the first step to adding password-hardened encryption to your database. Here you can learn how to set up PureKit at your backend to protect your users's passwords and data.

For more details about password-hardened encryption (PHE), take a look at our overview [here](https://developer.virgilsecurity.com/docs/purekit/fundamentals/password-hardened-encryption/).

### Install PureKit package

Use your package manager to download PureKit into your backend.

The Passw0rd PHP SDK is provided as a package named virgil/purekit. The package is distributed via Composer. The package is available for PHP 7.2 or newer.

Add the "vsce_phe_php" extension before using the SDK:

1. Download the virgil-crypto-c-{latest version} archive from the CDN: https://cdn.virgilsecurity.com/virgil-crypto-c/php/.

2. Place the "vsce_phe_php.so" file from the archive (/lib folder) into the directory with extensions

3. Add the "extension=vsce_phe_php" string in to the php.ini file

4. Restart your web-service (apache or nginx): sudo service {apache2 / nginx} restart

Tips: PHP version: phpversion() / php --version OS Version: PHP_OS php.ini and extensions directory: phpinfo() / php -i / php-config --extension_dir

Also, you can launch the "extension/helper.php" file to get information about a version and extensions.

Now, install PureKit SDK library with the following code:

```PHP
composer require virgil/purekit
```



### Configure PureKit
Navigate to [Virgil Dashboard](https://dashboard.virgilsecurity.com), create a new Pure application and configure PureKit framework with your application credentials:

```PHP

use Dotenv\Dotenv;
use Virgil\PureKit\Protocol\Protocol;
use Virgil\PureKit\Protocol\ProtocolContext;

// setup SDK configuration .env file with the following variables:
// APP_TOKEN=
// SERVICE_PUBLIC_KEY=
// APP_SECRET_KEY=
// UPDATE_TOKEN= //must be empty

// Add correct path to .env file!
(new Dotenv("{PATH_TO_FILE}"))->load();

try {
    $context = (new ProtocolContext)->create([
        'appToken' => $_ENV['APP_TOKEN'],
        'appSecretKey' => $_ENV['APP_SECRET_KEY'],
        'servicePublicKey' => $_ENV['SERVICE_PUBLIC_KEY'],
        'updateToken' => $_ENV['UPDATE_TOKEN']
    ]);

    $protocol = new Protocol($context);
}
catch(\Exception $e) {
    // add your custom logic here
    var_dump($e);
    die;
}
```


#### Prepare your database

A **Pure record** is a user password that is protected with our PureKit technology. A Pure Record contains the version, client & server random salts, and two values obtained during the execution of the PHE protocol.

In order to create and work with a user's `record`, you need to add an additional column to your database table.

The column must have the following parameters:

|Parameters|Type|Size (bytes)|Description|
|--- |--- |--- |--- |
|record|bytearray|210|A unique Pure record, namely a user's protected password.|

#### Generate a recovery key pair (optional)

To be able to move away from Pure without having to put your users through registering again, or just to be able to recover data that your users may lose, you need to make a backup of your database, generate a recovery key pair and encrypt your backup with the recovery public key. The public key will be used to encrypt the database at the enrollment step.

To generate a recovery keypair, [install Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.

> **Warning!** You won’t be able to restore your recovery private key, so it is crucial not to lose it.

```PHP
use Virgil\CryptoImpl\VirgilCrypto;
// generate keypair:
$virgilCrypto = new VirgilCrypto();
$keyPair = $virgilCrypto->generateKeys();

$privateKey = $keyPair->getPrivateKey();
$publicKey = $keyPair->getPublicKey();

// store exported keys:
$privateKeyExported = $virgilCrypto->exportPrivateKey($privateKey);
$publicKeyExported = $virgilCrypto->exportPublicKey($publicKey);
```
## Usage Examples

### Generate user's Pure Record

To create a Pure `record` for a database:
- Take the user's **password** (or hash) and pass it into the `EnrollAccount` function.
- Store this user's unique `record` in your database.

The enrollment snippet below also provides an example on how to protect user personal data with `encryptionKey` and encrypt user password hashes with `recoveryPublicKey`.

> Warning! If you need to update your user's Pure Records, for instance, if your database is COMPROMISED, take the immediate steps according to [this guide](#rotate-keys-and-records).


```PHP
try {
    $enroll = $protocol->enrollAccount($password); // [record, encryption key]
    $record = $enroll[0]; //save Pure Record to database
    $encryptionKey = $enroll[1]; //use encryption key for protecting user data

    //use encryptionKey for protecting user data
    $cipher = new PHE();
    $encryptedUserData = $cipher->encrypt($data, $encryptionKey);

    //(optional) use the generated recovery public key to encrypt a user password hash
    //save encryptedPasswordHash into your database
    $encryptedPasswordHash = $virgilCrypto->encrypt($password, $recoveryPublicKey);
}
catch(\Exception $e) {
    // Add your custom logic here
    var_dump($e);
    die;
}
```

> **Note!** If you have a database with user passwords, you don't have to wait until they log in. You can go through your database and enroll (create) a user's Pure Record at any time.

### Verify user's password

After a user has their Pure Record, you can authenticate the user by verifying their password using the `VerifyPassword` function:

```PHP

try {
    $encryptionKey = $protocol->verifyPassword($password, $record)); //use encryption key for decrypting user data
}
catch(\Exception $e) {
    // login error (incorrect password)
}
if($encryptionKey)
    // login success
```

### Change user's password

Use this flow when a user wants to change their password.

> **Warning!** If you use PureKit not only for hardening passwords, but also for encrypting user's data, you'll have to re-encrypt user's data with the new key so that the user doesn't lose access to it. Navigate to [this guide](#re-encrypt-data-when-password-is-changed) and follow the instructions there.

If you're using PureKit only for encrypting passwords, then you have to simply create a new Pure Record using the new password for the user, and replace the old Pure Record with the new one.


### Data encryption & decryption

The PHE service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from the `enrollAccount` or `verifyPassword` functions. The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) a user's Pure Record. The `encryptionKey` will be updated after a user changes their own password.

> Virgil Security has zero knowledge about a user's `encryptionKey`, because the key is calculated every time you execute the `enrollAccount` or `verifyPassword` functions on your server side.

> Encryption is performed using AES256-GCM with key & nonce derived from the user's encryptionKey using HKDF and the random 256-bit salt.

Here is an example of data encryption/decryption with an `encryptionKey`:

```PHP
use Virgil\PureKit\Core\PHE;

try {
    //key is obtained from protocol->enrollAccount() or protocol->verifyPassword() calls
    $data = "Personal data";

    $phe = new PHE();
    $cipherText = $phe->encrypt($data, $encryptionKey);
    $decrypted = $phe->decrypt($cipherText, $encryptionKey);

    // var_dump($decrypted);
}
catch(\Exception $e) {
    // add your custom logic here
    var_dump($e);
    die;
}
```

### Re-encrypt data when password is changed

Use this flow when a user wants to change their password and maintain access to their data.

When Pure Record for the user is created for the very first time, generate a new key (let's call it `User Key`) and store it in your database.

**1. Prepare database**. Create a new column in your database for storing `User Keys`.

|Parameters|Type|Size (bytes)|Description|
|--- |--- |--- |--- |
|Ecnrypted User Key|bytearray|210|A unique key for user's data encryption.|

**2. Obtain Pure Record key**. When the Pure Record is created for the very first time, you need to obtain the `encryptionKey` from the `enrollAccount` function (see the [Generate User's Pure Record](#generate-users-pure-record) section).

**3. Generate User key**. To generate a `User Key`, [install Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.

**4. Encrypt and store User key**. Encrypt the `User Key` with the `encryptionKey` and save the `Encrypted User Key` at your database.

**5. Encrypt data with User key**. Whenever the user needs to encrypt their data, decrypt the `Encrypted User Key` with the `encryptionKey` and use the decrypted `User Key` instead of the `encryptionKey` for encrypting user's data.

**6. Change user's password**. To change the password, user enters their old password to authenticate at backend, and the new password. Use their new password to create a new Pure Record for the user.

During the password change, decrypt the `Encrypted User Key` with the old `encryptionKey` and encrypt the `User Key` with the new `encryptionKey` you get from `enrollAccount` using the new password. This will allow the user to access their data without re-encrypting all of it.

After that, you can delete the old Pure Record from your database and save the new one instead.

### Rotate Keys and Records

This guide shows how to rotate PureKit-related keys and update Pure Records. There can never be enough security, so you should rotate your sensitive data regularly (about once a week).

**Also, use this flow in case your database has been COMPROMISED!**

Use this workflow to get an `update_token` for updating user's Pure Record in your database and to get a new `app_secret_key` and `service_public_key` for your application.

> **Note!** When a user just needs to change their password, use the `EnrollAccount` function (see the *Password Encryption* step) to replace the user's old `record` value in your DB with a new `record`.

Learn more about Pure Records and keys rotation as a part of Post-Compromise Security in [this guide](https://developer.virgilsecurity.com/docs/purekit/fundamentals/post-compromise-security/).

**1. Get your update token**. Navigate to your Application panel at [Virgil Dashboard](https://dashboard.virgilsecurity.com/) and, after pressing "BEGIN ROTATION PROCESS" press “SHOW UPDATE TOKEN” button to get the `update_token`.

**2. Initialize PureKit with the update token**. Move to PureKit configuration file and specify your `update_token`:

```PHP
// setup configuration .env file
APP_TOKEN=
SERVICE_PUBLIC_KEY=
APP_SECRET_KEY=
UPDATE_TOKEN= //need to be filled
```

**3. Start migration**. Run the `update` method of the `RecordUpdater` class to create a new user `record` and save user's new `record` into your database.

```PHP
use Virgil\PureKit\Protocol\RecordUpdater;

try {
    $recordUpdater = new RecordUpdater($_ENV["UPDATE_TOKEN"]);

    $newRecord = $recordUpdater->update($oldRecord));

    // $newRecord is null ONLY if $oldRecord is already updated
    if ($newRecord !== null)
        // Save new record to the database
}
catch(\Exception $e) {
    // add your custom logic here
    var_dump($e);
    die;
}
```

> **Note!** You don't need to ask your users for a new password.

> **Note!** The SDK is able to work with two versions of a user's `record` (old and new). This means, if a user logs into your system when you do the migration, the PureKit SDK will verify their password without any problems.

**4. Download Virgil CLI**. After you updated your database records, it's required to update (rotate) your application credentials. For security reasons, you need to use the [Virgil CLI utility](https://github.com/VirgilSecurity/virgil-cli).

**5. Rotate App Secret key**. Use Virgil CLI `update-keys` command and your `update_token` to update the `app_secret_key` and `service_public_key`:

```go
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

**6. Configure PureKit SDK with new credentials**. Move to PureKit SDK configuration and replace your previous `app_secret_key`, `service_public_key` with a new one (same for the `app_token`). Delete `update_token` and previous `app_secret_key`, `service_public_key`.

```PHP
// setup configuration .env file with new values
APP_TOKEN=
SERVICE_PUBLIC_KEY=
APP_SECRET_KEY=
UPDATE_TOKEN= //must be empty
```

### Uninstall PureKit

Use this workflow to move away from Pure without having to put your users through registering again. This can be carried out by decrypting the encrypted database backup (users password hashes included) and replacing the encrypted data with it.

**1. Prepare your recovery key**. In order to recover the original password hashes, you need to prepare your recovery private key.

> If you don't have a recovery key, then you have to ask your users to go through the registration process again to restore their passwords.

**2. Decrypt encrypted password hashes**. Now use your recovery private key to get original password hashes:

```PHP
$virgilCrypto = new VirgilCrypto();
//iImport key
$privateKeyImported = $virgilCrypto->importPrivateKey($privateKeyExported, $privateKeyPassword);

// decrypt password hashes and save them in database
$decrypted = $virgilCrypto->decrypt($encryptedPasswordHash, $privateKeyImported);
```

Save the decrypted users password hashes into your database.
After the recovery process is done, you can delete all the Pure data and the recovery keypair.


## Docs

* [Virgil Dashboard](https://dashboard.virgilsecurity.com/)
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol
* [PureKit documentation](https://developer.virgilsecurity.com/docs/use-cases/v1/passwords-and-data-protection) - explore our use-case to protect user passwords and data in your database from data breaches

## License

This library is released under the [3-clause BSD License](https://github.com/VirgilSecurity/virgil-purekit-go/blob/v2/LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
