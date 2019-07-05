# Virgil PureKit PHP SDK
[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-purekit-php.png?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-purekit-php)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/virgil/purekit.svg?style=flat-square)](https://packagist.org/packages/virgil/purekit)
[![Total Downloads](https://img.shields.io/packagist/dt/virgil/purekit.svg?style=flat-square)](https://packagist.org/packages/virgil/purekit)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<img src="https://cdn.virgilsecurity.com/assets/images/github/logos/pure_grey_logo.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a powerful and revolutionary cryptographic technology that provides stronger and more modern security, that secures users' data and reduces the security risks associated with weak passwords.

Virgil PureKit allows developers to interact with the Virgil PHE Service to protect user passwords and sensitive personal identifiable information (PII data) in a database from offline/online attacks and makes stolen passwords/data useless if your database has been compromised. Neither Virgil nor attackers know anything about user passwords/data.

This technology can be used within any database or login system that uses a password, so it’s applicable for a company of any industry or size.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of user passwords
- Passwords & data protection from online attacks
- Passwords & data protection from offline attacks
- Instant invalidation of a stolen database
- User data encryption with a personal key


## Register Your Account
Before working with the SDK and usage examples, make sure that:
- you have a registered Virgil Account at [Virgil Dashboard](https://dashboard.virgilsecurity.com/)
- you've created a PURE Application
- you've obtained your PureKit application's credentials such as: `APP_TOKEN`, `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY`


## Install and Configure PureKit
The PureKit is provided as a package named `virgil/purekit`. The package is distributed via Composer and is available for PHP version 7.2.


### Install the PureKit Package

-  **Step #1.** Add the [crypto extensions](https://github.com/VirgilSecurity/virgil-purekit-php/releases) into your 
server before using the PureKit. Read more [here](#add-the-crypto-extensions-into-your-server-before-using-the-purekit).

- **Step #2.** Install the PureKit library with the following code:
    ```bash
    composer require virgil/purekit
    ```
    
To uninstall Pure, see the [Recover Password Hashes](#recover-password-hashes) section.
    
### Configure PureKit

Configure the PureKit .env file:

```dotenv
APP_TOKEN=
SERVICE_PUBLIC_KEY=
APP_SECRET_KEY=
UPDATE_TOKEN= //must be empty
```

Here is an example of how to specify your credentials Protocol class instance:

```php
use Dotenv\Dotenv;
use Virgil\PureKit\Protocol\Protocol;
use Virgil\PureKit\Protocol\ProtocolContext;

// Add the correct path to .env file!
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
    // Add your custom logic here
    var_dump($e);
    die;
}
```

## Prepare Your Database
PureKit allows you to easily perform all the necessary operations to create, verify, and rotate (update) a user's `PureRecord`.

**Pure Record** - a user's password that is protected with our PureKit technology. Pure `record` contains a version, client & server random salts, and two values obtained during the execution of the PHE protocol.

In order to create and work with a user's Pure `record` you have to set up your database with an additional column.

The column must have the following parameters:
<table class="params">
<thead>
		<tr>
			<th>Parameters</th>
			<th>Type</th>
			<th>Size (bytes)</th>
			<th>Description</th>
		</tr>
</thead>

<tbody>
<tr>
	<td>record</td>
	<td>bytearray</td>
	<td>210</td>
	<td> A unique record, namely a user's protected Pure Record.</td>
</tr>

</tbody>
</table>

### Generate a recovery keypair

This step is __optional__. Use this step if you will need to move away from Pure without having to reregistering your users.

To be able to move away from Pure without having to reregistering your users, you need to generate a recovery keypair (public and private key). The public key will be used to encrypt password hashes at the enrollment step. You will need to store the encrypted hashes in your database.

To generate a recovery keypair, [install the Virgil Crypto Library](https://developer.virgilsecurity.com/docs/how-to/virgil-crypto/install-virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.

> You won’t be able to restore your recovery private key, so it is crucial not to lose it.

```php
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

### Prepare your database for storing encrypted password hashes

Now you need to prepare your database for the future password hash recovery. Create a column in your users table or a separate table for storing encrypted user password hashes.

<table class="params">
<thead>
		<tr>
			<th>Parameters</th>
			<th>Type</th>
			<th>Size (bytes)</th>
			<th>Description</th>
		</tr>
</thead>

<tbody>
<tr>
	<td>encrypted_password_hashes</td>
	<td>bytearray</td>
	<td>512</td>
	<td>User password hash, encrypted with the recovery key.</td>
</tr>
</tbody>
</table>

Further, at the [enrollment step](#enroll-user-record) you'll need to encrypt user password hashes with the generated recovery public key and save them to the `encrypted_password_hashes` column.


## Usage Examples

> You can find a working example for the following commands in [this directory](/samples)

### Enroll a User Record

Use this flow to create a `PureRecord` in your DB for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs into your system to implement PHE technology. You can go through your database and enroll (create) a user's Pure `Record` at any time.

So, in order to create a Pure `Record` for a new or existing database, go through the following operations:
- Take a user's **password** (or its hash or whatever you use) and pass it into the `EnrollAccount` function in the PureKit on your Server side.
- PureKit will send a request to the PureKit service to get enrollment.
- Then, PureKit will create a user's Pure `Record`. You need to store this unique user's Pure `Record` in your database in the associated column.
- (optional) Encrypt your user password hashes with the recovery key generated in [Generate a recovery keypair](#generate-a-recovery-keypair) and save them to your database.

```php
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

When you've created a Pure `record` for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User Record

Use this flow when a user already has his or her own Pure `record` in your database. This function allows you to
verify a user's password with the Pure `record` from your DB every time the user signs in. You have to pass his or her Pure `record` from your DB through the `VerifyPassword` function:

```php
try {
    $encryptionKey = $protocol->verifyPassword($password, $record)); //use encryption key for decrypting user data
}
catch(\Exception $e) {
    // Login error (incorrect password)
}
if($encryptionKey)
    // Login success
```

### Encrypt user data in your database

Not only a user's password is sensitive data. In this flow we will help you protect any personally identifiable information (PII) in your database.

PII is data that could potentially identify a specific individual, and PII is sensitive.
Sensitive PII is information, when disclosed, could result in harm to the individual whose privacy has been breached. Sensitive PII should, therefore, be encrypted in transit and when data is at rest. Such information includes biometric information, medical information, personally identifiable financial information (PIFI), and unique identifiers such as passport or Social Security numbers.

PureKit service allows you to protect a user's PII (personal data) with a user's `encryptionKey` that is obtained from the `EnrollAccount` or `VerifyPassword` functions. The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) the user's
`PureRecord`. The `encryptionKey` will be updated after a user changes their own password.

Here is an example of data encryption/decryption with an `encryptionKey`:

```php
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
    // Add your custom logic here
    var_dump($e);
    die;
}
```
Encryption is performed using AES256-GCM with a key & nonce derived from the user's encryptionKey using HKDF and random 256-bit salt.

Virgil Security has zero knowledge about a user's `encryptionKey`, because the key is calculated every time you execute `EnrollAccount` or `VerifyPassword` functions on your server side.

### Rotate app keys and user PureRecord
There can never be enough security, so you should rotate your sensitive data regularly (about once a week). Use this
flow to get an `UPDATE_TOKEN` for updating a user's `PureRecord` in your database and to get a new `APP_SECRET_KEY`
and `SERVICE_PUBLIC_KEY` of a specific application.

Also, use this flow in the event your database has been COMPROMISED!

> This action doesn't require creating an additional table or to modify the scheme of existing tables. When a user needs to change his or her own password, use the EnrollAccount function to replace a user's oldRecord in your DB with a newRecord.

Here is how it works:

**Step 1.** Get your `UPDATE_TOKEN`

Navigate to the [Virgil Dashboard](https://dashboard.virgilsecurity.com/login), open your pure application panel, and press the "Show update token" button to get the `UPDATE_TOKEN`.

**Step 2.** Initialize PureKit with the `UPDATE_TOKEN`
Move to the PureKit configuration .env file and specify your `UPDATE_TOKEN`:

```dotenv
APP_TOKEN=
SERVICE_PUBLIC_KEY=
APP_SECRET_KEY=
UPDATE_TOKEN= //need to be filled
```

**Step 3.** Start migration. Use the `RecordUpdater::update()` PureKit method to create a user's new Pure `record`
(you don't need to ask your users to create a new password). The `RecordUpdater::update()` method requires the `UPDATE_TOKEN` and user's old Pure `record` from your DB:

```php
use Virgil\PureKit\Protocol\RecordUpdater;

try {
    $recordUpdater = new RecordUpdater($_ENV["UPDATE_TOKEN"]);

    $newRecord = $recordUpdater->update($oldRecord));

    // $newRecord is null ONLY if $oldRecord is already updated
    if ($newRecord !== null)
        // Save new record to the database
}
catch(\Exception $e) {
    // Add your custom logic here
    var_dump($e);
    die;
}
```

Run the `RecordUpdater::update()` method and save the user's new Pure `record` into your database.

Since the PureKit is able to work simultaneously with two versions of user PureRecords (new Pure `record` and old Pure `record`),
this will not affect the backend or users. This means, if a user logs into your system when you do the migration,
the Virgil PureKit will verify the user's password without any problems because PureKit can work with both user Pure Records (new and old).


**Step 4.** Get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application

Use the Virgil CLI `update-keys` command and your `UPDATE_TOKEN` to update the `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY`:

```bash
// FreeBSD / Linux / Mac OS
./virgil pure update-keys <service_public_key> <app_secret_key> <update_token>

// Windows OS
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

**Step 5.** Move to the PureKit configuration .env file and replace your previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` with a new one (`APP_TOKEN` will be the same). Delete the previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` and `UPDATE_TOKEN`.

```dotenv
APP_TOKEN=
SERVICE_PUBLIC_KEY=
APP_SECRET_KEY=
UPDATE_TOKEN= //must be empty
```

### Recover password hashes

Use this step if you're uninstalling Pure. 

Password hash recovery is carried out by decrypting the encrypted users password hashes in your database and replacing the Pure records with them.

In order to recover the original password hashes, you need to prepare your recovery private key. If you don't have a recovery key, then you have to ask your users to go through the registration process again to restore their passwords.

Use your recovery private key to get original password hashes:

```php
$virgilCrypto = new VirgilCrypto();
//iImport key
$privateKeyImported = $virgilCrypto->importPrivateKey($privateKeyExported, $privateKeyPassword);

// decrypt password hashes and save them in database
$decrypted = $virgilCrypto->decrypt($encryptedPasswordHash, $privateKeyImported);
```

Save the decrypted user password hashes into your database. After the recovery process is done, you can delete all the Pure data and the recovery keypair.

## Additional information

### Add the crypto extensions into your server before using the PureKit

- [Download](https://github.com/VirgilSecurity/virgil-purekit-php/releases) *virgil-test.zip*, unzip it and execute it on your server's [virgil-test.php](/_help/virgil-test.php) file.

- [Download](https://github.com/VirgilSecurity/virgil-purekit-php/releases) and unzip *%YOUR_OS%_extensions.zip* archive according to your server operating system and PHP version.

- Make sure you have access to edit the php.ini file (for example, use *root* for Linux/Darwin or run *cmd* as administrator for Windows).
- Copy extension files to the extensions directory.
    - For Linux/Darwin:
    ```
     $ path="%PATH_TO_EXTENSIONS_DIR%" && cp vsce_phe_php.so $path && cp virgil_crypto_php.so $path
    ```
    - For Windows:
    ```
     $ set path=%PATH_TO_EXTENSIONS_DIR% && copy vsce_phe_php.dll %path% && copy virgil_crypto_php.dll %path%
    ```
- Add the extensions into the php.ini file 
    ```
    $ echo -e "extension=vsce_phe_php\nextension=virgil_crypto_php” >> %PATH_TO_PHP.INI%
    ```
    
- Restart your server or php-fpm service

#### Extensions installation example

Our web stack is: *Linux, nginx, php7.2-fpm*

- Execute [virgil-test.php](/_help/virgil-test.php) to find your path to the extensions directory and the path to the php.ini file:
    <p><img src="https://raw.githubusercontent.com/VirgilSecurity/virgil-pure-wordpress/master/_help/s-1.png" 
    width="60%"></p> 

- Then, go to the command line interface (CLI) to specify the paths you've identified in the previous step:
    <p><img src="https://raw.githubusercontent.com/VirgilSecurity/virgil-pure-wordpress/master/_help/s-2.png" 
    width="60%"></p>

- Reload the page in your browser to see that the extension is loaded (`IS_VSCE_PHE_PHP_EXTENSION_LOADED => true` and 
`IS_VIRGIL_CRYPTO_PHP_EXTENSION_LOADED => true`):
    <p><img src="https://raw.githubusercontent.com/VirgilSecurity/virgil-pure-wordpress/master/_help/s-3.png" 
    width="60%"></p>
    

        
## Docs
* [Virgil Dashboard](https://dashboard.virgilsecurity.com)
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol
* [PHP Sample](/samples) - explore our PHP PURE samples to easily run the SDK
* [PURE use-case](https://developer.virgilsecurity.com/docs/use-cases/v1/passwords-and-data-protection) - explore our
 use-case to protect user passwords and data in your database from data breaches

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email: support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
