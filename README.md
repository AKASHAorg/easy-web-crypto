# Web-crypto

[![Build Status](https://travis-ci.org/deiu/web-crypto.svg?branch=master)](https://travis-ci.org/deiu/web-crypto)

This is a wrapper around the Webcrypto API available in modern browsers. It enables faster
development of applications that require storing encrypted data.

## Usage

### genAESKey

Generate an AES key for encryption. By default this key can be exported. It supports the
following parameters: `extractable` (defaults to true), `mode` (defaults to AES-GCM), and
`keySize` (defaults to 128).


```js
const WebCrypto = require('web-crypto')

// genAESKey(extractable, mode = 'AES-GCM', keySize = 128)
const key = await WebCrypto.genAESKey()
```

### encrypt:

Encrypt a string|Object using an AES key.

```js
const data = { foo: 'bar' }

// using the key generated above
const encrypted = await WebCrypto.encrypt(key, data)
```

### decrypt:

```js
const val = await WebCrypto.decrypt(key, encrypted)
console.log(val) // { foo: 'bar' }
```

### encryptBuffer:

Encrypt an ArrayBuffer using an AES key.

```js
const buffer = new ArrayBuffer(8)

// using the key generated above
const encrypted = WebCrypto.encryptBuffer(key, buffer)
```

### decryptBuffer:

```js
WebCrypto.decryptBuffer(key, encrypted).then(val => console.log(val)) // ArrayBuffer {}
```

### exportKey:

Export an AES key into a raw|jwk key (defaults to raw) that can be stored.

```js
const exported = WebCrypto.exportKey(key)
```

### importKey:

Imports an AES key. It accepts the following parameters `key` (exported key), `type` (defaults
to raw), `mode` (defaults to AES-GCM).

```js
// importKey(key, type = 'raw', mode = 'AES-GCM')
const key = WebCrypto.importKey(key)

// use this AES key now to encrypt/decrypt as above
```


### genEncryptedMasterKey:

Uses PBKDF2 to derive a Key Encryption Key from a passphrase, in order to generate an encrypted
AES symmetric key that can be safely stored. It accepts the following parameters: `passPhrase`,
`salt` (defaults to a random ArrayBuffer(16)), `iterations` (defaults to 10000), `hashAlgo`
(defaults to SHA-256).

Please make sure you use a sufficiently secure passphrase as well as a minimum of 10000 iterations!

```js
// genEncryptedMasterKey(passPhrase, salt = genRandomBuffer(16), iterations = 100000, hashAlgo = 'SHA-256')
const passphrase = 'your super secure passphrase'

const encMasterKey = await WebCrypto.genEncryptedMasterKey(passphrase)

// you can now safely store the encMasterKey for future use
```

### decryptMasterKey:

Decrypt a master key by deriving the encryption key from the provided passphrase and encrypted
master key.

```js
// use the values from genEncryptedMasterKey example
const key = await WebCrypto.decryptMasterKey(passphrase, encMasterKey)

// use this AES key now to encrypt/decrypt your data
```


### updatePassphraseKey:

Update the derived key encryption key (KEK) based on the new passphrase from user.

Please note that the actual AES key used for encryption does not change, so you can still
decrypt previously encrypted data. Only the passphrase changed!

```js
// use the values from genEncryptedMasterKey example + the new passphrase
const newPassphrase = 'something different from the last passphrase'

// updatePassphraseKey(oldassphrase, newPassphrase, oldEncryptedMasterKey)
const updatedEncMK = await WebCrypto.updatePassphraseKey(passphrase, newPassphrase, encMasterKey)

// you can now safely store the updatedEncMK for future use
```

That's it!


## Full example

```js
const passphrase = 'your super secure passphrase'

// derive a new key from passphrase and generate the master AES key
const encMasterKey = await WebCrypto.genEncryptedMasterKey(passphrase)

// decrypt the AES key
let key = await WebCrypto.decryptMasterKey(passphrase, encMasterKey)

// encrypt some data
const data = { foo: 'bar' }

// using the key generated above
const encrypted = await WebCrypto.encrypt(key, data)

// decrypt the data
let val = await WebCrypto.decrypt(key, encrypted)
console.log(val) // { foo: 'bar' }

// change passphrase
const newPassphrase = 'something different from the last passphrase'

// updatePassphraseKey(oldassphrase, newPassphrase, oldEncryptedMasterKey)
const updatedEncMK = await WebCrypto.updatePassphraseKey(passphrase, newPassphrase, encMasterKey)

// decrypt new master key
key = await WebCrypto.decryptMasterKey(newPassphrase, updatedEncMK)

// decrypt the previous data
val = await WebCrypto.decrypt(key, encrypted)
console.log(val) // { foo: 'bar' }
```


## Installing

### Via npm

```sh
npm install git+https://github.com/deiu/web-crypto#master
```

### Via `<script>` tag

* `dist/web-WebCrypto.js` can be directly used in browsers.
