# Easy-web-crypto

[![Build Status](https://api.travis-ci.org/AKASHAorg/easy-web-crypto.svg?branch=master)](https://travis-ci.org/AKASHAorg/easy-web-crypto)

This is a wrapper around the Webcrypto API available in modern browsers. It enables fast
development of applications that require storing as well as signing and verifying data.
It is well tested and it comes with no external dependencies.

# Usage

## ECDA public key

### genKeyPair

Generates an ECDA key pair for signing and verifying. By default this key can be exported.
It supports the following optional parameters: `extractable` (defaults to true), `namedCurve`
that accepts `P-256`, `P-384`, and `P-521` (defaults to `P-256`).

```js
const WebCrypto = require('easy-web-crypto')

// generate an ECDA P-256 key pair
const keyPair = await WebCrypto.genKeyPair()
```

### exportPublicKey

Export a public key using base64 format by default. `ArrayBuffer` is also supported by passing
an optional format parameter with the value`raw`.

```js
const keyPair = await WebCrypto.genKeyPair()
const exportedPub = await WebCrypto.exportPublicKey(keyPair.publicKey)
// console.log(exported) -> MFkwEwYHKoZ ... UmUXN7Q27txQ==

// to export using raw format
const exportedPub = await WebCrypto.exportPublicKey(keyPair.publicKey, 'raw')
```

### exportPrivateKey

Export a prvate key using base64 format by default. `ArrayBuffer` is also supported by passing
an optional format parameter with the value`raw`.

```js
const keyPair = await WebCrypto.genKeyPair()
const exportedPriv = await WebCrypto.exportPrivateKey(keyPair.privateKey)
// console.log(exported) -> MFkwEwYHKoZ ... UmUXN7Q27txQ==

// to export using raw format
const exportedPriv = await WebCrypto.exportPrivateKey(keyPair.privateKey, 'raw')
```

### importPublicKey

Import a public key using the base64 format by default. It supports the following optional parameters: `namedCurve` that accepts `P-256`, `P-384`, and `P-521` (defaults to `P-256`),
`format` that can be `base64`, `hex`, and `raw` for ArrayBuffer (defaults to `base64`).

```js
// using the exported public key above
const imported = await WebCrypto.importPublicKey(exportedPub)
```

### importPrivateKey

Import a private key using the base64 format by default. It supports the following optional parameters: `namedCurve` that accepts `P-256`, `P-384`, and `P-521` (defaults to `P-256`),
`format` that can be `base64`, `hex`, and `raw` for ArrayBuffer (defaults to `base64`).

```js
// using the exported private key above
const imported = await WebCrypto.importPrivateKey(exportedPriv)
```

### sign

Sign data using the private key. It supports the following optional parameters: `format`, 
that can be `base64`, `hex`, and `raw` for ArrayBuffer (defaults to `base64`), and `hash` that
can be of type `SHA-1`, `SHA-256`, `SHA-384`, or `SHA-512` (defaults to `SHA-256`).

```js
const data = { foo: 'bar' }
// generate keys
const keys = await WebCrypto.genKeyPair()
// sign
const sig = await WebCrypto.sign(keys.privateKey, data)
// console.log(sig) -> Cf51pRgxund ... Tvp7hYbiRQvnTnLZLpuw==
```

### verify

Verify a signature over some data using the private key. It supports the following optional
parameters: `format` that can be `base64`, `hex`, and `raw` for ArrayBuffer (defaults to
`base64`), and `hash` that can be of type `SHA-1`, `SHA-256`, `SHA-384`, or `SHA-512`
(defaults to `SHA-256`).

```js
// using the signature we got above
const isValid = await WebCrypto.verify(keys.publicKey, data, sig)
// console.log(isValid) -> true
```

## AES

### genAESKey

Generates an AES key for encryption. By default this key can be exported. It supports the
following optional parameters: `extractable` (defaults to true), `mode` (defaults to AES-GCM), and
`keySize` with a length of `128`, `192`, or `256` (defaults to `128`).


```js
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

Imports an AES key. It accepts the following optional parameters: `type` (defaults
to raw), `mode` (defaults to AES-GCM).

```js
// importKey(key, type = 'raw', mode = 'AES-GCM')
const key = WebCrypto.importKey(key)

// use this AES key now to encrypt/decrypt as above
```

## Passphrase-based key derivation

### genEncryptedMasterKey:

Uses PBKDF2 to derive a Key Encryption Key from a passphrase, in order to generate an encrypted
AES symmetric key that can be safely stored. It accepts the following optional parameters:
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

## Utility

### hash:

Generate the hash of a string or ArrayBuffer. It accepts the following optional parameters:
`outputFormat` (defaults to hex), and `name` (defaults to SHA-256 but also supports SHA-1
(don't use this in cryptographic applications), SHA-384, and SHA-512 algorithms).

```js
// hash(data, outputFormat = 'hex', name = 'SHA-256')
const hashed = await WebCrypto.hash('abc123')

console.log(hashed)
// 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
```

### genId:

Generate a random hexadecimal ID based on the provided length. Defaults to a length of 16.

```js
const randomId = WebCrypto.genId(32)

console.log(randomId) // a6d2a143edb8b521645bf5d39c29e401
```


That's it!

## Full example for signing / verifying data

```js
const WebCrypto = require('easy-web-crypto')

// generate a new ECDA key pair
const keys = await WebCrypto.genKeyPair()

// sign some data
const data = { foo: 'bar' }
const sig = await WebCrypto.sign(privKey, data)

// check signature
const isValid = await WebCrypto.verify(pubKey, data, sig)
console.log(isValid) // -> true

// EXPORT

// export public key
const exportedPub = await WebCrypto.exportPublicKey(keyPair.publicKey)
// export private key
const exportedPriv = await WebCrypto.exportPrivateKey(keyPair.publicKey)

// IMPORT

// import public key
const pubKey = await WebCrypto.importPublicKey(exportedPub)
// import private key
const privKey = await WebCrypto.importPrivateKey(exportedPriv)

// sign some data using imported keys
const data = { foo: 'bar' }
const sig = await WebCrypto.sign(privKey, data)

// check signature
const isValid = await WebCrypto.verify(pubKey, data, sig)
console.log(isValid) // -> true
```

## Full example for encrypting / decrypting data

```js
const WebCrypto = require('easy-web-crypto')

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
npm install --save easy-web-crypto
```

### Via `<script>` tag

You can call `window.WebCrypto` in browsers by using `dist/web-crypto.js`.

