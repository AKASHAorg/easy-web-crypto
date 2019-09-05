/* eslint-env mocha */
/* global chai */

const WebCrypto = window.WebCrypto

describe('Web crypto', function () {
  context('Generating a random buffer (for iv)', () => {
    it('Should generate a random buffer without providing the length parameter', () => {
      const iv1 = WebCrypto._genRandomBuffer()
      chai.assert.lengthOf(iv1, 16)
    })

    it('Should generate a random buffer with a specific length parameter', () => {
      const iv2 = WebCrypto._genRandomBuffer(8)
      chai.assert.lengthOf(iv2, 8)
    })
    it('Should generate a random buffer with a specific length parameter in hex format', () => {
      const buf1 = WebCrypto._genRandomBufferAsStr(8, 'hex')
      chai.assert.lengthOf(buf1, 16)
    })
    it('Should generate a random buffer with a specific length parameter in base64 format', () => {
      const buf = WebCrypto._genRandomBufferAsStr(8, 'base64')
      chai.assert.lengthOf(buf, 12)
    })
    it('Should reject if a wrong encoding format is given', async () => {
      let err
      try {
        await WebCrypto._genRandomBufferAsStr(8, 'base777')
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'Invalid encoding')
    })
  })

  context('Generating a random ID', () => {
    it('Should generate a random identifier without providing the length parameter', () => {
      const id = WebCrypto.genId(32)
      chai.assert.lengthOf(id, 32)
    })

    it('Should generate a random identifier with a specific length parameter of 16', () => {
      const id = WebCrypto.genId(16)
      chai.assert.lengthOf(id, 16)
    })
  })

  context('Hashing functions', () => {
    const toHash = 'abc123'
    it('Should generate a SHA-256 hash from a string using no parameters (default)', async () => {
      const hashed = await WebCrypto.hash(toHash)
      chai.assert.lengthOf(hashed, 64)
    })

    it('Should generate a SHA-256 hash from an ArrayBuffer using no parameters (default)', async () => {
      const buffer = new ArrayBuffer(16)
      const hashed = await WebCrypto.hash(buffer)
      chai.assert.lengthOf(hashed, 64)
    })

    it('Should generate a SHA-1 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex', 'SHA-1')
      chai.assert.lengthOf(hashed, 40)
    })

    it('Should generate a SHA-256 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex')
      chai.assert.lengthOf(hashed, 64)
    })

    it('Should generate a SHA-384 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex', 'SHA-384')
      chai.assert.lengthOf(hashed, 96)
    })

    it('Should generate a SHA-512 hash when specifying hex format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'hex', 'SHA-512')
      chai.assert.lengthOf(hashed, 128)
    })

    it('Should generate a SHA-1 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-1')
      chai.assert.lengthOf(hashed, 28)
    })

    it('Should generate a SHA-256 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-256')
      chai.assert.lengthOf(hashed, 44)
    })

    it('Should generate a SHA-384 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-384')
      chai.assert.lengthOf(hashed, 64)
    })

    it('Should generate a SHA-256 hash when specifying base64 format', async () => {
      const hashed = await WebCrypto.hash(toHash, 'base64', 'SHA-512')
      chai.assert.lengthOf(hashed, 88)
    })
  })

  context('ECDA keys', () => {
    it('Should fail to generate a key pair with wrong parameters', async () => {
      let err
      try {
        await WebCrypto.genKeyPair('foo', 'baz')
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'EcKeyGenParams: Unrecognized namedCurve')

      try {
        await WebCrypto.genKeyPair(undefined, 'P-256')
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'EcKeyGenParams: Unrecognized namedCurve')
    })

    it('Should generate an extractable key pair with default parameters', async () => {
      let err
      let keypair
      try {
        keypair = await WebCrypto.genKeyPair()
      } catch (error) {
        err = error
      }
      chai.assert.isUndefined(err)
      chai.assert.isDefined(keypair)
      chai.assert.isTrue(keypair.publicKey.extractable)
      chai.assert.isTrue(keypair.privateKey.extractable)
    })

    it('Should generate a key pair with unextractable private key using default parameters', async () => {
      let err
      let keypair
      try {
        keypair = await WebCrypto.genKeyPair(false)
      } catch (error) {
        err = error
      }
      chai.assert.isUndefined(err)
      chai.assert.isDefined(keypair)
      chai.assert.isTrue(keypair.publicKey.extractable)
      chai.assert.isFalse(keypair.privateKey.extractable)
    })

    it('Should fail to export a public key with wrong parameters', async () => {
      let err
      try {
        await WebCrypto.exportPublicKey()
      } catch (error) {
        err = error
      }
      chai.assert.exists(err.message, 'Failed to execute')

      err = undefined
      try {
        await WebCrypto.exportPublicKey('foo')
      } catch (error) {
        err = error
      }
      chai.assert.isDefined(err.message, 'Failed to execute')
    })

    it('Should export a public key in base64 format by default', async () => {
      const keys = await WebCrypto.genKeyPair()
      const exported = await WebCrypto.exportPublicKey(keys.publicKey)
      chai.assert.isDefined(exported)
      chai.assert.typeOf(exported, 'string')
    })

    it('Should export a public key in raw format', async () => {
      const keys = await WebCrypto.genKeyPair()
      const exported = await WebCrypto.exportPublicKey(keys.publicKey, 'raw')

      chai.assert.isDefined(exported)
      chai.assert.typeOf(exported, 'Uint8Array')
    })

    it('Should fail to import a public key with wrong parameters', async () => {
      let err
      try {
        await WebCrypto.importPublicKey('foo', 'baz')
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'EcKeyImportParams: Unrecognized namedCurve')

      try {
        await WebCrypto.importPublicKey(undefined, 'P-256')
      } catch (error) {
        err = error
      }
      chai.assert.exists(err.message, 'First argument must be a string')
    })

    it('Should import a public key for curves P-256, P-384, P-521', async () => {
      const curves = ['P-256', 'P-384', 'P-521']
      // default params
      const keys = await WebCrypto.genKeyPair()
      const exported = await WebCrypto.exportPublicKey(keys.publicKey)
      const imported = await WebCrypto.importPublicKey(exported)
      chai.assert.typeOf(imported, 'CryptoKey')

      curves.forEach(async curve => {
        let err
        try {
          const keys = await WebCrypto.genKeyPair(true, curve)
          const exported = await WebCrypto.exportPublicKey(keys.publicKey)
          const imported = await WebCrypto.importPublicKey(exported, curve)
          chai.assert.typeOf(imported, 'CryptoKey')
        } catch (error) {
          err = error
        }
        chai.assert.isUndefined(err)
      })
    })

    it('Should fail to export a private key with wrong parameters', async () => {
      let err
      try {
        await WebCrypto.exportPrivateKey()
      } catch (error) {
        err = error
      }
      chai.assert.exists(err.message, 'Failed to execute')

      err = undefined
      try {
        await WebCrypto.exportPrivateKey('foo')
      } catch (error) {
        err = error
      }
      chai.assert.isDefined(err.message, 'Failed to execute')
    })

    it('Should export a public key to base64 format by default', async () => {
      const keys = await WebCrypto.genKeyPair()
      const exported = await WebCrypto.exportPrivateKey(keys.privateKey)

      chai.assert.typeOf(exported, 'string')
    })

    it('Should export a public key to raw format', async () => {
      const keys = await WebCrypto.genKeyPair()
      const exported = await WebCrypto.exportPrivateKey(keys.privateKey, 'raw')

      chai.assert.typeOf(exported, 'Uint8Array')
    })

    it('Should fail to import a private key with wrong parameters', async () => {
      let err
      try {
        await WebCrypto.importPrivateKey('foo', 'baz')
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'EcKeyImportParams: Unrecognized namedCurve')

      try {
        await WebCrypto.importPrivateKey(undefined, 'P-256')
      } catch (error) {
        err = error
      }
      chai.assert.exists(err.message, 'First argument must be a string')
    })

    it('Should import a private key for curves P-256, P-384, P-521', async () => {
      const curves = ['P-256', 'P-384', 'P-521']
      // default params
      const keys = await WebCrypto.genKeyPair()
      const exported = await WebCrypto.exportPrivateKey(keys.privateKey)
      const imported = await WebCrypto.importPrivateKey(exported)
      chai.assert.typeOf(imported, 'CryptoKey')

      curves.forEach(async curve => {
        let err
        try {
          const keys = await WebCrypto.genKeyPair(true, curve)
          const exported = await WebCrypto.exportPrivateKey(keys.privateKey)
          const imported = await WebCrypto.importPrivateKey(exported, curve)
          chai.assert.typeOf(imported, 'CryptoKey')
        } catch (error) {
          err = error
        }
        chai.assert.isUndefined(err)
      })
    })

    it('Should fail to sign with wrong parameters', async () => {
      const keys = await WebCrypto.genKeyPair()

      let err
      try {
        await WebCrypto.sign()
      } catch (error) {
        err = error
      }
      chai.assert.exists(err.message, 'First argument must be a string')

      try {
        await WebCrypto.sign(keys.privateKey, 'foo', 'bar')
      } catch (error) {
        err = error
      }
      chai.assert.exists(err.message, 'First argument must be a string')
    })

    it('Should sign/verify data using base64 as default format for signatures', async () => {
      const data = { foo: 'bar' }
      const keys = await WebCrypto.genKeyPair()

      const sig = await WebCrypto.sign(keys.privateKey, data)
      const valid = await WebCrypto.verify(keys.publicKey, data, sig)
      chai.assert.isTrue(valid)
    })

    it('Should sign/verify data using raw format for signatures', async () => {
      const data = { foo: 'bar' }
      const keys = await WebCrypto.genKeyPair()

      const sig = await WebCrypto.sign(keys.privateKey, data, 'raw')
      const valid = await WebCrypto.verify(keys.publicKey, data, sig, 'raw')
      chai.assert.isTrue(valid)
    })
  })

  context('AES keys', () => {
    it('Should reject if the key is not of type CryptoKey', async () => {
      let err
      try {
        await WebCrypto.encrypt([2, 3], { data: 'hello' })
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'Invalid key type')
    })

    it('Should fail to decrypt a message with default parameters (wrong iv)', async () => {
      const message = { data: 'hello' }
      const key = await WebCrypto.genAESKey()
      const ciphertext = await WebCrypto.encrypt(key, message)

      let err = { message: '_ERROR_NOT_THROWN_' }
      try {
        ciphertext.iv = ciphertext.iv.slice(0, 10)
        await WebCrypto.decrypt(key, ciphertext)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'Unable to decrypt data')
    })

    it('Should fail to decrypt a message with default parameters (wrong key)', async () => {
      const message = { data: 'hello' }
      const key = await WebCrypto.genAESKey()
      const ciphertext = await WebCrypto.encrypt(key, message)

      let err
      try {
        const key2 = await WebCrypto.genAESKey()
        await WebCrypto.decrypt(key2, ciphertext)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'Unable to decrypt data')
    })

    it('Should generate an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await WebCrypto.genAESKey()
      chai.assert.equal(key.type, 'secret', 'Secret key')
      chai.assert.isTrue(key.extractable)
    })

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await WebCrypto.genAESKey()
      const rawKey = await WebCrypto.exportKey(key)
      chai.assert.lengthOf(rawKey, 16)
    })

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 256 bits)', async () => {
      const key = await WebCrypto.genAESKey(true, 'AES-GCM', 256)
      const rawKey = await WebCrypto.exportKey(key)
      chai.assert.lengthOf(rawKey, 32)
    })

    it('Should generate and export in raw format an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await WebCrypto.genAESKey()
      const rawKey = await WebCrypto.exportKey(key, 'raw')
      chai.assert.lengthOf(rawKey, 16)
    })

    it('Should encrypt a message and encode with default format (hex)', async () => {
      const message = { data: 'hello' }
      const key = await WebCrypto.genAESKey()
      const ciphertext = await WebCrypto.encrypt(key, message)
      chai.assert.lengthOf(ciphertext.iv, 24)
    })

    it('Should encrypt a message and encode with base64 format ', async () => {
      const message = { data: 'hello' }
      const key = await WebCrypto.genAESKey()
      const ciphertext = await WebCrypto.encrypt(key, message, 'base64')

      chai.assert.equal(ciphertext.ciphertext.slice(-1), '=')
    })

    it('Should encrypt and decrypt a message with default parameters', async () => {
      const message = { data: 'hello' }
      const key = await WebCrypto.genAESKey()
      const ciphertext = await WebCrypto.encrypt(key, message)
      const plaintext = await WebCrypto.decrypt(key, ciphertext)
      chai.assert.deepEqual(plaintext, message)
    })

    it('Should generate/encrypt/export/import/decrypt with raw format for key export', async () => {
      const message = { data: 'hello' }
      const key = await WebCrypto.genAESKey()
      const ciphertext = await WebCrypto.encrypt(key, message)
      const rawKey = await WebCrypto.exportKey(key)
      const cryptoKey = await WebCrypto.importKey(rawKey)
      const plaintext = await WebCrypto.decrypt(cryptoKey, ciphertext)
      chai.assert.deepEqual(plaintext, message)
    })

    it('Should generate/encrypt/export/import/decrypt with jwk format for key export', async () => {
      const message = { data: 'hello' }
      const key = await WebCrypto.genAESKey()
      const encrypted = await WebCrypto.encrypt(key, message)
      const jwk = await WebCrypto.exportKey(key, 'jwk')
      const cryptoKey = await WebCrypto.importKey(jwk, 'jwk')
      const plaintext = await WebCrypto.decrypt(cryptoKey, encrypted)
      chai.assert.deepEqual(plaintext, message)
    })
  })

  context('Passphrase key derivation', () => {
    const passphrase = 'mySecretPass'

    it('Should reject if passphrase is not a string or is empty', async () => {
      let err
      try {
        await WebCrypto.genEncryptedMasterKey([])
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'Not a valid value')
    })

    it('Should reject if the any property of protectedMK is missing or empty', async () => {
      let err
      try {
        await WebCrypto.decryptMasterKey('secretPassphraseCandidate', {})
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.message, 'Missing properties from master key')
    })

    it('Should reject if the given passphrase is NOT the same as the stored one', async () => {
      let err
      try {
        const protectedMK = await WebCrypto.genEncryptedMasterKey(passphrase)
        await WebCrypto.decryptMasterKey(passphrase + 'modifed', protectedMK)
      } catch (error) {
        err = error
      }

      chai.assert.strictEqual(err.message, 'Wrong passphrase')
    })

    it('Should derive a passphrase with default settings, generate MK and encrypt it', async () => {
      const protectedMasterKey = await WebCrypto.genEncryptedMasterKey(passphrase)
      const { derivationParams, encryptedMasterKey } = protectedMasterKey
      const { salt, iterations, hashAlgo } = derivationParams
      chai.assert.equal(hashAlgo, 'SHA-256', 'Default hash algo is SHA-256')
      chai.assert.equal(iterations, 100000, 'Default iteration is 100000')
      chai.assert.lengthOf(salt, 32, 'Default salt is 128 bits array, 32 bytes as hex string')
      chai.assert.exists(encryptedMasterKey.iv)
      chai.assert.exists(encryptedMasterKey.ciphertext)
    })

    it('Should update the passphrase but keep the same MK', async () => {
      const newPassphrase = 'newPassphrase'

      const protectedMasterKey1 = await WebCrypto.genEncryptedMasterKey(passphrase)
      const protectedMasterKey2 = await WebCrypto.updatePassphraseKey(passphrase, newPassphrase, protectedMasterKey1)

      chai.assert.notEqual(protectedMasterKey1.encryptedMasterKey, protectedMasterKey2.encryptedMasterKey)

      chai.assert.notEqual(protectedMasterKey1.encryptedMasterKey.ciphertext,
        protectedMasterKey2.encryptedMasterKey.ciphertext)

      chai.assert.equal(protectedMasterKey1.derivationParams.hashAlgo,
        protectedMasterKey1.derivationParams.hashAlgo,
        'Default hash algo is SHA-256')

      chai.assert.equal(protectedMasterKey1.derivationParams.iterations,
        protectedMasterKey2.derivationParams.iterations,
        'Default iteration is 100000')

      // Check if the masterkey is the same
      const decMK1 = await WebCrypto.decryptMasterKey(passphrase, protectedMasterKey1)
      const decMK2 = await WebCrypto.decryptMasterKey(newPassphrase, protectedMasterKey2)
      const key1 = await WebCrypto.exportKey(decMK1).toString('hex')
      const key2 = await WebCrypto.exportKey(decMK2).toString('hex')
      chai.assert.equal(key1, key2)
    })

    it('Should return the MK (an Array) if the given passphrase is the same as the stored one', async () => {
      const protectedMK = await WebCrypto.genEncryptedMasterKey(passphrase)
      const masterKey = await WebCrypto.decryptMasterKey(passphrase, protectedMK)

      chai.assert.exists(masterKey, 'The check operation should return the MK')
      chai.assert.lengthOf(await WebCrypto.exportKey(masterKey), 32)
    })

    it('Should derive a key from passphrase, gen MK, enc/dec a value', async () => {
      const protectedMK = await WebCrypto.genEncryptedMasterKey(passphrase)
      const cryptokey = await WebCrypto.decryptMasterKey(passphrase, protectedMK)
      const data = { hello: 'world' }
      const enc = await WebCrypto.encrypt(cryptokey, data)
      chai.assert.exists(enc.iv, 'iv must exist')
      chai.assert.exists(enc.ciphertext, 'ciphertext must exist')

      // Just to be sure that everything is working well.
      const dec = await WebCrypto.decrypt(cryptokey, enc)
      chai.assert.deepEqual(dec, data)
    })

    it('The salt and protectedMK must be different for two consecutive call to genEncryptedMasterKey even with the same passphrase', async () => {
      const passphrase = 'secret'
      const protectedMK1 = await WebCrypto.genEncryptedMasterKey(passphrase)
      const protectedMK2 = await WebCrypto.genEncryptedMasterKey(passphrase)
      chai.assert.notStrictEqual(protectedMK1.derivationParams.salt, protectedMK2.derivationParams.salt)
      chai.assert.notStrictEqual(protectedMK1.encryptedMasterKey.iv, protectedMK2.encryptedMasterKey.iv)
      chai.assert.notStrictEqual(protectedMK1.encryptedMasterKey.ciphertext, protectedMK2.encryptedMasterKey.ciphertext)
    })
  })
})
