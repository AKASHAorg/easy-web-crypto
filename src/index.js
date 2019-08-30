/**
 * Originally from https://github.com/QwantResearch/masq-common/ with modifications
 * by Andrei Sambra
 */

/**
   * Generate an AES key based on the cipher mode and keysize
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {Promise<CryptoKey>} - The generated AES key.
   */
const genAESKey = (extractable, mode = 'AES-GCM', keySize = 128) => {
  return window.crypto.subtle.generateKey({
    name: mode,
    length: keySize
  }, extractable || true, ['decrypt', 'encrypt'])
}

/**
    * Import a raw|jwk as a CryptoKey
    *
    * @param {arrayBuffer|Object} key - The key
    * @param {string} [type] - The type of the key to import ('raw', 'jwk')
    * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
    * @returns {Promise<arrayBuffer>} - The cryptoKey
    */
const importKey = (key, type = 'raw', mode = 'AES-GCM') => {
  const parsedKey = (type === 'raw') ? Buffer.from(key, 'base64') : key
  return window.crypto.subtle.importKey(type, parsedKey, { name: mode }
    , true, ['encrypt', 'decrypt'])
}

/**
  * Export a CryptoKey into a raw|jwk key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @param {string} [type] - The type of the exported key: raw|jwk
  * @returns {Promise<arrayBuffer>} - The raw key or the key as a jwk format
  */
const exportKey = async (key, type = 'raw') => {
  const exportedKey = await window.crypto.subtle.exportKey(type, key)
  return (type === 'raw') ? new Uint8Array(exportedKey) : exportedKey
}

/**
   * Encrypt buffer
   *
   * @param {ArrayBuffer} key - The AES CryptoKey
   * @param {ArrayBuffer} data - Data to encrypt
   * @param {Object} cipherContext - The AES cipher parameters
   * @returns {ArrayBuffer} - The encrypted buffer
   */
const encryptBuffer = async (key, data, cipherContext) => {
  const encrypted = await window.crypto.subtle.encrypt(cipherContext, key, data)
  return new Uint8Array(encrypted)
}

/**
 * Decrypt buffer
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {Object} cipherContext - The AES cipher parameters
 * @returns {Promise<ArrayBuffer>} - The decrypted buffer
 */
const decryptBuffer = async (key, data, cipherContext) => {
  // TODO: test input params
  try {
    const decrypted = await window.crypto.subtle.decrypt(cipherContext, key, data)
    return new Uint8Array(decrypted)
  } catch (e) {
    if (e.message === 'Unsupported state or unable to authenticate data') {
      throw new Error('Unable to decrypt data')
    }
  }
}

const checkCryptokey = (key) => {
  if (!key.type || key.type !== 'secret') {
    throw new Error('Invalid key type')
  }
}

const genRandomBuffer = (len = 16) => {
  const values = window.crypto.getRandomValues(new Uint8Array(len))
  return Buffer.from(values)
}

/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
const encrypt = async (key, data, format = 'hex') => {
  checkCryptokey(key)
  const context = {
    iv: genRandomBuffer(key.algorithm.name === 'AES-GCM' ? 12 : 16),
    plaintext: Buffer.from(JSON.stringify(data))
  }

  // Prepare cipher context, depends on cipher mode
  const cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  }

  const encrypted = await encryptBuffer(key, context.plaintext, cipherContext)
  return {
    ciphertext: Buffer.from(encrypted).toString(format),
    iv: Buffer.from(context.iv).toString(format)
  }
}

/**
   * Decrypt data
   *
   * @param {CryptoKey} key - The AES CryptoKey
   * @param {string | Object} - The data to encrypt
   * @param {string} [format] - The ciphertext and iv encoding format
   */
const decrypt = async (key, ciphertext, format = 'hex') => {
  checkCryptokey(key)

  const context = {
    ciphertext: Object.prototype.hasOwnProperty.call(ciphertext, 'ciphertext') ? Buffer.from(ciphertext.ciphertext, (format)) : '',
    // IV is 128 bits long === 16 bytes
    iv: Object.prototype.hasOwnProperty.call(ciphertext, 'iv') ? Buffer.from(ciphertext.iv, (format)) : ''
  }

  // Prepare cipher context, depends on cipher mode
  const cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  }
  try {
    const decrypted = await decryptBuffer(key, context.ciphertext, cipherContext)
    return JSON.parse(Buffer.from(decrypted).toString())
  } catch (error) {
    throw new Error('Unable to decrypt data')
  }
}

const checkPassphrase = (str) => {
  if (typeof str !== 'string' || str === '') {
    throw new Error(`Not a valid value`)
  }
}

const checkEncodingFormat = (format) => {
  if (format !== 'hex' && format !== 'base64') throw new Error('Invalid encoding')
}

const genRandomBufferAsStr = (len = 16, encodingFormat = 'hex') => {
  if (encodingFormat) {
    checkEncodingFormat(encodingFormat)
  }
  const buf = genRandomBuffer(len)
  return buf.toString(encodingFormat)
}

/**
 * Generate a PBKDF2 derived key (bits) based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation
 * @returns {Promise<Uint8Array>} A promise that contains the derived key
 */
const deriveBits = async (passPhrase, salt, iterations, hashAlgo) => {
  // Always specify a strong salt
  if (iterations < 10000) { console.warn('Less than 10000 :(') }

  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    (typeof passPhrase === 'string') ? Buffer.from(passPhrase) : passPhrase,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  )
  const derivedKey = await window.crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: salt || new Uint8Array([]),
    iterations: iterations || 100000,
    hash: hashAlgo || 'SHA-256'
  }, baseKey, 128)

  return new Uint8Array(derivedKey)
}

/**
 * Derive a key based on a given passphrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<keyEncryptionKey>} A promise that contains the derived key and derivation
 * parameters
 */
const deriveKeyFromPassphrase = async (passPhrase, salt = genRandomBuffer(16), iterations = 100000, hashAlgo = 'SHA-256') => {
  checkPassphrase(passPhrase)

  const derivedKey = await deriveBits(passPhrase, salt, iterations, hashAlgo)
  const key = await importKey(derivedKey)
  return {
    derivationParams: {
      salt: Buffer.from(salt).toString('hex'),
      iterations,
      hashAlgo
    },
    key
  }
}

/**
 * Derive the passphrase with PBKDF2 to obtain a KEK
 * Generate a AES key (masterKey)
 * Encrypt the masterKey with the KEK
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<protectedMasterKey>} A promise that contains the encrypted derived key
 */
const genEncryptedMasterKey = async (passPhrase, salt, iterations, hashAlgo) => {
  // derive key encryption key from passphrase
  const keyEncryptionKey = await deriveKeyFromPassphrase(passPhrase, salt, iterations, hashAlgo)

  // Generate the masterKey
  const masterKey = await genRandomBufferAsStr(32, 'hex')

  const encryptedMasterKey = await encrypt(keyEncryptionKey.key, masterKey)

  return {
    derivationParams: keyEncryptionKey.derivationParams,
    encryptedMasterKey
  }
}

/**
 * Update the derived encryption key (KEK) based on the new passphrase from user, while retaining
 * the symmetric key that encrypts data at rest
 *
 * @param {string | arrayBuffer} currentPassPhrase The current (old) passphrase that is used to derive the key
 * @param {string | arrayBuffer} newPassPhrase The new passphrase that will be used to derive the key
 * @param {oldMasterKey} oldMasterKey - The old object returned by genEncryptedMasterKey for the old passphrase
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<protectedMasterKey>}
 */
const updatePassphraseKey = async (currentPassPhrase, newPassPhrase, oldMasterKey, salt, iterations, hashAlgo) => {
  const masterKey = await decryptMasterKey(currentPassPhrase, oldMasterKey)
  // derive a new key encryption key from newPassPhrase
  const keyEncryptionKey = await deriveKeyFromPassphrase(newPassPhrase, salt, iterations, hashAlgo)

  // enconde existing masterKey as a hex string since it's a buffer
  const toBeEncryptedMasterKey = Buffer.from(await exportKey(masterKey)).toString('hex')

  const encryptedMasterKey = await encrypt(keyEncryptionKey.key, toBeEncryptedMasterKey)

  return {
    derivationParams: keyEncryptionKey.derivationParams,
    encryptedMasterKey
  }
}

/**
 * Decrypt a master key by deriving the encryption key from the
 * provided passphrase and encrypted master key.
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {protectedMasterKey} protectedMasterKey - The same object returned
 * by genEncryptedMasterKey
 * @returns {Promise<masterKey>} A promise that contains the masterKey
 */
const decryptMasterKey = async (passPhrase, protectedMasterKey) => {
  if (!protectedMasterKey.encryptedMasterKey ||
    !protectedMasterKey.derivationParams) {
    throw new Error('Missing properties from master key')
  }
  const { derivationParams, encryptedMasterKey } = protectedMasterKey
  const { salt, iterations, hashAlgo } = derivationParams
  const _salt = typeof (salt) === 'string' ? Buffer.from(salt, ('hex')) : salt
  const derivedKey = await deriveBits(passPhrase, _salt, iterations, hashAlgo)
  const keyEncryptionKey = await importKey(derivedKey)
  try {
    const decryptedMasterKeyHex = await decrypt(keyEncryptionKey, encryptedMasterKey)
    // return decryptedMasterKeyHex
    const parsedKey = Buffer.from(decryptedMasterKeyHex, 'hex')
    return window.crypto.subtle.importKey('raw', parsedKey, { name: 'AES-GCM' }
      , true, ['encrypt', 'decrypt'])
  } catch (error) {
    throw new Error('Wrong passphrase')
  }
}

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} data The message
 * @param {string} [format] The encoding format ('hex' by default, could be 'base64')
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise<String>}  A promise that contains the hash as a String encoded with encodingFormat
 */
const hash = async (data, format = 'hex', type = 'SHA-256') => {
  const digest = await window.crypto.subtle.digest(
    {
      name: type
    },
    (typeof data === 'string') ? Buffer.from(data) : data
  )
  return Buffer.from(digest).toString(format)
}

module.exports = {
  genAESKey,
  importKey,
  exportKey,
  encrypt,
  decrypt,
  encryptBuffer,
  decryptBuffer,
  genEncryptedMasterKey,
  decryptMasterKey,
  updatePassphraseKey,
  hash,
  _genRandomBuffer: genRandomBuffer,
  _genRandomBufferAsStr: genRandomBufferAsStr
}
