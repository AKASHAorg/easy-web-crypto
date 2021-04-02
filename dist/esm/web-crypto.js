/**
 * Originally from https://github.com/QwantResearch/masq-common/
 * with improvements by Andrei Sambra
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const checkCryptokey = (key) => {
    if (!key.type || key.type !== 'secret') {
        throw new Error('Invalid key type');
    }
};
const genRandomBuffer = (len = 16) => {
    const values = window.crypto.getRandomValues(new Uint8Array(len));
    return Buffer.from(values);
};
const genRandomBufferAsStr = (len = 16, encodingFormat = 'hex') => {
    if (encodingFormat) {
        checkEncodingFormat(encodingFormat);
    }
    const buf = genRandomBuffer(len);
    return buf.toString(encodingFormat);
};
const checkPassphrase = (str) => {
    if (typeof str !== 'string' || str === '') {
        throw new Error(`Not a valid value`);
    }
};
const checkEncodingFormat = (format) => {
    if (format !== 'hex' && format !== 'base64')
        throw new Error('Invalid encoding');
};
/**
 * Generate a random hexadecimal ID of a given length
 *
 * @param {integer} [len] The string length of the new ID
 * @returns {string} The new ID
 */
const genId = (len = 32) => {
    // 2 bytes for each char
    return genRandomBufferAsStr(Math.floor(len / 2));
};
/**
 * Generate the hash of a string or ArrayBuffer
 *
 * @param {string | arrayBuffer} data The message
 * @param {string} [format] The encoding format ('hex' by default, can also be 'base64')
 * @param {string} [name] The hashing algorithm (SHA-256 by default)
 * @returns {Promise<String>}  A promise that contains the hash as a String encoded with encodingFormat
 */
const hash = (data, format = 'hex', name = 'SHA-256') => __awaiter(void 0, void 0, void 0, function* () {
    const digest = yield window.crypto.subtle.digest({
        name
    }, (typeof data === 'string') ? Buffer.from(data) : data);
    return Buffer.from(digest).toString(format);
});
/**
   * Generate an ECDA key pair based on the provided curve name
   *
   * @param {boolean} extractable - Specify if the generated key is extractable
   * @param {namedCurve} namedCurve - The curve name to use
   * @returns {Promise<CryptoKey>} - A promise containing the key pair
   */
const genKeyPair = (extractable = true, namedCurve = 'P-256') => {
    return window.crypto.subtle.generateKey({
        name: 'ECDSA',
        namedCurve // can be "P-256", "P-384", or "P-521"
    }, extractable, ['sign', 'verify']);
};
function importPublicKey(key, namedCurve = 'P-256', format = 'base64') {
    return window.crypto.subtle.importKey('spki', typeof key === 'string' ? Buffer.from(key, format) : key, {
        name: 'ECDSA',
        namedCurve // can be "P-256", "P-384", or "P-521"
    }, true, ['verify']);
}
function importPrivateKey(key, namedCurve = 'P-256', format = 'base64') {
    return window.crypto.subtle.importKey('pkcs8', typeof key === 'string' ? Buffer.from(key, format) : key, {
        name: 'ECDSA',
        namedCurve // can be "P-256", "P-384", or "P-521"
    }, true, ['sign']);
}
function exportPublicKey(key, format = 'base64') {
    return __awaiter(this, void 0, void 0, function* () {
        const exported = yield window.crypto.subtle.exportKey('spki', key);
        return (format === 'raw') ? new Uint8Array(exported) : Buffer.from(exported).toString(format);
    });
}
function exportPrivateKey(key, format = 'base64') {
    return __awaiter(this, void 0, void 0, function* () {
        const exported = yield window.crypto.subtle.exportKey('pkcs8', key);
        return (format === 'raw') ? new Uint8Array(exported) : Buffer.from(exported).toString(format);
    });
}
/**
 * Sign data using the private key
 *
 * @param {CryptoKey} key - The private key
 * @param {*} data - Data to sign
 * @param {*} hash - The hashing algorithm
 * @returns {Promise<arrayBuffer>} - The raw signature
 */
const sign = (key, data, format = 'base64', hash = 'SHA-256') => __awaiter(void 0, void 0, void 0, function* () {
    const signature = yield window.crypto.subtle.sign({
        name: 'ECDSA',
        hash: { name: hash } // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    }, key, Buffer.from(JSON.stringify(data)));
    return (format === 'raw') ? new Uint8Array(signature) : Buffer.from(signature).toString(format);
});
/**
 * Verify data using the public key
 *
 * @param {CryptoKey} key - The public key
 * @param {*} data - Data to verify
 * @param {*} hash - The hashing algorithm
 * @returns {Promise<boolean>} - The verification outcome
 */
const verify = (key, data, signature, format = 'base64', hash = 'SHA-256') => __awaiter(void 0, void 0, void 0, function* () {
    return window.crypto.subtle.verify({
        name: 'ECDSA',
        hash: { name: hash } // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    }, key, Buffer.from(signature, format), Buffer.from(JSON.stringify(data)));
});
/**
   * Generate an AES key based on the cipher mode and keysize
   *
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {Promise<CryptoKey>} - The generated AES key.
   */
const genAESKey = (extractable = true, mode = 'AES-GCM', keySize = 128) => {
    return window.crypto.subtle.generateKey({
        name: mode,
        length: keySize
    }, extractable, ['decrypt', 'encrypt']);
};
/**
    * Import a raw|jwk as a CryptoKey
    *
    * @param {arrayBuffer|Object} key - The key
    * @param {string} [type] - The type of the key to import ('raw', 'jwk')
    * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
    * @returns {Promise<arrayBuffer>} - The cryptoKey
    */
const importKey = (key, type = 'raw', mode = 'AES-GCM') => {
    const parsedKey = (type === 'raw') ? Buffer.from(key, 'base64') : key;
    return window.crypto.subtle.importKey(type, parsedKey, { name: mode }, true, ['encrypt', 'decrypt']);
};
/**
  * Export a CryptoKey into a raw|jwk key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @param {string} [type] - The type of the exported key: raw|jwk
  * @returns {Promise<arrayBuffer>} - The raw key or the key as a jwk format
  */
const exportKey = (key, type = 'raw') => __awaiter(void 0, void 0, void 0, function* () {
    const exportedKey = yield window.crypto.subtle.exportKey(type, key);
    return (type === 'raw') ? new Uint8Array(exportedKey) : exportedKey;
});
/**
   * Encrypt buffer
   *
   * @param {ArrayBuffer} key - The AES CryptoKey
   * @param {ArrayBuffer} data - Data to encrypt
   * @param {Object} cipherContext - The AES cipher parameters
   * @returns {ArrayBuffer} - The encrypted buffer
   */
const encryptBuffer = (key, data, cipherContext) => __awaiter(void 0, void 0, void 0, function* () {
    const encrypted = yield window.crypto.subtle.encrypt(cipherContext, key, data);
    return new Uint8Array(encrypted);
});
/**
 * Decrypt buffer
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {Object} cipherContext - The AES cipher parameters
 * @returns {Promise<ArrayBuffer>} - The decrypted buffer
 */
const decryptBuffer = (key, data, cipherContext) => __awaiter(void 0, void 0, void 0, function* () {
    // TODO: test input params
    try {
        const decrypted = yield window.crypto.subtle.decrypt(cipherContext, key, data);
        return new Uint8Array(decrypted);
    }
    catch (e) {
        if (e.message === 'Unsupported state or unable to authenticate data') {
            throw new Error('Unable to decrypt data');
        }
    }
});
/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
const encrypt = (key, data, format = 'hex') => __awaiter(void 0, void 0, void 0, function* () {
    checkCryptokey(key);
    const context = {
        iv: genRandomBuffer(key.algorithm.name === 'AES-GCM' ? 12 : 16),
        plaintext: Buffer.from(JSON.stringify(data))
    };
    // Prepare cipher context, depends on cipher mode
    const cipherContext = {
        name: key.algorithm.name,
        iv: context.iv
    };
    const encrypted = yield encryptBuffer(key, context.plaintext, cipherContext);
    return {
        ciphertext: Buffer.from(encrypted).toString(format),
        iv: Buffer.from(context.iv).toString(format)
    };
});
/**
   * Decrypt data
   *
   * @param {CryptoKey} key - The AES CryptoKey
   * @param {string | Object} - The data to decrypt
   * @param {string} [format] - The ciphertext and iv encoding format
   */
const decrypt = (key, ciphertext, format = 'hex') => __awaiter(void 0, void 0, void 0, function* () {
    checkCryptokey(key);
    const context = {
        ciphertext: Buffer.from(Object.prototype.hasOwnProperty.call(ciphertext, 'ciphertext') ? ciphertext.ciphertext : '', (format)),
        // IV is 128 bits long === 16 bytes
        iv: Object.prototype.hasOwnProperty.call(ciphertext, 'iv') ? Buffer.from(ciphertext.iv, (format)) : ''
    };
    // Prepare cipher context, depends on cipher mode
    const cipherContext = {
        name: key.algorithm.name,
        iv: context.iv
    };
    try {
        const decrypted = yield decryptBuffer(key, context.ciphertext, cipherContext);
        if (decrypted === undefined) {
            throw new Error();
        }
        return JSON.parse(Buffer.from(decrypted).toString());
    }
    catch (error) {
        throw new Error('Unable to decrypt data');
    }
});
/**
 * Generate a PBKDF2 derived key (bits) based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation
 * @returns {Promise<Uint8Array>} A promise that contains the derived key
 */
const deriveBits = (passPhrase, salt, iterations, hashAlgo) => __awaiter(void 0, void 0, void 0, function* () {
    // Always specify a strong salt
    if (iterations < 10000) {
        console.warn('Less than 10000 :(');
    }
    const baseKey = yield window.crypto.subtle.importKey('raw', (typeof passPhrase === 'string') ? Buffer.from(passPhrase) : passPhrase, 'PBKDF2', false, ['deriveBits', 'deriveKey']);
    const derivedKey = yield window.crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: salt || new Uint8Array([]),
        iterations: iterations || 100000,
        hash: hashAlgo || 'SHA-256'
    }, baseKey, 128);
    return new Uint8Array(derivedKey);
});
/**
 * Derive a key based on a given passphrase
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<keyEncryptionKey>} A promise that contains the derived key and derivation
 * parameters
 */
const deriveKeyFromPassphrase = (passPhrase, salt = genRandomBuffer(16), iterations = 100000, hashAlgo = 'SHA-256') => __awaiter(void 0, void 0, void 0, function* () {
    checkPassphrase(passPhrase);
    const derivedKey = yield deriveBits(passPhrase, salt, iterations, hashAlgo);
    const key = yield importKey(derivedKey);
    return {
        derivationParams: {
            salt: Buffer.from(salt).toString('hex'),
            iterations,
            hashAlgo
        },
        key
    };
});
/**
 * Derive the passphrase with PBKDF2 to obtain a KEK
 * Generate a AES key (masterKey)
 * Encrypt the masterKey with the KEK
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<protectedMasterKey>} A promise that contains the encrypted derived key
 */
const genEncryptedMasterKey = (passPhrase, salt, iterations, hashAlgo) => __awaiter(void 0, void 0, void 0, function* () {
    // derive key encryption key from passphrase
    const keyEncryptionKey = yield deriveKeyFromPassphrase(passPhrase, salt, iterations, hashAlgo);
    // Generate the masterKey
    const masterKey = genRandomBufferAsStr(32, 'hex');
    const encryptedMasterKey = yield encrypt(keyEncryptionKey.key, masterKey);
    return {
        derivationParams: keyEncryptionKey.derivationParams,
        encryptedMasterKey
    };
});
/**
 * Update the derived encryption key (KEK) based on the new passphrase from user, while retaining
 * the symmetric key that encrypts data at rest
 *
 * @param {string} currentPassPhrase The current (old) passphrase that is used to derive the key
 * @param {string} newPassPhrase The new passphrase that will be used to derive the key
 * @param {oldMasterKey} oldMasterKey - The old object returned by genEncryptedMasterKey for the old passphrase
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<protectedMasterKey>}
 */
const updatePassphraseKey = (currentPassPhrase, newPassPhrase, oldMasterKey, salt, iterations, hashAlgo) => __awaiter(void 0, void 0, void 0, function* () {
    const masterKey = yield decryptMasterKey(currentPassPhrase, oldMasterKey);
    // derive a new key encryption key from newPassPhrase
    const keyEncryptionKey = yield deriveKeyFromPassphrase(newPassPhrase, salt, iterations, hashAlgo);
    // enconde existing masterKey as a hex string since it's a buffer
    const toBeEncryptedMasterKey = Buffer.from(yield exportKey(masterKey)).toString('hex');
    const encryptedMasterKey = yield encrypt(keyEncryptionKey.key, toBeEncryptedMasterKey);
    return {
        derivationParams: keyEncryptionKey.derivationParams,
        encryptedMasterKey
    };
});
/**
 * Decrypt a master key by deriving the encryption key from the
 * provided passphrase and encrypted master key.
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {protectedMasterKey} protectedMasterKey - The same object returned
 * by genEncryptedMasterKey
 * @returns {Promise<masterKey>} A promise that contains the masterKey
 */
const decryptMasterKey = (passPhrase, protectedMasterKey) => __awaiter(void 0, void 0, void 0, function* () {
    if (!protectedMasterKey.encryptedMasterKey ||
        !protectedMasterKey.derivationParams) {
        throw new Error('Missing properties from master key');
    }
    const { derivationParams, encryptedMasterKey } = protectedMasterKey;
    const { salt, iterations, hashAlgo } = derivationParams;
    const _salt = typeof (salt) === 'string' ? Buffer.from(salt, ('hex')) : salt;
    const derivedKey = yield deriveBits(passPhrase, _salt, iterations, hashAlgo);
    const keyEncryptionKey = yield importKey(derivedKey);
    try {
        const decryptedMasterKeyHex = yield decrypt(keyEncryptionKey, encryptedMasterKey);
        // return decryptedMasterKeyHex
        const parsedKey = Buffer.from(decryptedMasterKeyHex, 'hex');
        return window.crypto.subtle.importKey('raw', parsedKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    }
    catch (error) {
        throw new Error('Wrong passphrase');
    }
});
const _genRandomBuffer = genRandomBuffer;
const _genRandomBufferAsStr = genRandomBufferAsStr;
export { genId, hash, genKeyPair, importPublicKey, importPrivateKey, exportPublicKey, exportPrivateKey, sign, verify, genAESKey, importKey, exportKey, encrypt, decrypt, encryptBuffer, decryptBuffer, genEncryptedMasterKey, decryptMasterKey, updatePassphraseKey, _genRandomBuffer, _genRandomBufferAsStr };
//# sourceMappingURL=web-crypto.js.map