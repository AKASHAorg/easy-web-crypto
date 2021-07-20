/**
 * Originally from https://github.com/QwantResearch/masq-common/
 * with improvements by Andrei Sambra
 */
/// <reference types="node" />
import { Buffer } from 'buffer';
interface CipherData {
    ciphertext: string;
    iv: string;
}
interface DerivationParams {
    salt: string;
    iterations: number;
    hashAlgo: string;
}
interface ProtectedMasterKey {
    derivationParams: DerivationParams;
    encryptedMasterKey: CipherData;
}
/**
 * Generate a random hexadecimal ID of a given length
 *
 * @param {integer} [len] The string length of the new ID
 * @returns {string} The new ID
 */
declare const genId: (len?: number) => string;
/**
 * Generate the hash of a string or ArrayBuffer
 *
 * @param {string | arrayBuffer} data The message
 * @param {string} [format] The encoding format ('hex' by default, can also be 'base64')
 * @param {string} [name] The hashing algorithm (SHA-256 by default)
 * @returns {Promise<String>}  A promise that contains the hash as a String encoded with encodingFormat
 */
declare const hash: (data: string | ArrayBuffer, format?: BufferEncoding, name?: string) => Promise<string>;
/**
   * Generate an ECDA key pair based on the provided curve name
   *
   * @param {boolean} extractable - Specify if the generated key is extractable
   * @param {namedCurve} namedCurve - The curve name to use
   * @returns {Promise<CryptoKey>} - A promise containing the key pair
   */
declare const genKeyPair: (extractable?: boolean, namedCurve?: string) => Promise<CryptoKeyPair>;
declare type KeyBufferEncoding = BufferEncoding | 'raw';
declare type SelectKeyType<TFormat extends KeyBufferEncoding> = TFormat extends 'raw' ? Uint8Array : string;
/**
  * Import a public key
  *
  * @param {CryptoKey} key - The public CryptoKey
  * @param {string} namedCurve - The curve name to use
  * @returns {Promise<arrayBuffer>} - The raw key
  */
declare function importPublicKey(key: string): Promise<CryptoKey>;
declare function importPublicKey(key: string, namedCurve: string): Promise<CryptoKey>;
declare function importPublicKey<TFormat extends KeyBufferEncoding>(key: SelectKeyType<TFormat>, namedCurve: string, format: TFormat): Promise<CryptoKey>;
/**
  * Import a private key
  *
  * @param {CryptoKey} key - The private CryptoKey
  * @param {string} namedCurve - The curve name to use
  * @returns {Promise<arrayBuffer>} - The raw key
  */
declare function importPrivateKey(key: string): Promise<CryptoKey>;
declare function importPrivateKey(key: string, namedCurve: string): Promise<CryptoKey>;
declare function importPrivateKey<TFormat extends KeyBufferEncoding>(key: SelectKeyType<TFormat>, namedCurve: string, format: TFormat): Promise<CryptoKey>;
/**
  * Export a public key
  *
  * @param {CryptoKey} key - The public CryptoKey
  * @returns {Promise<arrayBuffer | string>} - The raw key
  */
declare function exportPublicKey(key: CryptoKey): Promise<string>;
declare function exportPublicKey<TFormat extends KeyBufferEncoding>(key: CryptoKey, format: TFormat): Promise<SelectKeyType<TFormat>>;
/**
  * Export a private key
  *
  * @param {CryptoKey} key - The private CryptoKey
  * @returns {Promise<arrayBuffer>} - The raw key
  */
declare function exportPrivateKey(key: CryptoKey): Promise<string>;
declare function exportPrivateKey<TFormat extends KeyBufferEncoding>(key: CryptoKey, format: TFormat): Promise<SelectKeyType<TFormat>>;
/**
 * Sign data using the private key
 *
 * @param {CryptoKey} key - The private key
 * @param {*} data - Data to sign
 * @param {*} hash - The hashing algorithm
 * @returns {Promise<arrayBuffer>} - The raw signature
 */
declare const sign: (key: CryptoKey, data: any, format?: KeyBufferEncoding, hash?: string) => Promise<string | Uint8Array>;
/**
 * Verify data using the public key
 *
 * @param {CryptoKey} key - The public key
 * @param {*} data - Data to verify
 * @param {*} hash - The hashing algorithm
 * @returns {Promise<boolean>} - The verification outcome
 */
declare const verify: (key: CryptoKey, data: any, signature: string, format?: BufferEncoding, hash?: string) => Promise<boolean>;
/**
   * Generate an AES key based on the cipher mode and keysize
   *
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {Promise<CryptoKey>} - The generated AES key.
   */
declare const genAESKey: (extractable?: boolean, mode?: string, keySize?: number) => Promise<CryptoKey>;
/**
    * Import a raw|jwk as a CryptoKey
    *
    * @param {arrayBuffer|Object} key - The key
    * @param {string} [type] - The type of the key to import ('raw', 'jwk')
    * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
    * @returns {Promise<arrayBuffer>} - The cryptoKey
    */
declare const importKey: (key: ArrayBuffer, type?: string, mode?: string) => Promise<CryptoKey>;
/**
  * Export a CryptoKey into a raw|jwk key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @param {string} [type] - The type of the exported key: raw|jwk
  * @returns {Promise<arrayBuffer>} - The raw key or the key as a jwk format
  */
declare const exportKey: (key: CryptoKey, type?: 'raw' | 'pkcs8' | 'spki' | 'jwk') => Promise<ArrayBuffer>;
/**
   * Encrypt buffer
   *
   * @param {ArrayBuffer} key - The AES CryptoKey
   * @param {ArrayBuffer} data - Data to encrypt
   * @param {Object} cipherContext - The AES cipher parameters
   * @returns {ArrayBuffer} - The encrypted buffer
   */
declare const encryptBuffer: <TCipherContext extends Algorithm>(key: CryptoKey, data: Buffer, cipherContext: TCipherContext) => Promise<Uint8Array>;
/**
 * Decrypt buffer
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {Object} cipherContext - The AES cipher parameters
 * @returns {Promise<ArrayBuffer>} - The decrypted buffer
 */
declare const decryptBuffer: <TCipherContext extends Algorithm>(key: CryptoKey, data: ArrayBuffer, cipherContext: TCipherContext) => Promise<Uint8Array | undefined>;
/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
declare const encrypt: (key: CryptoKey, data: string | object, format?: BufferEncoding) => Promise<CipherData>;
/**
   * Decrypt data
   *
   * @param {CryptoKey} key - The AES CryptoKey
   * @param {string | Object} - The data to decrypt
   * @param {string} [format] - The ciphertext and iv encoding format
   */
declare const decrypt: (key: CryptoKey, ciphertext: CipherData, format?: BufferEncoding) => Promise<any>;
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
declare const genEncryptedMasterKey: (passPhrase: string, salt?: Buffer | undefined, iterations?: number | undefined, hashAlgo?: string | undefined) => Promise<ProtectedMasterKey>;
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
declare const updatePassphraseKey: (currentPassPhrase: string, newPassPhrase: string, oldMasterKey: ProtectedMasterKey, salt?: Buffer | undefined, iterations?: number | undefined, hashAlgo?: string | undefined) => Promise<ProtectedMasterKey>;
/**
 * Decrypt a master key by deriving the encryption key from the
 * provided passphrase and encrypted master key.
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {protectedMasterKey} protectedMasterKey - The same object returned
 * by genEncryptedMasterKey
 * @returns {Promise<masterKey>} A promise that contains the masterKey
 */
declare const decryptMasterKey: (passPhrase: string, protectedMasterKey: ProtectedMasterKey) => Promise<CryptoKey>;
declare const _genRandomBuffer: (len?: number) => Buffer;
declare const _genRandomBufferAsStr: (len?: number, encodingFormat?: BufferEncoding) => string;
export { genId, hash, genKeyPair, importPublicKey, importPrivateKey, exportPublicKey, exportPrivateKey, sign, verify, genAESKey, importKey, exportKey, encrypt, decrypt, encryptBuffer, decryptBuffer, genEncryptedMasterKey, decryptMasterKey, updatePassphraseKey, _genRandomBuffer, _genRandomBufferAsStr, CipherData, DerivationParams, ProtectedMasterKey };
