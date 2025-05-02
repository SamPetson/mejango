/**
 * Solid - Advanced Data Obfuscation Module
 * Provides secure data transformation for database assurance
 * @module Solid
 */

const crypto = require('crypto');
const { Transform } = require('stream');

// Constants for obfuscation parameters
const HASH_ITERATIONS = 10000;
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const CIPHER_ALGORITHM = 'aes-256-cbc';
const HASH_ALGORITHM = 'sha512';

class Solid {
  /**
   * Initialize Solid with optional secret key
   * @param {string} [secretKey] - Optional secret key for encryption
   */
  constructor(secretKey) {
    this._secretKey = secretKey || this._generateRandomKey(32);
    this._keyCache = new Map();
  }

  /**
   * Generate a random cryptographic key
   * @private
   * @param {number} length - Length of key to generate
   * @returns {string} Random hex key
   */
  _generateRandomKey(length) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Derive a secure key from password with salt
   * @private
   * @param {string} password - Password to derive key from
   * @param {string} salt - Salt for key derivation
   * @returns {Buffer} Derived key
   */
  _deriveKey(password, salt) {
    const cacheKey = `${password}:${salt}`;
    if (this._keyCache.has(cacheKey)) {
      return this._keyCache.get(cacheKey);
    }

    const key = crypto.pbkdf2Sync(
      password,
      salt,
      HASH_ITERATIONS,
      KEY_LENGTH,
      HASH_ALGORITHM
    );

    this._keyCache.set(cacheKey, key);
    return key;
  }

  /**
   * Obfuscate data with multiple protection layers
   * @param {*} data - Data to obfuscate
   * @param {Object} [options] - Obfuscation options
   * @param {boolean} [options.encrypt=true] - Enable encryption
   * @param {boolean} [options.hash=false] - Enable hashing (one-way)
   * @returns {Object} Obfuscated data container
   */
  obfuscate(data, options = {}) {
    const { encrypt = true, hash = false } = options;
    
    if (hash && encrypt) {
      throw new Error('Cannot use both hash and encrypt options together');
    }

    const salt = crypto.randomBytes(SALT_LENGTH).toString('hex');
    const iv = crypto.randomBytes(16);
    const dataString = JSON.stringify(data);

    if (hash) {
      // One-way hashing for sensitive data like passwords
      const hashValue = crypto
        .createHash(HASH_ALGORITHM)
        .update(dataString + salt)
        .digest('hex');

      return {
        type: 'hash',
        algorithm: HASH_ALGORITHM,
        hash: hashValue,
        salt,
        iterations: HASH_ITERATIONS,
        timestamp: new Date().toISOString()
      };
    }

    if (encrypt) {
      // Reversible encryption for protected data
      const key = this._deriveKey(this._secretKey, salt);
      const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv);
      
      let encrypted = cipher.update(dataString, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      return {
        type: 'encrypted',
        algorithm: CIPHER_ALGORITHM,
        data: encrypted,
        iv: iv.toString('hex'),
        salt,
        timestamp: new Date().toISOString()
      };
    }

    // Basic obfuscation without encryption/hashing
    return {
      type: 'plain',
      data: Buffer.from(dataString).toString('base64'),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Deobfuscate data that was encrypted
   * @param {Object} container - Obfuscated data container
   * @returns {*} Original data
   */
  deobfuscate(container) {
    if (!container || typeof container !== 'object') {
      throw new Error('Invalid obfuscation container');
    }

    switch (container.type) {
      case 'encrypted': {
        const key = this._deriveKey(this._secretKey, container.salt);
        const iv = Buffer.from(container.iv, 'hex');
        const decipher = crypto.createDecipheriv(
          container.algorithm || CIPHER_ALGORITHM,
          key,
          iv
        );

        let decrypted = decipher.update(container.data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
      }

      case 'plain': {
        return JSON.parse(Buffer.from(container.data, 'base64').toString('utf8'));
      }

      case 'hash':
        throw new Error('Cannot deobfuscate hashed data - it is one-way transformed');

      default:
        throw new Error(`Unknown obfuscation type: ${container.type}`);
    }
  }

  /**
   * Create a transform stream for obfuscating data in streams
   * @param {Object} options - Obfuscation options
   * @returns {Transform} Transform stream
   */
  createObfuscateStream(options) {
    return new Transform({
      objectMode: true,
      transform: (chunk, encoding, callback) => {
        try {
          const obfuscated = this.obfuscate(chunk, options);
          callback(null, obfuscated);
        } catch (err) {
          callback(err);
        }
      }
    });
  }

  /**
   * Create a transform stream for deobfuscating data in streams
   * @returns {Transform} Transform stream
   */
  createDeobfuscateStream() {
    return new Transform({
      objectMode: true,
      transform: (chunk, encoding, callback) => {
        try {
          const deobfuscated = this.deobfuscate(chunk);
          callback(null, deobfuscated);
        } catch (err) {
          callback(err);
        }
      }
    });
  }

  /**
   * Verify if hashed data matches input
   * @param {*} input - Input data to verify
   * @param {Object} hashedContainer - Previously hashed data container
   * @returns {boolean} True if input matches hash
   */
  verifyHash(input, hashedContainer) {
    if (hashedContainer.type !== 'hash') {
      throw new Error('Container is not a hash type');
    }

    const inputString = JSON.stringify(input);
    const hashValue = crypto
      .createHash(hashedContainer.algorithm || HASH_ALGORITHM)
      .update(inputString + hashedContainer.salt)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(hashValue),
      Buffer.from(hashedContainer.hash)
    );
  }

  /**
   * Rotate the secret key and re-encrypt all provided data containers
   * @param {Object[]} containers - Array of encrypted containers
   * @param {string} [newSecret] - Optional new secret key
   * @returns {Object[]} Array of re-encrypted containers with new key
   */
  rotateKey(containers, newSecret) {
    const newKey = newSecret || this._generateRandomKey(32);
    const results = [];

    for (const container of containers) {
      if (container.type !== 'encrypted') {
        results.push(container);
        continue;
      }

      // Deobfuscate with old key
      const oldKey = this._secretKey;
      this._secretKey = oldKey;
      const data = this.deobfuscate(container);

      // Obfuscate with new key
      this._secretKey = newKey;
      results.push(this.obfuscate(data, { encrypt: true }));
    }

    this._secretKey = newKey;
    this._keyCache.clear();
    return results;
  }
}

module.exports = Solid;
