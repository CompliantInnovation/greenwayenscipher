const crypto = require('crypto');
const Rfc2898DeriveBytes = require('./Rfc2898DeriveBytes');
const $saltSize = Symbol('saltSize');
const $keySize = Symbol('keySize');
const $ivSize = Symbol('ivSize');

class AESEncryptor {
  constructor() {
    this[$saltSize] = AESEncryptor.SALT_SIZE;
    this[$keySize] = AESEncryptor.KEY_SIZE;
    this[$ivSize] = AESEncryptor.IV_SIZE;
  }

  static get SALT_SIZE() {
    return 256;
  }

  static get KEY_SIZE() {
    return 32;
  }

  static get IV_SIZE() {
    return 16;
  }

  get saltSize() {
    return this[$saltSize];
  }

  set saltSize(byteCount) {
    this[$saltSize] = byteCount;
  }

  get keySize() {
    return this[$keySize];
  }

  set keySize(byteCount) {
    this[$keySize] = byteCount;
  }

  get ivSize() {
    return this[$ivSize];
  }

  set ivSize(byteCount) {
    this[$ivSize] = byteCount;
  }

  encrypt(plainText, password) {

    if (!plainText) {
      throw new TypeError('Invalid plaintext');
    }

    if (!password) {
      throw new TypeError('Invalid password');
    }

    let deriver = new Rfc2898DeriveBytes(password, this.saltSize);
    let salt = deriver.salt;
    let key = deriver.getBytes(this.keySize);
    let iv = deriver.getBytes(this.ivSize);

    let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let enciphered = cipher.update(plainText, 'utf8', 'hex') + cipher.final('hex');
    let packed = Buffer.from(salt.toString('hex') + enciphered, 'hex').toString('base64');
    return packed;
  }

  decrypt(cipherText, password) {

    if (!cipherText) {
      throw new TypeError('Invalid ciphertext');
    }

    if (!password) {
      throw new TypeError('Invalid password');
    }

    let packed = Buffer.from(cipherText, 'base64');
    let salt = Buffer.alloc(this.saltSize)
    let enciphered = Buffer.alloc(packed.length - salt.length);

    // load salt
    for (let i = 0; i < salt.length; i++) {
      salt[i] = packed[i];
    }

    // load enciphered data
    for (let i = 0; i < enciphered.length; i++) {
      enciphered[i] = packed[i + salt.length];
    }

    let deriver = new Rfc2898DeriveBytes(password, this.saltSize);
    deriver.salt = salt;
    let key = deriver.getBytes(32);
    let iv = deriver.getBytes(16);

    let cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let deciphered = Buffer.from(cipher.update(enciphered).toString('hex') + cipher.final('hex'), 'hex').toString('utf8');
    return deciphered;
  }

}

module.exports = AESEncryptor;
