
const crypto = require('crypto');
const $key = Symbol('key');
const $saltSize = Symbol('saltSize');
const $salt = Symbol('salt');
const $iterationCount = Symbol('iterationCount');
const $position = Symbol('position');

class Rfc2898DeriveBytes {
	constructor(key, saltSize = 32, iterationCount = 1000) {
		this[$key] = key;
		this[$saltSize] = saltSize;
		this[$iterationCount] = iterationCount;
		this[$position] = 0;
		this[$salt] = crypto.randomBytes(this[$saltSize]);
	}

	get salt() {
		return this[$salt];
	}
	set salt(buffer) {
		this[$salt] = buffer;
	}

	get iterationCount() {
		return this[$iterationCount];
	}
	set iterationCount(count) {
		this[$iterationCount] = count;
	}

	getBytes(byteCount) {
		let position = this[$position];
		let bytes = crypto.pbkdf2Sync(Buffer.from(this[$key]), this.salt, this.iterationCount, position + byteCount, 'sha1');
		this[$position] += byteCount;
		let result = Buffer.alloc(byteCount);
		for (let i = 0; i < byteCount; i++) { result[i] = bytes[position + i]; }
		return result;
	}
}

module.exports = Rfc2898DeriveBytes;