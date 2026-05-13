/**
 * ML-DSA-87 Wallet object encapsulating descriptor, seeds and keypair.
 * @module wallet/ml_dsa_87/wallet
 */

import { bytesToHex } from '@noble/hashes/utils.js';
import { randomBytes } from '../../utils/random.js';
import { mnemonicToBin, binToMnemonic } from '../misc/mnemonic.js';
import { getAddressFromPKAndDescriptor, addressToString } from '../common/address.js';
import { DEFAULT_ADDRESS_SIZE } from '../common/constants.js';
import { signingContext } from '../common/context.js';
import { Descriptor } from '../common/descriptor.js';
import { Seed, ExtendedSeed } from '../common/seed.js';
import { newMLDSA87Descriptor } from './descriptor.js';
import { keygen, sign, verify } from './crypto.js';

/**
 * Property names that carry secret material. Kept non-enumerable so that
 * `Object.keys`, `JSON.stringify`, `{...wallet}`, and default `util.inspect`
 * do not surface them — defense-in-depth against accidental leakage through
 * logs, crash reporters, serializers, etc. Direct access (e.g. `w.sk`)
 * still works for legitimate callers; see `toJSON()` for the redacted
 * public shape.
 */
const SECRET_FIELDS = ['seed', 'sk', 'extendedSeed', '_zeroized'];

class Wallet {
  /**
   * @param {{descriptor: Descriptor, seed: Seed, pk: Uint8Array, sk: Uint8Array, addressSize?: number}} opts
   */
  constructor({ descriptor, seed, pk, sk, addressSize = DEFAULT_ADDRESS_SIZE }) {
    if (!Number.isInteger(addressSize) || addressSize <= 0) {
      throw new Error('addressSize must be a positive integer');
    }
    this.descriptor = descriptor;
    this.seed = seed;
    this.pk = pk;
    this.sk = sk;
    /**
     * Address length in bytes this wallet derives. Defaults to
     * {@link DEFAULT_ADDRESS_SIZE} (64, NIST Category 5 for the QRL address
     * migration). Pass an explicit address size for legacy vectors.
     * @type {number}
     */
    this.addressSize = addressSize;
    this.extendedSeed = ExtendedSeed.newExtendedSeed(descriptor, seed);
    /** @private */
    this._zeroized = false;
    for (const name of SECRET_FIELDS) {
      Object.defineProperty(this, name, { enumerable: false });
    }
  }

  /**
   * Create a new random wallet(non-deterministic).
   * @param {[number, number]} [metadata=[0,0] ]
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWallet(metadata = [0, 0], addressSize = DEFAULT_ADDRESS_SIZE) {
    const descriptor = newMLDSA87Descriptor(metadata);
    const seedBytes = randomBytes(48);
    try {
      const seed = new Seed(seedBytes);
      const { pk, sk } = keygen(seed);
      return new Wallet({ descriptor, seed, pk, sk, addressSize });
    } finally {
      seedBytes.fill(0);
    }
  }

  /**
   * @param {Seed} seed
   * @param {[number, number]} [metadata=[0,0]]
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWalletFromSeed(seed, metadata = [0, 0], addressSize = DEFAULT_ADDRESS_SIZE) {
    const descriptor = newMLDSA87Descriptor(metadata);
    const { pk, sk } = keygen(seed);
    return new Wallet({ descriptor, seed, pk, sk, addressSize });
  }

  /**
   * @param {ExtendedSeed} extendedSeed
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWalletFromExtendedSeed(extendedSeed, addressSize = DEFAULT_ADDRESS_SIZE) {
    const descriptor = extendedSeed.getDescriptor();
    const seed = extendedSeed.getSeed();
    const { pk, sk } = keygen(seed);
    return new Wallet({ descriptor, seed, pk, sk, addressSize });
  }

  /**
   * @param {string} mnemonic
   * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
   * @returns {Wallet}
   */
  static newWalletFromMnemonic(mnemonic, addressSize = DEFAULT_ADDRESS_SIZE) {
    const bin = mnemonicToBin(mnemonic);
    try {
      const extendedSeed = new ExtendedSeed(bin);
      return this.newWalletFromExtendedSeed(extendedSeed, addressSize);
    } finally {
      bin.fill(0);
    }
  }

  /** @returns {Uint8Array} */
  getAddress() {
    return getAddressFromPKAndDescriptor(this.pk, this.descriptor, this.addressSize);
  }

  /** @returns {string} */
  getAddressStr() {
    return addressToString(this.getAddress());
  }

  /** @returns {Descriptor} */
  getDescriptor() {
    return new Descriptor(this.descriptor.toBytes());
  }

  /**
   * @private
   * @throws {Error} If the wallet has been zeroized.
   */
  _requireLive() {
    if (this._zeroized) {
      throw new Error('Wallet has been zeroized');
    }
  }

  /** @returns {ExtendedSeed} */
  getExtendedSeed() {
    this._requireLive();
    return ExtendedSeed.from(this.extendedSeed.toBytes());
  }

  /** @returns {Seed} */
  getSeed() {
    this._requireLive();
    return new Seed(this.seed.toBytes());
  }

  /** @returns {string} hex(ExtendedSeed) */
  getHexExtendedSeed() {
    this._requireLive();
    return `0x${bytesToHex(this.getExtendedSeed().toBytes())}`;
  }

  /** @returns {string} */
  getMnemonic() {
    this._requireLive();
    return binToMnemonic(this.getExtendedSeed().toBytes());
  }

  /** @returns {Uint8Array} */
  getPK() {
    return this.pk.slice();
  }

  /**
   * Returns a copy of the secret key.
   * @returns {Uint8Array}
   * @warning Caller is responsible for zeroing the returned buffer when done
   * (e.g. `sk.fill(0)`). The Wallet's `zeroize()` method cannot reach copies
   * returned by this method.
   */
  getSK() {
    this._requireLive();
    return this.sk.slice();
  }

  /**
   * Sign a message. The wallet binds the signature to its descriptor via
   * the domain-separated signing context; callers do not need to pass it
   * explicitly.
   * @param {Uint8Array} message
   * @returns {Uint8Array} Signature bytes.
   */
  sign(message) {
    this._requireLive();
    return sign(this.sk, message, signingContext(this.descriptor));
  }

  /**
   * Verify a signature. The descriptor is required so verification uses
   * the same domain-separated context that signing did.
   * @param {Uint8Array} signature
   * @param {Uint8Array} message
   * @param {Uint8Array} pk
   * @param {Descriptor} descriptor
   * @returns {boolean}
   */
  static verify(signature, message, pk, descriptor) {
    return verify(signature, message, pk, signingContext(descriptor));
  }

  /**
   * Redacted JSON shape used by `JSON.stringify`. Returns only public
   * information — address and public key. Secret material (sk, seed,
   * extendedSeed) is intentionally excluded so that accidental
   * serialization through logs, crash reporters, telemetry, structured
   * clone, or object spreading cannot leak secrets.
   *
   * Callers who need the raw material must ask for it explicitly via
   * `getSK()`, `getSeed()`, `getExtendedSeed()`, or `getMnemonic()`.
   *
   * @returns {{address: string, pk: string}}
   */
  toJSON() {
    return {
      address: this.getAddressStr(),
      pk: `0x${bytesToHex(this.pk)}`,
    };
  }

  /**
   * Safe representation for Node's `util.inspect` / `console.log`.
   * Never includes secret material.
   * @returns {string}
   */
  [Symbol.for('nodejs.util.inspect.custom')]() {
    const state = this._zeroized ? 'zeroized' : 'live';
    const addr = this._zeroized ? '<zeroized>' : this.getAddressStr();
    return `Wallet { address: '${addr}', state: '${state}', <secret material redacted> }`;
  }

  /**
   * Securely zeroize sensitive key material.
   * Call this when the wallet is no longer needed to minimize
   * the window where secrets exist in memory.
   *
   * Note: JavaScript garbage collection may retain copies;
   * this provides best-effort zeroization.
   */
  zeroize() {
    if (this.sk) {
      this.sk.fill(0);
      this.sk = null;
    }
    if (this.seed) {
      this.seed.zeroize();
      this.seed = null;
    }
    if (this.extendedSeed) {
      this.extendedSeed.zeroize();
      this.extendedSeed = null;
    }
    this._zeroized = true;
  }
}

export { Wallet };
