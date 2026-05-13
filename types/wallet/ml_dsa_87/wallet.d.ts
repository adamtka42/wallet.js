export class Wallet {
    /**
     * Create a new random wallet(non-deterministic).
     * @param {[number, number]} [metadata=[0,0] ]
     * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
     * @returns {Wallet}
     */
    static newWallet(metadata?: [number, number], addressSize?: number): Wallet;
    /**
     * @param {Seed} seed
     * @param {[number, number]} [metadata=[0,0]]
     * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
     * @returns {Wallet}
     */
    static newWalletFromSeed(seed: Seed, metadata?: [number, number], addressSize?: number): Wallet;
    /**
     * @param {ExtendedSeed} extendedSeed
     * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
     * @returns {Wallet}
     */
    static newWalletFromExtendedSeed(extendedSeed: ExtendedSeed, addressSize?: number): Wallet;
    /**
     * @param {string} mnemonic
     * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
     * @returns {Wallet}
     */
    static newWalletFromMnemonic(mnemonic: string, addressSize?: number): Wallet;
    /**
     * Verify a signature. The descriptor is required so verification uses
     * the same domain-separated context that signing did.
     * @param {Uint8Array} signature
     * @param {Uint8Array} message
     * @param {Uint8Array} pk
     * @param {Descriptor} descriptor
     * @returns {boolean}
     */
    static verify(signature: Uint8Array, message: Uint8Array, pk: Uint8Array, descriptor: Descriptor): boolean;
    /**
     * @param {{descriptor: Descriptor, seed: Seed, pk: Uint8Array, sk: Uint8Array, addressSize?: number}} opts
     */
    constructor({ descriptor, seed, pk, sk, addressSize }: {
        descriptor: Descriptor;
        seed: Seed;
        pk: Uint8Array;
        sk: Uint8Array;
        addressSize?: number;
    });
    descriptor: Descriptor;
    seed: Seed;
    pk: Uint8Array<ArrayBufferLike>;
    sk: Uint8Array<ArrayBufferLike>;
    /**
     * Address length in bytes this wallet derives. Defaults to
     * {@link DEFAULT_ADDRESS_SIZE} (64, NIST Category 5 for the QRL address
     * migration). Pass an explicit address size for legacy vectors.
     * @type {number}
     */
    addressSize: number;
    extendedSeed: ExtendedSeed;
    /** @private */
    private _zeroized;
    /** @returns {Uint8Array} */
    getAddress(): Uint8Array;
    /** @returns {string} */
    getAddressStr(): string;
    /** @returns {Descriptor} */
    getDescriptor(): Descriptor;
    /**
     * @private
     * @throws {Error} If the wallet has been zeroized.
     */
    private _requireLive;
    /** @returns {ExtendedSeed} */
    getExtendedSeed(): ExtendedSeed;
    /** @returns {Seed} */
    getSeed(): Seed;
    /** @returns {string} hex(ExtendedSeed) */
    getHexExtendedSeed(): string;
    /** @returns {string} */
    getMnemonic(): string;
    /** @returns {Uint8Array} */
    getPK(): Uint8Array;
    /**
     * Returns a copy of the secret key.
     * @returns {Uint8Array}
     * @warning Caller is responsible for zeroing the returned buffer when done
     * (e.g. `sk.fill(0)`). The Wallet's `zeroize()` method cannot reach copies
     * returned by this method.
     */
    getSK(): Uint8Array;
    /**
     * Sign a message. The wallet binds the signature to its descriptor via
     * the domain-separated signing context; callers do not need to pass it
     * explicitly.
     * @param {Uint8Array} message
     * @returns {Uint8Array} Signature bytes.
     */
    sign(message: Uint8Array): Uint8Array;
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
    toJSON(): {
        address: string;
        pk: string;
    };
    /**
     * Securely zeroize sensitive key material.
     * Call this when the wallet is no longer needed to minimize
     * the window where secrets exist in memory.
     *
     * Note: JavaScript garbage collection may retain copies;
     * this provides best-effort zeroization.
     */
    zeroize(): void;
}
import { Descriptor } from '../common/descriptor.js';
import { Seed } from '../common/seed.js';
import { ExtendedSeed } from '../common/seed.js';
//# sourceMappingURL=wallet.d.ts.map