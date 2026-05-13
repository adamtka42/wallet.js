export type Descriptor = import("./descriptor.js").Descriptor;
/**
 * Convert address bytes to string form.
 * @param {Uint8Array} addrBytes
 * @returns {string}
 * @throws {Error} If input is not a non-empty Uint8Array.
 */
export function addressToString(addrBytes: Uint8Array): string;
/**
 * Convert address string to bytes.
 * @param {string} addrStr - Address string starting with 'Q' followed by an
 *   even number of hex characters (2 per byte). Length is implied by the
 *   string — 40 hex chars for a 20-byte address, 128 hex chars for a 64-byte
 *   address, etc.
 * @returns {Uint8Array} Decoded address bytes.
 * @throws {Error} If address format is invalid.
 */
export function stringToAddress(addrStr: string): Uint8Array;
/**
 * Check if a string is a valid QRL address format (structure only).
 * Accepts any `Q`-prefixed even-length hex string — this lets 20-byte and
 * 64-byte addresses coexist. QRL addresses contain no checksum; applications
 * should add their own confirmation or checksum layer.
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean} True if valid address format.
 */
export function isValidAddress(addrStr: string): boolean;
/**
 * Derive an address from a public key and descriptor.
 * @param {Uint8Array} pk
 * @param {Descriptor} descriptor
 * @param {number} [addressSize=DEFAULT_ADDRESS_SIZE] Address length in bytes.
 *   Defaults to 64 bytes for the QRL address migration. Pass an explicit
 *   size for legacy vectors.
 * @returns {Uint8Array} `addressSize`-byte address.
 * @throws {Error} If pk length mismatch or addressSize is not a positive integer.
 */
export function getAddressFromPKAndDescriptor(pk: Uint8Array, descriptor: Descriptor, addressSize?: number): Uint8Array;
//# sourceMappingURL=address.d.ts.map