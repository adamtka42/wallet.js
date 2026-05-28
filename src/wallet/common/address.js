/**
 * Address helpers.
 * @module wallet/common/address
 *
 * Address Format:
 *   - String form: "Q" prefix followed by 2 × addressSize lowercase hex characters.
 *     At the default size (64 bytes, NIST Category 5) this is a 129-character
 *     string. Legacy 20-byte strings are still accepted by the parser.
 *   - Byte form: `addressSize`-byte SHAKE-256 hash of (descriptor || public key)
 *   - Output is always lowercase hex; input parsing is case-insensitive for both
 *     the "Q"/"q" prefix and hex characters
 *   - EIP-55-style display checksums are available via `toChecksumAddress`.
 *     They use SHAKE-256 over the lowercase ASCII hex address body, not Keccak.
 *   - The address helpers are length-agnostic: `addressToString`,
 *     `stringToAddress`, and `isValidAddress` accept any (positive, even)
 *     byte length so that 20-byte, 64-byte, and future addresses can
 *     coexist. `getAddressFromPKAndDescriptor` accepts an explicit
 *     `addressSize` (default: {@link DEFAULT_ADDRESS_SIZE}).
 */

/** @typedef {import('./descriptor.js').Descriptor} Descriptor */
import { shake256 } from '@noble/hashes/sha3.js';
import { CryptoPublicKeyBytes } from '@theqrl/mldsa87';
import { DEFAULT_ADDRESS_SIZE } from './constants.js';

/**
 * Convert address bytes to string form.
 * @param {Uint8Array} addrBytes
 * @returns {string}
 * @throws {Error} If input is not a non-empty Uint8Array.
 */
function addressToString(addrBytes) {
  if (!(addrBytes instanceof Uint8Array) || addrBytes.length === 0) {
    throw new Error('address must be a non-empty Uint8Array');
  }
  const hex = [...addrBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `Q${hex}`;
}

/**
 * Convert address string to bytes.
 * @param {string} addrStr - Address string starting with 'Q' followed by an
 *   even number of hex characters (2 per byte). Length is implied by the
 *   string — 40 hex chars for a 20-byte address, 128 hex chars for a 64-byte
 *   address, etc.
 * @returns {Uint8Array} Decoded address bytes.
 * @throws {Error} If address format is invalid.
 */
function stringToAddress(addrStr) {
  if (typeof addrStr !== 'string') {
    throw new Error('address must be a string');
  }
  const trimmed = addrStr.trim();
  if (!trimmed.startsWith('Q') && !trimmed.startsWith('q')) {
    throw new Error('address must start with Q');
  }
  const hex = trimmed.slice(1);
  if (hex.length === 0 || hex.length % 2 !== 0) {
    throw new Error(`address must be Q + a non-empty even number of hex characters, got ${hex.length}`);
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('address contains invalid characters');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Return the EIP-55-style mixed-case representation of a QRL address using
 * SHAKE-256 instead of Keccak. The hash input is the lowercase ASCII hex
 * address body without the Q prefix.
 * @param {string} addrStr - QRL address string.
 * @returns {string} Checksummed QRL address string.
 * @throws {Error} If address format is invalid.
 */
function toChecksumAddress(addrStr) {
  const body = getAddressBody(addrStr);
  const lowerBody = body.toLowerCase();
  const hash = shake256
    .create({ dkLen: lowerBody.length / 2 })
    .update(new TextEncoder().encode(lowerBody))
    .digest();
  const hashHex = [...hash].map((b) => b.toString(16).padStart(2, '0')).join('');

  let checksummed = 'Q';
  for (let i = 0; i < lowerBody.length; i += 1) {
    const char = lowerBody[i];
    checksummed += char >= 'a' && char <= 'f' && Number.parseInt(hashHex[i], 16) >= 8 ? char.toUpperCase() : char;
  }

  return checksummed;
}

/**
 * Check if a string is a valid QRL checksum address.
 * Lowercase and uppercase address bodies are accepted as non-checksummed
 * compatibility forms. Mixed-case address bodies must match the SHAKE-256
 * checksum exactly.
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean} True if valid address format and checksum policy.
 */
function isValidChecksumAddress(addrStr) {
  try {
    const body = getAddressBody(addrStr);
    if (body === body.toLowerCase() || body === body.toUpperCase()) {
      return true;
    }
    return `Q${body}` === toChecksumAddress(addrStr);
  } catch {
    return false;
  }
}

/**
 * Check if a string is a valid QRL address.
 * Accepts any `Q`-prefixed even-length hex string — this lets 20-byte and
 * 64-byte addresses coexist. Lowercase and uppercase address bodies are
 * accepted as non-checksummed compatibility forms; mixed-case address bodies
 * must match the SHAKE-256 checksum.
 * @param {string} addrStr - Address string to validate.
 * @returns {boolean} True if valid address format.
 */
function isValidAddress(addrStr) {
  return isValidChecksumAddress(addrStr);
}

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
function getAddressFromPKAndDescriptor(pk, descriptor, addressSize = DEFAULT_ADDRESS_SIZE) {
  if (!(pk instanceof Uint8Array)) throw new Error('pk must be Uint8Array');
  if (!Number.isInteger(addressSize) || addressSize <= 0) {
    throw new Error('addressSize must be a positive integer');
  }

  const walletType = descriptor.type();
  let expectedPKLen;
  switch (walletType) {
    default:
      expectedPKLen = CryptoPublicKeyBytes;
  }
  if (pk.length !== expectedPKLen) {
    throw new Error(`pk must be ${expectedPKLen} bytes for wallet type ${walletType}`);
  }

  const descBytes = descriptor.toBytes();
  const input = new Uint8Array(descBytes.length + pk.length);
  input.set(descBytes, 0);
  input.set(pk, descBytes.length);
  return shake256.create({ dkLen: addressSize }).update(input).digest();
}

function getAddressBody(addrStr) {
  if (typeof addrStr !== 'string') {
    throw new Error('address must be a string');
  }
  const trimmed = addrStr.trim();
  if (!trimmed.startsWith('Q') && !trimmed.startsWith('q')) {
    throw new Error('address must start with Q');
  }
  const body = trimmed.slice(1);
  if (body.length === 0 || body.length % 2 !== 0) {
    throw new Error(`address must be Q + a non-empty even number of hex characters, got ${body.length}`);
  }
  if (!/^[0-9a-fA-F]+$/.test(body)) {
    throw new Error('address contains invalid characters');
  }
  return body;
}

export {
  addressToString,
  stringToAddress,
  isValidAddress,
  toChecksumAddress,
  isValidChecksumAddress,
  getAddressFromPKAndDescriptor,
};
