/**
 * Constants used across wallet components.
 * @module wallet/common/constants
 */

/** @type {number} Size in bytes of the 3-byte descriptor */
export const DESCRIPTOR_SIZE = 3;

/**
 * @type {number} Address length in bytes for NIST Category 1 post-quantum
 * security. 20 bytes produces a `Q` + 40 hex-character address string.
 */
export const ADDRESS_SIZE_CATEGORY_1 = 20;

/**
 * @type {number} Address length in bytes for NIST Category 5 post-quantum
 * security. 64 bytes produces a `Q` + 128 hex-character
 * address string.
 */
export const ADDRESS_SIZE_CATEGORY_5 = 64;

/**
 * @type {number} Default address length in bytes.
 * Defaults to {@link ADDRESS_SIZE_CATEGORY_5} (64 bytes) for the 64-byte
 * QRL address migration. Callers that need legacy vectors can pass an
 * explicit `addressSize` to address helpers and `Wallet` factory methods.
 */
export const DEFAULT_ADDRESS_SIZE = ADDRESS_SIZE_CATEGORY_5;

/**
 * @type {number} Backwards-compatible alias for {@link DEFAULT_ADDRESS_SIZE}.
 * @deprecated Prefer {@link DEFAULT_ADDRESS_SIZE}, {@link ADDRESS_SIZE_CATEGORY_1},
 * or {@link ADDRESS_SIZE_CATEGORY_5} depending on intent.
 */
export const ADDRESS_SIZE = DEFAULT_ADDRESS_SIZE;

/** @type {number} Seed length in bytes */
export const SEED_SIZE = 48;

/** @type {number} Extended seed length in bytes */
export const EXTENDED_SEED_SIZE = DESCRIPTOR_SIZE + SEED_SIZE;
