/**
 * Tests for the configurable address-size API.
 *
 * The address size is configurable. The 64-byte migration makes Category 5
 * the default while keeping explicit legacy sizes available for vectors.
 */
import { expect } from 'chai';
import { bytesToHex } from '@noble/hashes/utils.js';
import { CryptoPublicKeyBytes } from '@theqrl/mldsa87';
import { walletTestCases } from '../fixtures/ml_dsa_87.fixtures.js';
import { Wallet as MLDSA87 } from '../../src/wallet/ml_dsa_87/wallet.js';
import { newWalletFromExtendedSeed } from '../../src/wallet/factory.js';
import { getAddressFromPKAndDescriptor, addressToString, stringToAddress } from '../../src/wallet/common/address.js';
import { Descriptor } from '../../src/wallet/common/descriptor.js';
import { Seed, ExtendedSeed } from '../../src/wallet/common/seed.js';
import {
  ADDRESS_SIZE,
  ADDRESS_SIZE_CATEGORY_1,
  ADDRESS_SIZE_CATEGORY_5,
  DEFAULT_ADDRESS_SIZE,
} from '../../src/wallet/common/constants.js';

const tc = walletTestCases[0];

describe('configurable address size', () => {
  describe('constants', () => {
    it('NIST Category 1 = 20 bytes', () => {
      expect(ADDRESS_SIZE_CATEGORY_1).to.equal(20);
    });

    it('NIST Category 5 = 64 bytes', () => {
      expect(ADDRESS_SIZE_CATEGORY_5).to.equal(64);
    });

    it('default equals Category 5', () => {
      expect(DEFAULT_ADDRESS_SIZE).to.equal(ADDRESS_SIZE_CATEGORY_5);
      expect(DEFAULT_ADDRESS_SIZE).to.equal(64);
    });

    it('legacy ADDRESS_SIZE alias tracks the default', () => {
      expect(ADDRESS_SIZE).to.equal(DEFAULT_ADDRESS_SIZE);
    });
  });

  describe('getAddressFromPKAndDescriptor', () => {
    it('defaults to 64-byte address when addressSize is omitted', () => {
      const pk = new Uint8Array(CryptoPublicKeyBytes).fill(0xab);
      const desc = new Descriptor(Uint8Array.from([1, 0, 0]));
      const addr = getAddressFromPKAndDescriptor(pk, desc);
      expect(addr.length).to.equal(64);
    });

    it('returns exact requested length for 20, 32, and 64 byte sizes', () => {
      const pk = new Uint8Array(CryptoPublicKeyBytes).fill(0xab);
      const desc = new Descriptor(Uint8Array.from([1, 0, 0]));
      for (const size of [20, 32, 64]) {
        expect(getAddressFromPKAndDescriptor(pk, desc, size).length).to.equal(size);
      }
    });

    it('20-byte address is a prefix of the 64-byte address (SHAKE-256 XOF property)', () => {
      const pk = new Uint8Array(CryptoPublicKeyBytes).fill(0xab);
      const desc = new Descriptor(Uint8Array.from([1, 0, 0]));
      const addr20 = bytesToHex(getAddressFromPKAndDescriptor(pk, desc, 20));
      const addr64 = bytesToHex(getAddressFromPKAndDescriptor(pk, desc, 64));
      expect(addr64.startsWith(addr20)).to.equal(true);
    });

    it('rejects zero, negative, or non-integer addressSize', () => {
      const pk = new Uint8Array(CryptoPublicKeyBytes).fill(0xab);
      const desc = new Descriptor(Uint8Array.from([1, 0, 0]));
      expect(() => getAddressFromPKAndDescriptor(pk, desc, 0)).to.throw('addressSize must be a positive integer');
      expect(() => getAddressFromPKAndDescriptor(pk, desc, -1)).to.throw('addressSize must be a positive integer');
      expect(() => getAddressFromPKAndDescriptor(pk, desc, 2.5)).to.throw('addressSize must be a positive integer');
      expect(() => getAddressFromPKAndDescriptor(pk, desc, NaN)).to.throw('addressSize must be a positive integer');
      expect(() => getAddressFromPKAndDescriptor(pk, desc, '48')).to.throw('addressSize must be a positive integer');
    });
  });

  describe('Wallet constructor', () => {
    it('stores addressSize on the instance and uses it for getAddress()', () => {
      const w = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic);
      expect(w.addressSize).to.equal(64);
      expect(w.getAddress().length).to.equal(64);
      expect(w.getAddressStr()).to.equal(tc.wantAddress);
      w.zeroize();
    });

    it('accepts addressSize: 64 for NIST Category 5', () => {
      const w = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic, ADDRESS_SIZE_CATEGORY_5);
      expect(w.addressSize).to.equal(64);
      expect(w.getAddress().length).to.equal(64);
      expect(w.getAddressStr()).to.equal(tc.wantAddress);
      w.zeroize();
    });

    it('rejects invalid addressSize when constructed directly', () => {
      const seed = new Seed(new Uint8Array(48).fill(1));
      expect(
        () =>
          new MLDSA87({
            descriptor: new Descriptor(Uint8Array.from([1, 0, 0])),
            seed,
            pk: new Uint8Array(CryptoPublicKeyBytes),
            sk: new Uint8Array(100),
            addressSize: 0,
          })
      ).to.throw('addressSize must be a positive integer');
    });
  });

  describe('Wallet static factories', () => {
    it('newWallet() defaults to 64 bytes', () => {
      const w = MLDSA87.newWallet();
      expect(w.addressSize).to.equal(64);
      expect(w.getAddress().length).to.equal(64);
      w.zeroize();
    });

    it('newWallet(metadata, 64) produces 64-byte addresses', () => {
      const w = MLDSA87.newWallet([0, 0], ADDRESS_SIZE_CATEGORY_5);
      expect(w.addressSize).to.equal(64);
      expect(w.getAddress().length).to.equal(64);
      w.zeroize();
    });

    it('newWalletFromSeed() defaults to 64 bytes and honors explicit legacy 20 bytes', () => {
      const seed = new Seed(new Uint8Array(48).fill(0x11));
      const wDefault = MLDSA87.newWalletFromSeed(seed);
      const wLegacy = MLDSA87.newWalletFromSeed(seed, [0, 0], ADDRESS_SIZE_CATEGORY_1);
      expect(wDefault.getAddressStr().length - 1).to.equal(128);
      expect(wLegacy.getAddressStr().length - 1).to.equal(40);
      // Same seed, same pk: the legacy 20-byte address is a prefix of the 64-byte one.
      expect(wDefault.getAddressStr().slice(1)).to.match(new RegExp(`^${wLegacy.getAddressStr().slice(1)}`));
      wDefault.zeroize();
      wLegacy.zeroize();
    });

    it('newWalletFromExtendedSeed() defaults to 64 bytes and honors explicit legacy 20 bytes', () => {
      const ext = ExtendedSeed.from(tc.extendedSeed);
      const wDefault = MLDSA87.newWalletFromExtendedSeed(ext);
      const wLegacy = MLDSA87.newWalletFromExtendedSeed(ext, ADDRESS_SIZE_CATEGORY_1);
      expect(wDefault.getAddressStr()).to.equal(tc.wantAddress);
      expect(wLegacy.getAddressStr()).to.equal(`Q${tc.wantAddress.slice(1, 1 + ADDRESS_SIZE_CATEGORY_1 * 2)}`);
      wDefault.zeroize();
      wLegacy.zeroize();
    });

    it('newWalletFromMnemonic() defaults to 64 bytes and honors explicit legacy 20 bytes', () => {
      const wDefault = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic);
      const wLegacy = MLDSA87.newWalletFromMnemonic(tc.wantMnemonic, ADDRESS_SIZE_CATEGORY_1);
      expect(wDefault.getAddressStr()).to.equal(tc.wantAddress);
      expect(wLegacy.getAddressStr()).to.equal(`Q${tc.wantAddress.slice(1, 1 + ADDRESS_SIZE_CATEGORY_1 * 2)}`);
      wDefault.zeroize();
      wLegacy.zeroize();
    });
  });

  describe('auto-select factory', () => {
    it('newWalletFromExtendedSeed() auto-select defaults to 64 bytes', () => {
      const w = newWalletFromExtendedSeed(tc.extendedSeed);
      expect(w.getAddressStr()).to.equal(tc.wantAddress);
      w.zeroize();
    });

    it('newWalletFromExtendedSeed() auto-select honors explicit legacy 20 bytes', () => {
      const w = newWalletFromExtendedSeed(tc.extendedSeed, ADDRESS_SIZE_CATEGORY_1);
      expect(w.getAddressStr()).to.equal(`Q${tc.wantAddress.slice(1, 1 + ADDRESS_SIZE_CATEGORY_1 * 2)}`);
      w.zeroize();
    });
  });

  describe('address string helpers are length-agnostic', () => {
    it('round-trips 20-byte addresses', () => {
      const bytes = new Uint8Array(20).fill(0xcd);
      const str = addressToString(bytes);
      expect(str).to.equal('Q' + 'cd'.repeat(20));
      expect(Array.from(stringToAddress(str))).to.deep.equal(Array.from(bytes));
    });

    it('round-trips 64-byte addresses', () => {
      const bytes = new Uint8Array(64).fill(0xcd);
      const str = addressToString(bytes);
      expect(str).to.equal('Q' + 'cd'.repeat(64));
      expect(Array.from(stringToAddress(str))).to.deep.equal(Array.from(bytes));
    });

    it('round-trips arbitrary byte lengths', () => {
      for (const size of [1, 16, 20, 32, 48, 64]) {
        const bytes = new Uint8Array(size).fill(size & 0xff);
        expect(Array.from(stringToAddress(addressToString(bytes)))).to.deep.equal(Array.from(bytes));
      }
    });
  });

  describe('interop between sizes', () => {
    it('wallet constructed at 20 bytes and 64 bytes produce addresses with the same prefix for the same seed', () => {
      const ext = ExtendedSeed.from(tc.extendedSeed);
      const w20 = MLDSA87.newWalletFromExtendedSeed(ext, ADDRESS_SIZE_CATEGORY_1);
      const w64 = MLDSA87.newWalletFromExtendedSeed(ext, ADDRESS_SIZE_CATEGORY_5);
      expect(w64.getAddressStr().slice(1).startsWith(w20.getAddressStr().slice(1))).to.equal(true);
      w20.zeroize();
      w64.zeroize();
    });
  });
});
