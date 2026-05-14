import { expect } from 'chai';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { CryptoPublicKeyBytes } from '@theqrl/mldsa87';
import { walletTestCases } from '../fixtures/ml_dsa_87.fixtures.js';
import { addressToString, getAddressFromPKAndDescriptor } from '../../src/wallet/common/address.js';
import { Descriptor } from '../../src/wallet/common/descriptor.js';
import { DESCRIPTOR_SIZE } from '../../src/wallet/common/constants.js';
import { WalletType } from '../../src/wallet/common/wallettype.js';

describe('wallet/common/address', () => {
  const tc = walletTestCases[0];
  const addrHex = tc.wantAddress.slice(1);

  it('addressToString prefixes Q and hex encodes bytes', () => {
    const addrBytes = hexToBytes(addrHex);
    expect(addressToString(addrBytes)).to.equal(tc.wantAddress);
  });

  it('addressToString throws on empty / non-Uint8 input', () => {
    expect(() => addressToString(new Uint8Array(0))).to.throw('address must be a non-empty Uint8Array');
    expect(() => addressToString(null)).to.throw('address must be a non-empty Uint8Array');
    expect(() => addressToString([1, 2, 3])).to.throw('address must be a non-empty Uint8Array');
  });

  it('addressToString accepts any positive Uint8Array length (size-agnostic)', () => {
    // Length is not fixed: 20 bytes, 64 bytes, and future sizes all round-trip.
    // is acceptable. This keeps the helper usable at any addressSize.
    expect(addressToString(new Uint8Array(20).fill(0xaa))).to.match(/^Q[0-9a-f]{40}$/);
    expect(addressToString(new Uint8Array(64).fill(0xaa))).to.match(/^Q[0-9a-f]{128}$/);
    expect(addressToString(Uint8Array.from([1, 2]))).to.equal('Q0102');
  });

  it('getAddressFromPKAndDescriptor rejects wrong pk length for ML-DSA-87', () => {
    const desc = new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0, 0]));
    const badPk = new Uint8Array(CryptoPublicKeyBytes - 1);
    expect(() => getAddressFromPKAndDescriptor(badPk, desc)).to.throw(`pk must be ${CryptoPublicKeyBytes} bytes`);
  });

  it('getAddressFromPKAndDescriptor derives expected address for vector', () => {
    const descBytes = hexToBytes(tc.extendedSeed.slice(0, DESCRIPTOR_SIZE * 2));
    const pk = hexToBytes(tc.wantPK);
    const addr = getAddressFromPKAndDescriptor(pk, new Descriptor(descBytes));
    expect(bytesToHex(addr)).to.equal(addrHex);
  });

  it('getAddressFromPKAndDescriptor matches go-qrllib 64-byte cross-vector', () => {
    const desc = new Descriptor(Uint8Array.from([WalletType.ML_DSA_87, 0, 0]));
    const pk = new Uint8Array(CryptoPublicKeyBytes).fill(0x42);
    const addr = getAddressFromPKAndDescriptor(pk, desc);
    expect(addressToString(addr)).to.equal(
      'Qf9e32f504239505ae25c8dd30a3837b8433602ce6ef5dd828806475878fea626757016824d8f08033f453ffeae85c0290b1ee7b55324884e12947d0086e6a040'
    );
  });

  it('getAddressFromPKAndDescriptor rejects non-Uint8 public keys', () => {
    const desc = new Descriptor(Uint8Array.from([1, 0, 0]));
    expect(() => getAddressFromPKAndDescriptor([1, 2, 3], desc)).to.throw('pk must be Uint8Array');
  });
});
