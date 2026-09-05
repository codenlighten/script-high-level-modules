'use strict'

const crypto = require('crypto')
const { defineModule, apply } = require('../module')
const { emitReverse } = require('./bytes')
const int = require('./int')
const rsaJs = require('../rsa')
const { fromBE } = require('../num')

// RSA SIGNATURE VERIFICATION, in Bitcoin Script.
//
// There is no OP_CHECKRSASIG, and there does not need to be. RSASSA-PKCS1-v1_5
// verification is one equation:
//
//     s^e mod n  ==  0x00 ‖ 0x01 ‖ 0xFF… ‖ 0x00 ‖ DigestInfo ‖ SHA256(m)
//
// Every term on the right except the digest is a compile-time constant, and the
// digest is one opcode. Every term on the left is int.modexp, which is 17
// squarings for the usual e = 65537. What makes it cheap is not a trick; it is
// that Script's numbers are arbitrary precision post-Genesis, so a 2048-bit
// multiply is one OP_MUL. The probe measured 4096-bit operands working.
//
// TWO THINGS THAT ARE NOT DECORATION.
//
// The signature is pushed as a Script NUMBER (little-endian, sign-padded), not
// as the big-endian byte string a library hands you. Reversing 256 bytes on
// chain costs about a kilobyte of Script; asking the spender for the encoding
// Script already reads costs nothing. `rsa.encodeSignature` does the conversion
// off chain.
//
// And 0 ≤ s < n is checked. Without it s + n verifies too — same residue, same
// equation — so the spend would be malleable in the witness. The test kit
// attacks exactly that, so this is a proven property here, not a claim.

/**
 * The verification itself. `bounded` exists so tools/malleability-demo.js can
 * run the REAL code path with the range check removed, rather than a copy of it
 * that might not be the same code any more.
 */
function emitVerify (asm, { n, e, emLen }, { bounded = true, mode } = {}) {
  // Canonicity: exactly one signature value is accepted, not a residue class.
  //
  // One OP_WITHIN rather than two comparisons, and it RECORDS what it checked —
  // so int.modexp, which requires its base to be reduced, discharges that
  // requirement from this instead of the framework emitting the 257-byte
  // modulus again a few lines later.
  // Three states, and tools/malleability-demo.js walks all of them:
  //   'checked'  — the bound is emitted and the fact recorded;
  //   'omitted'  — the line is deleted, and the framework puts it back, because
  //                int.modexp REQUIRES a reduced base and says so;
  //   'asserted' — the fact is claimed without being checked, which is the only
  //                way to actually lose the property, and is why assert() will
  //                not take a claim without a written reason.
  const how = mode || (bounded ? 'checked' : 'omitted')
  if (how === 'checked') asm.bound('sig', 0n, n, '_sb')
  else if (how === 'asserted') asm.assert('sig', { range: { lo: 0n, hi: n } }, 'claimed and never checked — this is the demonstration')

  // the right-hand side: EM, assembled little-endian so no 256-byte reversal is
  // needed — only the 32-byte digest is reversed, and the rest is constant.
  asm.roll('msg'); asm.sha256('_h')
  emitReverse(asm, 32, '_h', '_hle')
  asm.data(Buffer.from(rsaJs.pkcs1Prefix(emLen)).reverse(), '_prefixLE')
  asm.cat('_emLE')
  asm.bin2num('_em')

  // the left-hand side, and the equation
  apply(asm, int.modexp, { n, e }, ['sig'], ['_r'])
  asm.numEqualVerify()
  return asm
}

/**
 * The module is parameterised by a KEY, and a module without cases is not a
 * module — so this is a factory rather than a constant. Hand it a key and the
 * messages to sign, and it hands back a module with a suite already attached.
 */
function verifier (key, messages = ['the quick brown fox jumps over the lazy dog', 'a', '']) {
  return defineModule({
  name: 'rsa.verify',
  doc: 'assert that sig is a PKCS#1 v1.5 / SHA-256 signature over msg under (n, e)',
  inputs: [
    { name: 'msg', kind: 'bytes', witness: true },
    { name: 'sig', kind: 'num', witness: true }
  ],
  outputs: [],
  hint: ({ msg }, { key }) => ({ sig: rsaJs.encodeSignature(rsaJs.sign(Buffer.from(msg), key.privateKey)) }),
  model: () => ({}),
  emit: (asm, params) => emitVerify(asm, params),
  // A signature verifier's real property is what it REFUSES, so the message is
  // attacked as well as the signature.
  attacks: (honest, params, name) => {
    if (name !== 'msg') return null
    const m = Buffer.from(honest.msg)
    const flipped = Buffer.from(m); flipped[0] ^= 0x01
    return [
      { label: 'one bit of the message flipped', value: flipped },
      { label: 'a byte appended', value: Buffer.concat([m, Buffer.from([0x00])]) },
      { label: 'the last byte removed', value: m.subarray(0, m.length - 1) },
      { label: 'the empty message', value: Buffer.alloc(0) }
    ]
  },
    cases: messages.map((msg) => ({
      name: `“${String(msg).slice(0, 30)}”`,
      inputs: { msg: Buffer.from(msg) },
      params: { n: key.n, e: key.e, emLen: key.emLen, key }
    })),
    notes: [
      'the spender pushes the signature as a Script number — see rsa.encodeSignature',
      'e is a compile-time constant: a secret exponent cannot be unrolled this way'
    ]
  })
}

/** Load the committed key fixture, so the suite is deterministic and fast. */
function fixtureKey () {
  const f = require('../../fixtures/rsa2048.json')
  return {
    n: BigInt('0x' + f.n),
    e: BigInt(f.e),
    emLen: f.emLen,
    privateKey: crypto.createPrivateKey(f.privatePem),
    message: f.message,
    signature: Buffer.from(f.signature, 'hex')
  }
}

module.exports = { verifier, emitVerify, fixtureKey, fromBE }
