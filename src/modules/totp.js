'use strict'

const crypto = require('crypto')
const { defineModule } = require('../module')
const { emitHmac } = require('./hmac')
const { emitReverse } = require('./bytes')

// TOTP — RFC 6238 — verified inside a locking script.
//
// A six-digit authenticator code is not a new cryptographic primitive. It is
// HMAC-SHA1 of a counter, a truncation that reads its own offset out of the
// digest, and a reduction mod 10^d. Every step of that is one or two opcodes
// once HMAC exists, which is the whole point of building the layers in order.
//
// TWO THINGS ANYONE DEPLOYING THIS MUST KNOW.
//
// The shared secret is supplied by the spender, so it is published in the
// unlocking script of the spending transaction, in the clear, forever. A TOTP
// gate is therefore SINGLE USE: after the first spend the secret is public and
// anyone can compute every future code. That is inherent to verifying a
// symmetric secret on a public ledger, not a defect in this module.
//
// And `time` here is an input. On chain it has to come from something consensus
// enforces — nLockTime read out of the sighash preimage, with a non-final
// sequence — or the spender simply picks whatever time makes their code valid.
// That binding is the predicate layer's job; this module verifies the code.

const DIGITS = { 6: 1000000n, 8: 100000000n }

/** The reference: RFC 4226 dynamic truncation over RFC 2104 HMAC. */
function totpCode (key, time, { step = 30, digits = 6, algo = 'sha1' } = {}) {
  const counter = BigInt(time) / BigInt(step)
  const c = Buffer.alloc(8)
  c.writeBigUInt64BE(counter)
  const mac = crypto.createHmac(algo, Buffer.from(key)).update(c).digest()
  const offset = mac[mac.length - 1] & 0x0f
  const bin = BigInt(mac.readUInt32BE(offset) & 0x7fffffff)
  return bin % (10n ** BigInt(digits))
}

const verify = defineModule({
  name: 'totp.verify',
  doc: 'assert that `code` is the RFC 6238 code for `time` under a committed secret',
  inputs: [
    { name: 'key', kind: 'bytes', witness: true },
    { name: 'time', kind: 'num' },
    { name: 'code', kind: 'num', witness: true }
  ],
  outputs: [],
  hint: ({ key, time }, params) => ({ code: totpCode(key, time, params) }),
  model: () => ({}),
  emit: (asm, params) => {
    const { step = 30, digits = 6, algo = 'sha1', keyLen, keyCommitment } = params
    const modulus = DIGITS[digits]
    if (!modulus) throw new Error(`totp: ${digits} digits is not one of 6 or 8`)

    // The secret is checked against a commitment in the script, so the coin is
    // locked to ONE secret rather than to whoever brings a self-consistent pair.
    if (keyCommitment) {
      asm.pick('key', '_k1'); asm.sha256('_kh')
      asm.data(keyCommitment, '_kc'); asm.equalVerify()
    }

    // counter = floor(time / step), as eight big-endian bytes. OP_DIV truncates
    // toward zero, which is floor only for a non-negative time — so bound it.
    asm.pick('time', '_t1'); asm.num(0, '_zero'); asm.geVerify()
    asm.roll('time'); asm.num(step, '_step'); asm.div('_counter')
    asm.num2bin(8, '_ctrLE')
    emitReverse(asm, 8, '_ctrLE', '_ctr')

    emitHmac(asm, { algo, keyLen }, 'key', '_ctr', '_mac')

    // dynamic truncation: the last nibble of the digest says where to read.
    const macLen = algo === 'sha1' ? 20 : 32
    asm.pick('_mac', '_m1'); asm.splitAt(macLen - 1, '_mhead', '_mlast')
    asm.nip()                                       // drop the head, keep the last byte
    asm.data(Buffer.from([0x0f]), '_nib'); asm.and('_om')
    asm.bin2num('_offset')

    asm.roll('_mac'); asm.swap()                    // [.., mac, offset]
    asm.split('_pre', '_post')                      // mac[0:offset], mac[offset:]
    asm.nip()                                       // drop the prefix
    asm.splitAt(4, '_word', '_tail'); asm.drop()    // the four bytes at the offset

    // mask the sign bit (RFC 4226) and reduce
    asm.data(Buffer.from('7fffffff', 'hex'), '_mask'); asm.and('_masked')
    emitReverse(asm, 4, '_masked', '_le')
    asm.data(Buffer.from([0]), '_z'); asm.cat('_lep'); asm.bin2num('_bin')
    asm.num(modulus, '_mod'); asm.mod('_code')

    asm.roll('code'); asm.numEqualVerify()
  },
  attacks: (honest, params, name) => {
    if (name === 'code') {
      // The near-misses that matter: a neighbouring code, the code from the
      // neighbouring time step, and the same code plus the modulus — which is
      // the same residue and would pass a check written as a congruence.
      const step = params.step || 30
      const mod = DIGITS[params.digits || 6]
      return [
        { label: 'the code one higher', value: honest.code + 1n },
        { label: 'the previous window’s code', value: totpCode(honest.key, Number(honest.time) - step, params) },
        { label: 'the next window’s code', value: totpCode(honest.key, Number(honest.time) + step, params) },
        { label: 'the same residue (+10^d)', value: honest.code + mod },
        { label: 'zero', value: 0n }
      ]
    }
    if (name !== 'key') return null
    const k = Buffer.from(honest.key)
    const flipped = Buffer.from(k); flipped[0] ^= 0x01
    return [
      { label: 'one byte of the secret changed', value: flipped },
      { label: 'the secret truncated', value: k.subarray(0, k.length - 1) },
      { label: 'a zero secret', value: Buffer.alloc(k.length) }
    ]
  },
  // RFC 6238's own test vectors: the secret is the ASCII "12345678901234567890",
  // and the published eight-digit codes are asserted in tools/rfc6238-check.js.
  cases: [59, 1111111109, 1111111111, 1234567890, 2000000000].flatMap((time) => [6, 8].map((digits) => ({
    name: `t=${time}, ${digits} digits`,
    inputs: { key: Buffer.from('12345678901234567890'), time: BigInt(time) },
    params: { keyLen: 20, digits, step: 30, algo: 'sha1' }
  }))),
  notes: [
    'single use: the secret is published in the unlocking script of the spend',
    'time must be bound to nLockTime by the surrounding predicate, or it is the spender’s choice — `tx.locktime` is that binding, and examples/totp-timelock.js wires the two together'
  ]
})

/** The same module with the secret pinned to a commitment in the script. */
function committed (key, opts = {}) {
  const commitment = crypto.createHash('sha256').update(key).digest()
  return {
    ...verify,
    name: 'totp.verify (committed secret)',
    cases: verify.cases.map((c) => ({ ...c, params: { ...c.params, keyCommitment: commitment, keyLen: key.length, ...opts }, inputs: { ...c.inputs, key } }))
  }
}

module.exports = { verify, committed, totpCode, DIGITS }
