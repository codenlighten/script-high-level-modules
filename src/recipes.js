'use strict'

const crypto = require('crypto')
const bsv = require('@smartledger/bsv')
const compose = require('./compose')
const { defineModule, apply } = require('./module')
const txMod = require('./modules/tx')
const totp = require('./modules/totp')
const rsaModule = require('./modules/rsa')
const rsaJs = require('./rsa')

// COMPOSITIONS WORTH HAVING A NAME FOR.
//
// A recipe is not a new capability — every one of these is `pipe()` or `all()`
// over modules that already exist. It is here because a composition written out
// twice is a composition that will drift, and one of these had already been
// hand-wired in an example and in a deployment target with different names for
// the same value.

/**
 * An authenticator code for the time the transaction is locked to.
 *
 * `totp.verify` proves a code matches a time and can say nothing about WHICH
 * time, because the time arrives as a number the spender pushed. `tx.locktime`
 * produces that number from the transaction itself. Chained, the code must match
 * the time the spend is locked to.
 *
 * What it enforces, exactly: the transaction cannot be MINED before the time its
 * code is valid for. Not that the time is now — a spender may still claim a
 * later window and wait. What they cannot do is claim one time and spend at
 * another.
 */
function timelockedTotp (secret, { digits = 6, step = 30, algo = 'sha1', at, cases } = {}) {
  const keyCommitment = crypto.createHash('sha256').update(secret).digest()
  const code = at === undefined ? null : totp.totpCode(secret, at, { digits, step, algo })

  return compose.pipe('tx.locktime ▸ totp.verify', [
    { module: txMod.locktime, params: {}, as: { locktime: 'time' } },
    { module: totp.verify, params: { keyLen: secret.length, digits, step, algo, keyCommitment } }
  ], {
    doc: 'an authenticator code for the time the transaction is locked to',
    notes: [
      'the code must match the time the transaction is locked to, not one the spender chose',
      'enforces that the spend cannot be mined before that time — not that it is now',
      'single use: the secret is published in the unlocking script of the spend'
    ],
    cases: cases || (at === undefined ? [] : [
      { name: 'the code for the locked time', spend: { nLockTime: at }, inputs: { key: secret, code } },
      {
        name: 'the code for the next window',
        refuse: 'the code must match the time the transaction is locked to',
        spend: { nLockTime: at },
        inputs: { key: secret, code: totp.totpCode(secret, at + step, { digits, step, algo }) }
      },
      {
        name: 'a final sequence',
        refuse: 'consensus ignores nLockTime when the sequence is final, so the time proves nothing',
        spend: { sequence: 0xffffffff },
        inputs: { key: secret, code }
      }
    ])
  })
}

/**
 * The authority names the destination, and the chain pays whoever they named.
 *
 * This is the shape that output binding is for. `rsa.verify` proves an authority
 * signed a message; `tx.hashOutputs` proves what the spend commits to paying.
 * Between them the script BUILDS the output the message describes and requires
 * the transaction to match it — so the signature does not merely authorise a
 * spend, it directs one.
 *
 * The message is the instruction: twenty bytes of public-key hash and eight
 * little-endian bytes of amount. Serialising that as a transaction output is
 * three concatenations, because a P2PKH output is a fixed shape around those two
 * fields:
 *
 *     amount(8) ‖ 0x19 ‖ OP_DUP OP_HASH160 push20 ‖ pkh(20) ‖ OP_EQUALVERIFY OP_CHECKSIG
 *
 * Nothing about the destination is in the locking script. A different
 * instruction, signed by the same authority, pays somebody else — and one the
 * authority did not sign pays nobody.
 *
 * WHAT IT STILL CANNOT DO. The commitment covers the output SET, so the spend
 * must pay the named output and NOTHING ELSE: no change, no fee output. The fee
 * is therefore whatever the input holds minus the named amount, which the
 * authority has to know when it signs. That is a real constraint of pinning the
 * whole set rather than a part of it, and the alternative — SIGHASH_SINGLE,
 * which commits to one output — is a different covenant with different
 * malleability, not a free improvement.
 */
function authorityPays (rsaKey, { cases } = {}) {
  const params = { n: rsaKey.n, e: rsaKey.e, emLen: rsaKey.emLen }
  const verifier = rsaModule.verifier(rsaKey)

  return defineModule({
    name: 'rsa.verify ▸ tx.hashOutputs',
    doc: 'pay exactly what an RSA authority signed an instruction to pay',
    inputs: [
      { name: 'msg', kind: 'bytes', witness: true },
      { name: 'rsaSig', witness: true },
      { name: 'preimage', kind: 'bytes', witness: true }
    ],
    outputs: [],
    contextual: true,
    witnessFor: (ctx) => txMod.locktime.witnessFor(ctx),
    hint: ({ msg }) => (msg === undefined ? {} : { rsaSig: rsaJs.encodeSignature(rsaJs.sign(Buffer.from(msg), rsaKey.privateKey)) }),
    model: () => ({}),
    emit: (asm) => {
      // The instruction is read twice — once to check the signature over it, once
      // to build the output from it — so the first read is a copy. pipe() refuses
      // to make that copy silently, which is why this one is wired by hand.
      asm.pick('msg', '_m')
      apply(asm, verifier, params, ['_m', 'rsaSig'], [])

      asm.roll('msg')
      asm.splitAt(20, '_pkh', '_amt')                       // pkh ‖ amount(8, LE)
      asm.roll('_amt')
      asm.data(Buffer.from('1976a914', 'hex'), '_p1'); asm.cat('_o1')
      asm.roll('_pkh'); asm.cat('_o2')
      asm.data(Buffer.from('88ac', 'hex'), '_p2'); asm.cat('_txout')
      asm.hash256('_want')

      apply(asm, txMod.hashOutputs, {}, ['preimage'], ['_committed'])
      asm.equalVerify()
    },
    attacks: (honest, params2, name) => {
      if (name === 'msg') {
        const v = Buffer.from(honest.msg)
        const elsewhere = Buffer.from(v); elsewhere[0] ^= 0x01     // a different payee
        const more = Buffer.from(v); more[20] = (more[20] + 1) & 0xff  // a different amount
        return [
          { label: 'the instruction names a different payee', value: elsewhere },
          { label: 'the instruction names a different amount', value: more }
        ]
      }
      if (name === 'preimage') return txMod.locktime.attacks(honest, params2, name)
      if (name === 'rsaSig') {
        const n = rsaKey.n
        return [
          { label: 'the signature off by one', value: honest.rsaSig + 1n },
          { label: 'the same residue (+n)', value: honest.rsaSig + n },
          { label: 'no signature at all', value: 0n }
        ]
      }
      return null
    },
    cases: cases || [],
    notes: [
      'the destination is in the signed message, not in the locking script',
      'the commitment is over the whole output set, so the spend pays the named output and nothing else'
    ]
  })
}

/**
 * The cases every authorityPays instance should carry: it pays what was named,
 * and refuses everything else about the payment.
 */
function authorityPaysCases (payee, satoshis, elsewhere) {
  const msg = instruction(payee, satoshis)
  return [
    {
      name: 'paying exactly what the authority named',
      spend: { outputs: [instructedOutput(payee, satoshis)] },
      inputs: { msg }
    },
    {
      name: 'paying the right amount to a different address',
      refuse: 'the destination is in the signed instruction',
      spend: { outputs: [instructedOutput(elsewhere, satoshis)] },
      inputs: { msg }
    },
    {
      name: 'paying a different amount to the right address',
      refuse: 'the amount is in the signed instruction',
      spend: { outputs: [instructedOutput(payee, satoshis - 1)] },
      inputs: { msg }
    },
    {
      name: 'paying what was named, and something else besides',
      refuse: 'the commitment is over the whole output set',
      spend: { outputs: [instructedOutput(payee, satoshis), instructedOutput(elsewhere, 1)] },
      inputs: { msg }
    }
  ]
}

/** The instruction an authority signs: who, and how much. */
function instruction (address, satoshis) {
  const pkh = bsv.Address.fromString(String(address)).hashBuffer
  const amount = Buffer.alloc(8)
  amount.writeBigUInt64LE(BigInt(satoshis))
  return Buffer.concat([pkh, amount])
}

/** The transaction output that instruction describes. */
function instructedOutput (address, satoshis) {
  return new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(bsv.Address.fromString(String(address))),
    satoshis
  })
}

module.exports = { timelockedTotp, authorityPays, authorityPaysCases, instruction, instructedOutput }
