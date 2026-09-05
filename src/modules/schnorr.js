'use strict'

const { defineModule, apply } = require('../module')
const bytes = require('./bytes')
const ec = require('./ec')
const ecJs = require('../ec')
const schnorrJs = require('../schnorr')

// BIP-340 SCHNORR VERIFICATION.
//
// The same shape as `ecdsa.verify` and a better one to build on, for two
// reasons that both show up in a locking script.
//
// IT IS CANONICAL BY CONSTRUCTION. ECDSA admits (r, n − s) alongside (r, s), so
// a covenant gated on it has to impose a low-S rule to pick one, and the module
// here does — 267 bytes and a paragraph of explanation. A Schnorr signature over
// a message under a key is unique. There is nothing to legislate.
//
// THE KEY IS X-ONLY. Thirty-two bytes, with the even-Y point implied, which
// saves a byte on chain and costs a square root. That is the expensive direction
// to compute and the cheap one to check, so the spender supplies y and the
// script verifies y² = x³ + 7 and that y is even — the same trade that makes
// affine curve arithmetic affordable in the first place.
//
// The challenge is a tagged hash, and the tag is a compile-time constant:
// SHA256(tag) twice, then r ‖ pk ‖ m. Three concatenations and one OP_SHA256,
// because Bitcoin has that opcode. The verification equation is R = s·G − e·P,
// which is u₁·G + u₂·Q with u₂ = n − e — the interleaved ladder, unchanged.

const P = ecJs.P
const N = ecJs.N

/** e = int(tagged_hash("BIP0340/challenge", r ‖ pk ‖ m)) mod n, on the stack. */
function emitChallenge (asm, rName, pkName, msgName, nName, out) {
  asm.data(schnorrJs.challengeTagPrefix(), '_tag')      // SHA256(tag) ‖ SHA256(tag)
  asm.pick(rName, '_cr'); asm.cat('_c1')
  asm.pick(pkName, '_cp'); asm.cat('_c2')
  asm.roll(msgName); asm.cat('_c3')
  asm.sha256('_ch')
  apply(asm, bytes.beToNum, { width: 32 }, ['_ch'], ['_e0'])
  asm.pick(nName, '_cn'); asm.mod(out)
}

/**
 * The module is built for a set of messages, because a module without cases is
 * not a module and the cases need real signatures.
 */
function verifier (messages = ['script-modules', '', 'a longer message than one block holds, several times over, to be sure of it'], { cases } = {}) {
  const secret = 0xb7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfefn
  const pubkey = schnorrJs.publicKey(secret)

  return defineModule({
  name: 'schnorr.verify',
  doc: 'assert that sig is a BIP-340 Schnorr signature on msg under the x-only key',
  inputs: [
    { name: 'msg', kind: 'bytes', witness: true },
    { name: 'pubkey', kind: 'bytes', width: 32, witness: true },
    { name: 'sig', kind: 'bytes', width: 64, witness: true },
    { name: 'py', witness: true },
    ...ec.shamirInputs('sh')
  ],
  outputs: [],
  maxWitnessAttacks: 8,
  alwaysAttack: ['msg', 'pubkey', 'sig', 'py'],
  hint: ({ msg, pubkey, sig }) => {
    const p = schnorrJs.liftX(schnorrJs.toInt(pubkey))
    if (!p) return {}
    const s = schnorrJs.toInt(sig.subarray(32))
    const e = schnorrJs.challenge(sig.subarray(0, 32), pubkey, msg)
    return {
      py: p.y,
      ...ec.shamirWitness('sh', 256, s, ecJs.mod(-e, N), p, {})
    }
  },
  model: () => ({}),
  emit: (asm) => {
    asm.num(N, '_N'); asm.num(P, '_P')

    // the signature is r ‖ s, both big-endian
    asm.roll('sig'); asm.splitAt(32, '_rb', '_sb')
    apply(asm, bytes.beToNum, { width: 32 }, ['_sb'], ['_s'])
    asm.pick('_s', '_sc'); asm.num(0, '_z0'); asm.pick('_N', '_n0'); asm.withinVerify()   // 0 ≤ s < n

    // the challenge, over the SIGNED bytes rather than any value derived here
    emitChallenge(asm, '_rb', 'pubkey', 'msg', '_N', '_e')

    // lift the x-only key: y is supplied, and checked
    apply(asm, bytes.beToNum, { width: 32 }, ['pubkey'], ['_px'])
    asm.pick('py', '_y0'); asm.num(0, '_z1'); asm.pick('_P', '_p0'); asm.withinVerify()   // 0 ≤ y < p
    asm.pick('py', '_y1'); asm.num(2, '_two'); asm.mod('_par')
    asm.num(0, '_z2'); asm.numEqualVerify()                                               // y is even
    asm.pick('py', '_y2'); asm.pick('py', '_y3'); asm.mul('_yy')
    asm.pick('_P', '_p1'); asm.mod('_lhs')
    asm.pick('_px', '_x1'); asm.pick('_px', '_x2'); asm.mul('_xx')
    asm.pick('_px', '_x3'); asm.mul('_xxx')
    asm.num(7, '_b'); asm.add('_rhs0')
    asm.pick('_P', '_p2'); asm.mod('_rhs')
    asm.numEqualVerify()                                                                  // y² = x³ + 7

    // R = s·G + (n − e)·P
    asm.pick('_N', '_n1'); asm.pick('_e', '_e1'); asm.sub('_u2')
    asm.roll('_px'); asm.rename('qx'); asm.roll('py'); asm.rename('qy')
    ec.emitShamir(asm, { prefix: 'sh', bits: 256 }, ['_s', '_u2'], ['qx', 'qy'], ['rx', 'ry'])

    // R.y must be even, and R.x must be the r that was signed
    asm.roll('ry'); asm.num(2, '_two2'); asm.mod('_rpar')
    asm.num(0, '_z3'); asm.numEqualVerify()
    apply(asm, bytes.beToNum, { width: 32 }, ['_rb'], ['_r'])
    asm.roll('rx'); asm.numEqualVerify()

    for (const dead of ['_s', '_u2', '_e', 'qx', 'qy', '_N', '_P']) asm.discard(dead)
  },
  attacks: (honest, params, name) => {
    if (name === 'py') {
      return [
        { label: 'the odd y of the same x', value: P - honest.py },
        { label: 'y off by one', value: honest.py + 1n },
        { label: 'y = 0', value: 0n }
      ]
    }
    const v = honest[name]
    if (Buffer.isBuffer(v) && v.length) {
      const first = Buffer.from(v); first[0] ^= 0x01
      const last = Buffer.from(v); last[v.length - 1] ^= 0x01
      return [
        { label: `${name}: first byte changed`, value: first },
        { label: `${name}: last byte changed`, value: last },
        { label: `${name}: truncated`, value: v.subarray(0, v.length - 1) }
      ]
    }
    return ec.ladderAttacks(honest, name, P)
  },
    cases: cases || messages.map((m) => {
      const msg = Buffer.from(m)
      return {
        name: `“${String(m).slice(0, 30)}”`,
        inputs: { msg, pubkey, sig: schnorrJs.sign(secret, msg) }
      }
    }),
    notes: [
      'canonical by construction: no low-S rule, because a Schnorr signature is unique',
      'the x-only key costs a square root, supplied by the spender and checked'
    ]
  })
}

/**
 * Cases built from BIP-340's own published vectors — the positive ones as
 * spends that must be accepted, and the NEGATIVE ones as spends that must be
 * refused.
 *
 * The negative vectors are the valuable half. They were written to catch the
 * misreadings an implementation makes about itself: a public key that is not on
 * the curve, an r past the field size, an s past the group order, an odd R.y, a
 * negated message, a negated s, and the two where sG − eP is the point at
 * infinity. Every one of them is a way to be wrong that verifying a few honest
 * signatures would never reveal.
 *
 * A refused vector needs a witness anyway, or the harness refuses it before the
 * script gets a chance and the case proves nothing about the script. Where an
 * honest witness cannot exist — no y for that x — a zero-filled one of the right
 * shape is supplied, and the script refuses it at the point it should: the
 * y² = x³ + 7 check, before the ladder is ever entered.
 */
function bip340Cases (which = null) {
  const fs = require('fs')
  const path = require('path')
  const csv = fs.readFileSync(path.join(__dirname, '..', '..', 'fixtures', 'bip340-test-vectors.csv'), 'utf8')
  const rows = csv.trim().split('\n').slice(1).map((line) => {
    const [index, secret, pubkey, aux, message, sig, result, comment] = line.split(',')
    return {
      index: Number(index),
      pubkey: Buffer.from(pubkey, 'hex'),
      msg: Buffer.from(message, 'hex'),
      sig: Buffer.from(sig, 'hex'),
      expect: result.trim().toUpperCase() === 'TRUE',
      comment: (comment || '').trim()
    }
  })

  const chosen = which ? rows.filter((r) => which.includes(r.index)) : rows
  const TAPE = 33 * (1 + 2 * 256 + 1)

  // Forgeries are attacked once, on the first accepted vector. Repeating them
  // for every honest signature would multiply the run time and prove the same
  // thing nine times; the vectors are here for the failure modes they encode,
  // not to re-attack the witness.
  let attacked = false

  return chosen.map((v) => {
    const label = `BIP-340 vector ${v.index}${v.comment ? ' — ' + v.comment.slice(0, 44) : ''}`
    if (v.expect) {
      const first = !attacked
      attacked = true
      return { name: label, inputs: { msg: v.msg, pubkey: v.pubkey, sig: v.sig }, skipAttacks: !first }
    }
    return {
      name: label,
      refuse: v.comment || 'the standard says this signature is invalid',
      inputs: { msg: v.msg, pubkey: v.pubkey, sig: v.sig, py: 0n, shtape: Buffer.alloc(TAPE) }
    }
  })
}

module.exports = { verifier, bip340Cases, emitChallenge, P, N }
