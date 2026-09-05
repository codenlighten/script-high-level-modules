'use strict'

const bsv = require('@smartledger/bsv')
const { defineModule, apply } = require('../module')
const int = require('./int')
const ec = require('./ec')
const ecJs = require('../ec')

// ECDSA VERIFICATION OVER AN ARBITRARY MESSAGE.
//
// Bitcoin has OP_CHECKSIG, and OP_CHECKSIG answers exactly one question: is
// this a valid signature over THIS transaction's sighash? It cannot be asked
// whether an oracle signed a temperature reading, a price, or a shipping
// manifest. That gap is why the BSV ecosystem reaches for Rabin signatures —
// they are verifiable with OP_MUL and OP_MOD, so they need no curve arithmetic
// at all.
//
// The gap is not a limit of Script, only of that one opcode. ECDSA verification
// is
//
//     u₁ = z·s⁻¹,  u₂ = r·s⁻¹   (mod n)
//     R  = u₁·G + u₂·Q
//     valid  ⟺  r ≡ R.x  (mod n)
//
// and every term is a module that already exists here. So an oracle can sign
// with the secp256k1 key it already has — the same key that signs its
// transactions, the same key in its certificate — and a covenant can check that
// signature over any message at all.
//
// It costs about 195 KB of Script. That is the honest headline: this is the
// most expensive construction in this repository by an order of magnitude, and
// whether it is the right answer depends entirely on whether reusing a standard
// key is worth more than the fee. Rabin is far cheaper; it is also a key the
// oracle has to hold specifically for this.
//
// s⁻¹ is witnessed, not computed. It is the only inverse in the equation that
// is not already inside a ladder, and computing it would mean the extended
// Euclidean algorithm in Script.

const N = ecJs.N
const P = ecJs.P

/** Everything the spender must supply for one verification. */
function witness ({ z, r, s, q }) {
  const sinv = ecJs.inv(ecJs.mod(s, N), N)
  const u1 = ecJs.mod(z * sinv, N)
  const u2 = ecJs.mod(r * sinv, N)
  return {
    sinv,
    ...ec.shamirWitness('sh', 256, u1, u2, q, {})
  }
}

function verifier (cases, { lowS = true } = {}) {
  return defineModule({
    name: 'ecdsa.verify',
    doc: 'assert (r, s) is a secp256k1 ECDSA signature on z under the public key Q',
    inputs: [
      { name: 'z', witness: true },
      { name: 'r', witness: true },
      { name: 's', witness: true },
      { name: 'qx', witness: true },
      { name: 'qy', witness: true },
      { name: 'sinv', witness: true },
      ...ec.shamirInputs('sh')
    ],
    outputs: [],
    maxWitnessAttacks: 10,
    alwaysAttack: ['z', 'r', 's', 'qx', 'qy', 'sinv', 'shtape'],
    hint: (inputs) => witness({ z: inputs.z, r: inputs.r, s: inputs.s, q: { x: inputs.qx, y: inputs.qy } }),
    model: () => ({}),
    emit: (asm, { lowS = true } = {}) => {
      asm.num(N, '_N')

      // 1. the standard ranges. r and s outside [1, n) are not signatures, and
      //    z outside [0, n) is not a reduced message hash.
      for (const v of ['r', 's']) {
        asm.pick(v, '_v1'); asm.num(1, '_one'); asm.geVerify()
        asm.pick(v, '_v2'); asm.pick('_N', '_n1'); asm.ltVerify()
      }
      // LOW-S. ECDSA is malleable by construction: if (r, s) verifies then so
      // does (r, n − s), because R and −R share an x coordinate. Both are
      // genuine signatures, so a verifier that accepts both is not wrong — it is
      // just not canonical, and a covenant gated on it can be spent two ways
      // with two different txids by anyone who sees the transaction in flight.
      // Bitcoin answers this for OP_CHECKSIG with the mandatory LOW_S policy
      // rule; the same rule, for the same reason, belongs here.
      if (lowS) { asm.pick('s', '_sl'); asm.num((N + 1n) / 2n, '_half'); asm.ltVerify() }
      asm.pick('z', '_z1'); asm.num(0, '_zero'); asm.geVerify()
      asm.pick('z', '_z2'); asm.pick('_N', '_n2'); asm.ltVerify()

      // 2. Q is a point on the curve. Without this an attacker supplies a point
      //    on some other curve, where the discrete logarithm may be easy, and
      //    the arithmetic below carries on regardless.
      asm.num(P, '_P')
      asm.pick('qy', '_qy1'); asm.pick('qy', '_qy2')
      apply(asm, int.modmul, { n: '_P' }, ['_qy1', '_qy2'], ['_y2'])
      asm.pick('qx', '_qx1'); asm.pick('qx', '_qx2')
      apply(asm, int.modmul, { n: '_P' }, ['_qx1', '_qx2'], ['_x2'])
      asm.pick('_x2', '_x2c'); asm.pick('qx', '_qx3')
      apply(asm, int.modmul, { n: '_P' }, ['_x2c', '_qx3'], ['_x3'])
      asm.num(7, '_b'); asm.pick('_x3', '_x3c')
      apply(asm, int.modadd, { n: '_P' }, ['_x3c', '_b'], ['_rhs'])
      asm.roll('_y2'); asm.roll('_rhs'); asm.numEqualVerify()
      for (const dead of ['_x2', '_x3', '_P']) asm.discard(dead)

      // 3. s⁻¹, supplied and checked — canonical, so the spend is not malleable
      //    in the witness.
      asm.pick('sinv', '_si1'); asm.num(0, '_zero2'); asm.geVerify()
      asm.pick('sinv', '_si2'); asm.pick('_N', '_n3'); asm.ltVerify()
      asm.pick('s', '_sc'); asm.pick('sinv', '_si3')
      apply(asm, int.modmul, { n: '_N' }, ['_sc', '_si3'], ['_chk'])
      asm.num(1, '_one2'); asm.numEqualVerify()

      // 4. u₁ = z·s⁻¹, u₂ = r·s⁻¹ (mod n)
      asm.pick('z', '_zc'); asm.pick('sinv', '_si4')
      apply(asm, int.modmul, { n: '_N' }, ['_zc', '_si4'], ['u1'])
      asm.pick('r', '_rc'); asm.pick('sinv', '_si5')
      apply(asm, int.modmul, { n: '_N' }, ['_rc', '_si5'], ['u2'])

      // 5. R = u₁·G + u₂·Q, interleaved: one accumulator, one doubling chain.
      //    Two separate multiplications would double the chain and cost 23 KB
      //    more (see docs/optimization.md).
      ec.emitShamir(asm, { prefix: 'sh', bits: 256 }, ['u1', 'u2'], ['qx', 'qy'], ['rx', 'ry'])

      // 6. r ≡ R.x (mod n)
      asm.discard('ry')
      asm.roll('rx'); asm.pick('_N', '_n4'); asm.mod('_rmod')
      asm.pick('r', '_rf'); asm.numEqualVerify()

      for (const dead of ['u1', 'u2', 'sinv', 'z', 'r', 's', 'qx', 'qy', '_N']) asm.discard(dead)
    },
    attacks: (honest, params, name) => {
      if (name === 's') {
        return [
          { label: 's → n − s (the classic ECDSA malleation)', value: N - honest.s },
          { label: 's off by one', value: honest.s + 1n },
          { label: 's = 0', value: 0n }
        ]
      }
      if (name === 'z' || name === 'r') {
        return [
          { label: `${name} off by one`, value: honest[name] + 1n },
          { label: `${name} = 0`, value: 0n },
          { label: `${name} + n`, value: honest[name] + N }
        ]
      }
      if (name === 'qx' || name === 'qy') {
        return [
          { label: `${name} off by one (off the curve)`, value: honest[name] + 1n },
          { label: `${name} = 0`, value: 0n }
        ]
      }
      if (name === 'sinv' || name === 'finv') {
        return [
          { label: `${name} off by one`, value: honest[name] + 1n },
          { label: `${name} = 0`, value: 0n }
        ]
      }
      return ec.ladderAttacks(honest, name, P)
    },
    cases: cases.map((c) => ({ ...c, params: { lowS, ...(c.params || {}) } })),
    notes: [
      'z is an INPUT: bind it to a message you care about (hash it in the script), or this proves only that a signature exists for some z',
      lowS ? 'low-S enforced: (r, n − s) is refused, so the signature is canonical' : 'low-S NOT enforced: (r, n − s) verifies too and the spend is malleable',
      'the public key is checked to be on the curve — an invalid-curve point is refused',
      'about 195 KB: the most expensive module here, and the one to justify before using'
    ]
  })
}

/** A real signature from the library's own ECDSA, over an arbitrary message. */
function signCase (secretHex, message) {
  const priv = bsv.PrivateKey.fromBuffer(Buffer.from(secretHex, 'hex'))
  const hash = bsv.crypto.Hash.sha256(Buffer.from(message))
  const sig = bsv.crypto.ECDSA.sign(hash, priv)
  const q = ecJs.fromBsv(priv.publicKey.point)
  let sv = BigInt('0x' + sig.s.toString(16))
  if (sv > N / 2n) sv = N - sv           // the low-S representative, as any modern signer emits
  return {
    name: `“${message}” signed by the library’s own ECDSA`,
    inputs: {
      z: BigInt('0x' + hash.toString('hex')) % N,
      r: BigInt('0x' + sig.r.toString(16)),
      s: sv,
      qx: q.x,
      qy: q.y
    }
  }
}

module.exports = { verifier, witness, signCase, N, P }
