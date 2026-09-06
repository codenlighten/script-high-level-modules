'use strict'

const { defineModule } = require('../module')
const fp2 = require('./fp2')
const fp6 = require('./fp6')
const bls = require('../bls12381')

// ARE THESE POINTS WHAT THEY CLAIM TO BE?
//
// A verifier that reads a proof out of an unlocking script is reading numbers a
// spender chose. Bounding them into [0, p) makes each of them ONE field element
// rather than a congruence class, which is necessary and is not sufficient: a
// pair of field elements is not a curve point, and a curve point is not
// necessarily an element of the prime-order subgroup a pairing is defined on.
//
// Groth16 requires both. This file supplies the first — the curve equation —
// and states plainly what it does not supply.
//
//     y² = x³ + 4            on G1, over Fp
//     y² = x³ + 4(u + 1)     on G2, over Fp2, the D-type twist
//
// WHAT IS STILL MISSING is subgroup membership. E(Fp) has order h₁·r and the
// twist has order h₂·r, so a point can satisfy the curve equation and lie
// outside the r-order subgroup, and pairings of such points are not the bilinear
// map the security argument is about. The standard checks are [r]P = O, or the
// cheaper endomorphism forms; §"what this does not check" in the audit prices
// them. Until they are here, this verifier's soundness rests on the curve
// equation and the equation alone, which is LESS than Groth16 asks for and is
// said so rather than hoped over.

const P381 = bls.P
const { two, op, dup, numericModulus, residues, pushModulus, modulusName, dropModulus, inner } = fp6

const inField = (who, ...names) => (params) => {
  const r = residues(params, who)
  const out = {}
  for (const k of names) out[k] = r
  return out
}

/**
 * y² = x³ + b over Fp — the G1 curve equation, as a predicate.
 *
 * Three multiplications and two reductions. On a 1.24 MB verifier this is not a
 * cost, it is a rounding error, and its absence was a soundness gap.
 */
const onCurveG1 = defineModule({
  name: 'g1.onCurve',
  doc: 'y² = x³ + b over Fp — refuses a pair of field elements that is not a point',
  inputs: ['x', 'y'],
  outputs: [],
  requires: inField('g1.onCurve', 'x', 'y'),
  model: () => ({}),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n, b = 4n } = params
    const N = modulusName(n)
    asm.pick('y', '_y1'); asm.roll('y'); asm.mul('_yy')
    asm.pick(N, '_n'); asm.mod('_y2')
    asm.pick('x', '_x1'); asm.pick('x', '_x2'); asm.mul('_xx')
    asm.pick(N, '_n'); asm.mod('_x2r')
    asm.roll('x'); asm.mul('_xxx')
    asm.num(b, '_b'); asm.add('_rhs')
    asm.pick(N, '_n'); asm.mod('_rhsr')
    asm.numEqualVerify()
    dropModulus(asm, n)
  },
  cases: (() => {
    const G1 = bls.G1
    const two = bls.g1mul(2n)
    return [
      { name: 'the generator', inputs: { x: G1.x, y: G1.y }, params: { n: P381 } },
      { name: '2G1', inputs: { x: two.x, y: two.y }, params: { n: P381 } },
      { name: 'y negated is still on it', inputs: { x: G1.x, y: P381 - G1.y }, params: { n: P381 } },
      { name: 'x off by one', refuse: 'not a point on the curve', inputs: { x: G1.x + 1n, y: G1.y }, params: { n: P381 } },
      { name: 'y off by one', refuse: 'not a point on the curve', inputs: { x: G1.x, y: G1.y + 1n }, params: { n: P381 } },
      { name: 'both zero', refuse: 'the point at infinity has no affine coordinates', inputs: { x: 0n, y: 0n }, params: { n: P381 } }
    ]
  })(),
  notes: ['necessary and not sufficient: says nothing about the prime-order subgroup']
})

/**
 * y² = x³ + 4(u + 1) over Fp2 — the twist's curve equation, as a predicate.
 *
 * The constant is derived, not written: B2 = ξ·4 with ξ = u + 1, computed by
 * bls12381.js with the same Fp2 arithmetic everything else uses.
 */
const onCurveG2 = defineModule({
  name: 'g2.onCurve',
  doc: 'y² = x³ + 4(u + 1) over Fp2 — refuses coordinates that are not a twist point',
  inputs: ['x0', 'x1', 'y0', 'y1'],
  outputs: [],
  requires: inField('g2.onCurve', 'x0', 'x1', 'y0', 'y1'),
  model: () => ({}),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'g2.onCurve')
    const lhs = op(asm, fp2.sqr, p, ['y'])
    const x3 = op(asm, fp2.mul, p, [op(asm, fp2.sqr, p, [dup(asm, 'x')]), 'x'])
    asm.num(bls.B2[0], '_b0'); asm.num(bls.B2[1], '_b1')
    const rhs = op(asm, fp2.add, p, [x3, '_b'])
    asm.roll(rhs + '0'); asm.roll(lhs + '0'); asm.numEqualVerify()
    asm.roll(rhs + '1'); asm.roll(lhs + '1'); asm.numEqualVerify()
    dropModulus(asm, n)
  },
  cases: (() => {
    const Q = bls.G2
    const two = bls.g2mul(2n)
    return [
      { name: 'the generator', inputs: { x0: Q.x[0], x1: Q.x[1], y0: Q.y[0], y1: Q.y[1] }, params: { n: P381 } },
      { name: '2G2', inputs: { x0: two.x[0], x1: two.x[1], y0: two.y[0], y1: two.y[1] }, params: { n: P381 } },
      { name: 'x0 off by one', refuse: 'not a point on the twist', inputs: { x0: Q.x[0] + 1n, x1: Q.x[1], y0: Q.y[0], y1: Q.y[1] }, params: { n: P381 } },
      { name: 'y1 off by one', refuse: 'not a point on the twist', inputs: { x0: Q.x[0], x1: Q.x[1], y0: Q.y[0], y1: Q.y[1] + 1n }, params: { n: P381 } },
      { name: 'the untwisted G1 coordinates', refuse: 'a G1 point is not a twist point', inputs: { x0: bls.G1.x, x1: 0n, y0: bls.G1.y, y1: 0n }, params: { n: P381 } }
    ]
  })(),
  notes: ['necessary and not sufficient: says nothing about the prime-order subgroup']
})

module.exports = { onCurveG1, onCurveG2 }
