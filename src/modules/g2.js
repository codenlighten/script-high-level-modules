'use strict'

const { defineModule } = require('../module')
const fp2 = require('./fp2')
const fp6 = require('./fp6')
const { mod, invmod } = require('../bigint')

// THE MILLER LOOP'S STEP FUNCTION, on the twist E'(Fp2): y² = x³ + 4(u + 1).
//
// This is the part of a pairing that is not extension-field arithmetic. Each
// iteration takes a slope through two points of G2, uses it twice — once to
// move the accumulator point, once to build the line evaluated at the G1 point
// — and hands three Fp2 coefficients to fp12.mulLine.
//
// Both modules here compute λ ONCE. The obvious factoring computes the line
// from λ and then asks a general point-addition routine for the next point,
// and that routine finds λ again: a second modular inversion for a number the
// caller is already holding. Over a whole loop that is 68 inversions against
// 136, and in Script an inversion is a witness the spender supplies and the
// script bounds and checks — so halving them halves that.
//
// The G1 point is not an input to the line's w⁰ coefficient at all. ξ·y_P is
// the same value on every one of the 68 iterations, so it is hoisted out of
// the loop entirely and only x_P appears here.

const P381 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn

const { two, op, dup, park, unpark, numericModulus, residues,
  pushModulus, modulusName, dropModulus, inner, f2m, f2a, f2s } = fp6

const inField = (who, ...names) => (params) => {
  const r = residues(params, who)
  const out = {}
  for (const k of names) out[k] = r
  return out
}
const OUTS = ['x30', 'x31', 'y30', 'y31', 'l10', 'l11', 'l20', 'l21']
const ensuresStep = (who) => (p) => {
  const r = residues(p, who)
  const out = {}
  for (const k of OUTS) out[k] = r
  return out
}
/** a⁻¹ in Fp2, for the hint that supplies the witness. */
const f2inv = (a, n) => {
  const d = invmod(mod(a[0] * a[0] + a[1] * a[1], n), n)
  return [mod(a[0] * d, n), mod(-a[1] * d, n)]
}
const f2neg = (a, n) => [mod(-a[0], n), mod(-a[1], n)]
const f2mulFp = (a, k, n) => [mod(a[0] * k, n), mod(a[1] * k, n)]
const pack = (x3, y3, l1, l2) => ({
  x30: x3[0], x31: x3[1], y30: y3[0], y31: y3[1],
  l10: l1[0], l11: l1[1], l20: l2[0], l21: l2[1]
})

/**
 * Everything downstream of λ, which is identical for a tangent and a chord.
 *
 *     l1 = λ·Tx − Ty        the w³ coefficient
 *     l2 = −λ·Px            the w⁵ coefficient, Px in the base field
 *     x3 = λ² − Tx − bx     bx is Tx when doubling, Qx when adding
 *     y3 = λ(Tx − x3) − Ty
 *
 * The four results are built in the reverse of their declared order and parked
 * on the altstack, which hands them back the right way round without a closing
 * OP_ROLL — except x3, which y3 needs and which therefore stays live.
 */
function afterLambda (asm, p, lam, bx) {
  op(asm, fp2.neg, p, [op(asm, fp2.mulFp, p, [dup(asm, lam)], undefined, ['Px'])], 'l2')
  park(asm)
  op(asm, fp2.sub, p, [op(asm, fp2.mul, p, [dup(asm, lam), dup(asm, 'Tx')]), dup(asm, 'Ty')], 'l1')
  park(asm)
  op(asm, fp2.sub, p, [
    op(asm, fp2.sub, p, [op(asm, fp2.sqr, p, [dup(asm, lam)]), dup(asm, 'Tx')]),
    bx
  ], 'x3')
  op(asm, fp2.sub, p, [
    op(asm, fp2.mul, p, [lam, op(asm, fp2.sub, p, ['Tx', dup(asm, 'x3')])]),
    'Ty'
  ], 'y3')
  unpark(asm)
  unpark(asm)
}

/** fp2.mulFp wants its scalar as a stack value; three is one byte. */
function timesThree (asm, p, v) {
  asm.num(3n, '_three')
  return op(asm, fp2.mulFp, p, [v], undefined, ['_three'])
}

/**
 * T → 2T, with the tangent at T.
 *
 *     λ = 3Tx² / 2Ty
 *
 * The division is the witness: the spender supplies (2Ty)⁻¹ and fp2.inv checks
 * it, which is one Fp2 multiplication and two OP_WITHINs. On a CPU that
 * inversion would be hundreds of multiplications and the whole loop would be
 * written in projective coordinates to dodge it; here it is cheaper than the
 * three extra multiplications per step projective would cost, so the loop stays
 * affine. That inversion of the usual trade is the single biggest reason a
 * pairing fits in a megabyte rather than several.
 */
const stepDouble = defineModule({
  name: 'g2.stepDouble',
  doc: 'T → 2T on E′(Fp2), with the tangent line at T evaluated at x_P',
  inputs: ['Tx0', 'Tx1', 'Ty0', 'Ty1', 'Px',
    { name: 'inv0', witness: true }, { name: 'inv1', witness: true }],
  outputs: OUTS,
  requires: inField('g2.stepDouble', 'Tx0', 'Tx1', 'Ty0', 'Ty1', 'Px'),
  ensures: ensuresStep('g2.stepDouble'),
  hint: ({ Ty0, Ty1 }, { n }) => {
    const [i0, i1] = f2inv([mod(Ty0 + Ty0, n), mod(Ty1 + Ty1, n)], n)
    return { inv0: i0, inv1: i1 }
  },
  model: ({ Tx0, Tx1, Ty0, Ty1, Px }, { n }) => {
    const Tx = [Tx0, Tx1]; const Ty = [Ty0, Ty1]
    const lam = f2m(f2mulFp(f2m(Tx, Tx, n), 3n, n), f2inv(f2a(Ty, Ty, n), n), n)
    const x3 = f2s(f2s(f2m(lam, lam, n), Tx, n), Tx, n)
    const y3 = f2s(f2m(lam, f2s(Tx, x3, n), n), Ty, n)
    return pack(x3, y3, f2s(f2m(lam, Tx, n), Ty, n), f2neg(f2mulFp(lam, Px, n), n))
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'g2.stepDouble')
    const ai = op(asm, fp2.inv, p, [op(asm, fp2.add, p, [dup(asm, 'Ty'), dup(asm, 'Ty')])],
      undefined, ['inv0', 'inv1'])
    const lam = op(asm, fp2.mul, p, [timesThree(asm, p, op(asm, fp2.sqr, p, [dup(asm, 'Tx')])), ai])
    afterLambda(asm, p, lam, dup(asm, 'Tx'))
    dropModulus(asm, n)
  },
  cases: (() => {
    const bls = require('../bls12381')
    const at = (k, name) => {
      const T = bls.g2mul(k)
      return { name, inputs: { Tx0: T.x[0], Tx1: T.x[1], Ty0: T.y[0], Ty1: T.y[1], Px: bls.G1.x }, params: { n: P381 } }
    }
    return [at(1n, 'the generator'), at(2n, '2G2'), at(7n, '7G2'), at(123456789n, 'a random point')]
  })()
})

/**
 * T → T + Q, with the chord through them.
 *
 *     λ = (Qy − Ty) / (Qx − Tx)
 *
 * Q is the loop's fixed G2 input, so its coordinates are picked rather than
 * consumed by the caller. The witness is (Qx − Tx)⁻¹, and fp2.inv refusing a
 * zero is exactly the case that matters: T = ±Q has no chord, and no witness
 * makes one appear.
 */
const stepAdd = defineModule({
  name: 'g2.stepAdd',
  doc: 'T → T + Q on E′(Fp2), with the line through them evaluated at x_P',
  inputs: ['Tx0', 'Tx1', 'Ty0', 'Ty1', 'Qx0', 'Qx1', 'Qy0', 'Qy1', 'Px',
    { name: 'inv0', witness: true }, { name: 'inv1', witness: true }],
  outputs: OUTS,
  requires: inField('g2.stepAdd', 'Tx0', 'Tx1', 'Ty0', 'Ty1', 'Qx0', 'Qx1', 'Qy0', 'Qy1', 'Px'),
  ensures: ensuresStep('g2.stepAdd'),
  hint: ({ Tx0, Tx1, Qx0, Qx1 }, { n }) => {
    const [i0, i1] = f2inv(f2s([Qx0, Qx1], [Tx0, Tx1], n), n)
    return { inv0: i0, inv1: i1 }
  },
  model: ({ Tx0, Tx1, Ty0, Ty1, Qx0, Qx1, Qy0, Qy1, Px }, { n }) => {
    const Tx = [Tx0, Tx1]; const Ty = [Ty0, Ty1]
    const Qx = [Qx0, Qx1]; const Qy = [Qy0, Qy1]
    const lam = f2m(f2s(Qy, Ty, n), f2inv(f2s(Qx, Tx, n), n), n)
    const x3 = f2s(f2s(f2m(lam, lam, n), Tx, n), Qx, n)
    const y3 = f2s(f2m(lam, f2s(Tx, x3, n), n), Ty, n)
    return pack(x3, y3, f2s(f2m(lam, Tx, n), Ty, n), f2neg(f2mulFp(lam, Px, n), n))
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'g2.stepAdd')
    const ai = op(asm, fp2.inv, p, [op(asm, fp2.sub, p, [dup(asm, 'Qx'), dup(asm, 'Tx')])],
      undefined, ['inv0', 'inv1'])
    const lam = op(asm, fp2.mul, p, [op(asm, fp2.sub, p, ['Qy', dup(asm, 'Ty')]), ai])
    afterLambda(asm, p, lam, 'Qx')
    dropModulus(asm, n)
  },
  cases: (() => {
    const bls = require('../bls12381')
    const at = (k, j, name) => {
      const T = bls.g2mul(k); const Q = bls.g2mul(j)
      return {
        name,
        inputs: {
          Tx0: T.x[0], Tx1: T.x[1], Ty0: T.y[0], Ty1: T.y[1],
          Qx0: Q.x[0], Qx1: Q.x[1], Qy0: Q.y[0], Qy1: Q.y[1], Px: bls.G1.x
        },
        params: { n: P381 }
      }
    }
    const same = at(3n, 3n, 'T = Q, which has no chord')
    same.refuse = 'T = Q: the difference is zero and has no inverse'
    same.inputs.inv0 = 1n; same.inputs.inv1 = 0n
    return [at(2n, 1n, '2G2 + G2'), at(5n, 3n, '5G2 + 3G2'), at(123456789n, 1n, 'a random point + G2'), same]
  })()
})

module.exports = { stepDouble, stepAdd, OUTS }
