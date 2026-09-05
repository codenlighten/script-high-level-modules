'use strict'

const { defineModule, apply } = require('../module')
const int = require('./int')
const ecJs = require('../ec')

// ELLIPTIC-CURVE POINT ARITHMETIC over a prime field, in affine coordinates.
//
// The reason affine coordinates are affordable at all is `int.modinv`: the
// division in the slope is the expensive operation in Script and the cheap one
// to CHECK, so the spender supplies the inverse and the module verifies it with
// one multiplication and two comparisons. Every point operation here therefore
// takes a witness, and every witness carries the same two obligations —
// soundness and canonicity — that the test kit attacks.
//
// The modulus is pushed once per operation and picked thereafter. A 256-bit
// prime is a 33-byte push and a point addition needs it ten times; the
// difference between pushing and picking is about 300 bytes per operation.
//
// PRECONDITIONS, ENFORCED RATHER THAN DOCUMENTED. `add` covers two points with
// DIFFERENT x. Feed it two points with the same x and dx is zero, no inverse of
// zero exists, and the module refuses the spend — it cannot silently return the
// wrong point. `double` covers a point with y ≠ 0 for the same reason. The
// point at infinity has no affine coordinates and is not representable here;
// a caller that needs it must branch around it.

const P = ecJs.P

/** The field operations, as calls into the int modules, over a modulus already
 *  on the stack under `pName`. Each takes copies and names its result. */
function field (asm, pName) {
  const bin = (m) => (a, b, out) => { asm.pick(a, '_fa'); asm.pick(b, '_fb'); apply(asm, m, { n: pName }, ['_fa', '_fb'], [out]) }
  return { sub: bin(int.modsub), mul: bin(int.modmul), add: bin(int.modadd) }
}

/** Assert `invName` is the inverse of `ofName` mod p — the shape every witnessed
 *  division in this file uses. Canonical: 0 ≤ inv < p, so exactly one passes. */
function checkInverse (asm, f, pName, ofName, invName) {
  asm.pick(invName, '_i0'); asm.num(0, '_zero'); asm.geVerify()
  asm.pick(invName, '_i1'); asm.pick(pName, '_pl'); asm.ltVerify()
  f.mul(ofName, invName, '_chk')
  asm.num(1, '_one'); asm.numEqualVerify()
}

const add = defineModule({
  name: 'ec.add',
  doc: 'P₁ + P₂ on a short Weierstrass curve, for points with distinct x',
  inputs: ['x1', 'y1', 'x2', 'y2', { name: 'invdx', witness: true }],
  outputs: ['x3', 'y3'],
  hint: ({ x1, x2 }, { p = P }) => ({ invdx: ecJs.inv(ecJs.mod(x2 - x1, p), p) }),
  model: ({ x1, y1, x2, y2 }) => {
    const r = ecJs.add({ x: x1, y: y1 }, { x: x2, y: y2 })
    return { x3: r.x, y3: r.y }
  },
  emit: (asm, { p = P }) => {
    asm.num(p, '_p')
    const f = field(asm, '_p')

    f.sub('x2', 'x1', '_dx')                     // dx = x₂ − x₁
    checkInverse(asm, f, '_p', '_dx', 'invdx')
    f.sub('y2', 'y1', '_dy')                     // dy = y₂ − y₁
    f.mul('_dy', 'invdx', '_lam')                // λ  = dy / dx
    f.mul('_lam', '_lam', '_lam2')
    f.sub('_lam2', 'x1', '_t')
    f.sub('_t', 'x2', 'x3')                      // x₃ = λ² − x₁ − x₂
    f.sub('x1', 'x3', '_d')
    f.mul('_lam', '_d', '_m')
    f.sub('_m', 'y1', 'y3')                      // y₃ = λ(x₁ − x₃) − y₁

    for (const dead of ['_dx', '_dy', '_lam', '_lam2', '_t', '_d', '_m', '_p', 'x1', 'y1', 'x2', 'y2', 'invdx']) asm.discard(dead)
    asm.roll('x3'); asm.roll('y3')
  },
  attacks: (honest, params) => {
    const p = params.p || P
    const inv = honest.invdx
    return [
      { label: 'off by one', value: inv + 1n },
      { label: 'the same residue (+p)', value: inv + p },
      { label: 'negated', value: p - inv },
      { label: 'zero', value: 0n },
      { label: 'one', value: 1n }
    ]
  },
  cases: (() => {
    const pts = [1n, 2n, 3n, 7n, 11n, 12345n].map((k) => ecJs.mul(k))
    return [
      { name: 'G + 2G', inputs: { x1: pts[0].x, y1: pts[0].y, x2: pts[1].x, y2: pts[1].y } },
      { name: '3G + 7G', inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[3].x, y2: pts[3].y } },
      { name: '11G + 12345G', inputs: { x1: pts[4].x, y1: pts[4].y, x2: pts[5].x, y2: pts[5].y } },
      // The precondition, enforced rather than documented. dx = 0 has no
      // inverse, so no witness makes these pass — the module cannot be tricked
      // into returning the wrong point for a doubling or for P + (−P).
      { name: 'P + P (same point)', refuse: 'dx = 0 has no inverse',
        inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[2].x, y2: pts[2].y, invdx: 1n } },
      { name: 'P + (−P)', refuse: 'dx = 0 has no inverse',
        inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[2].x, y2: ecJs.mod(-pts[2].y), invdx: 0n } },
      { name: 'P + P, witness = p−1', refuse: 'no witness inverts zero',
        inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[2].x, y2: pts[2].y, invdx: P - 1n } }
    ]
  })(),
  notes: ['refuses two points with the same x — dx is zero and has no inverse']
})

const double = defineModule({
  name: 'ec.double',
  doc: '2P on a short Weierstrass curve with a = 0 (secp256k1), for y ≠ 0',
  inputs: ['x1', 'y1', { name: 'inv2y', witness: true }],
  outputs: ['x3', 'y3'],
  hint: ({ y1 }, { p = P }) => ({ inv2y: ecJs.inv(ecJs.mod(2n * y1, p), p) }),
  model: ({ x1, y1 }) => {
    const r = ecJs.double({ x: x1, y: y1 })
    return { x3: r.x, y3: r.y }
  },
  emit: (asm, { p = P }) => {
    asm.num(p, '_p')
    const f = field(asm, '_p')

    f.add('y1', 'y1', '_2y')                     // 2y
    checkInverse(asm, f, '_p', '_2y', 'inv2y')
    f.mul('x1', 'x1', '_x2')                     // 3x²
    asm.num(3, '_three'); asm.rename('_three')
    asm.pick('_x2', '_x2c'); apply(asm, int.modmul, { n: '_p' }, ['_three', '_x2c'], ['_3x2'])
    f.mul('_3x2', 'inv2y', '_lam')               // λ = 3x² / 2y
    f.mul('_lam', '_lam', '_lam2')
    f.sub('_lam2', 'x1', '_t')
    f.sub('_t', 'x1', 'x3')                      // x₃ = λ² − 2x₁
    f.sub('x1', 'x3', '_d')
    f.mul('_lam', '_d', '_m')
    f.sub('_m', 'y1', 'y3')                      // y₃ = λ(x₁ − x₃) − y₁

    for (const dead of ['_2y', '_x2', '_3x2', '_lam', '_lam2', '_t', '_d', '_m', '_p', 'x1', 'y1', 'inv2y']) asm.discard(dead)
    asm.roll('x3'); asm.roll('y3')
  },
  attacks: (honest, params) => {
    const p = params.p || P
    const inv = honest.inv2y
    return [
      { label: 'off by one', value: inv + 1n },
      { label: 'the same residue (+p)', value: inv + p },
      { label: 'zero', value: 0n }
    ]
  },
  cases: [
    ...[1n, 3n, 12345n].map((k) => {
      const pt = ecJs.mul(k)
      return { name: `2·(${k}G)`, inputs: { x1: pt.x, y1: pt.y } }
    }),
    { name: 'y = 0 (not a point on secp256k1)', refuse: '2y = 0 has no inverse',
      inputs: { x1: ecJs.G.x, y1: 0n, inv2y: 1n } }
  ],
  notes: ['a = 0 is baked in: this is secp256k1’s doubling, not the general one']
})

module.exports = { add, double, field, checkInverse, P }
