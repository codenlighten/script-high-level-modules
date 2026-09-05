'use strict'

// src/bls12381.js against @noble/curves.
//
// The pairing in this repository exists to be COUNTED, not to be fast — every
// field operation goes through an instrumented multiply so that the Script cost
// of a pairing can be computed rather than asserted. A counter is only worth
// having if the thing it counts is right, so this file checks the whole tower
// against an independent implementation: not just "is it bilinear" (a wrong
// pairing can be bilinear) but byte-for-byte equality of the Fp12 output.
//
// @noble/curves is ESM and this repository is CommonJS, hence the dynamic
// import. It is a devDependency: nothing shipped depends on it.

const assert = require('assert')
const b = require('../src/bls12381')

const flat = (f) => [
  f[0][0][0], f[0][0][1], f[0][1][0], f[0][1][1], f[0][2][0], f[0][2][1],
  f[1][0][0], f[1][0][1], f[1][1][0], f[1][1][1], f[1][2][0], f[1][2][1]
]
const nobleFlat = (t) => [
  t.c0.c0.c0, t.c0.c0.c1, t.c0.c1.c0, t.c0.c1.c1, t.c0.c2.c0, t.c0.c2.c1,
  t.c1.c0.c0, t.c1.c0.c1, t.c1.c1.c0, t.c1.c1.c1, t.c1.c2.c0, t.c1.c2.c1
]

// Scalars: the degenerate ones, small ones, and ones with no structure at all.
const PAIRS = [
  [1n, 1n],
  [2n, 3n],
  [7n, 11n],
  [12345n, 6789n],
  [0xdeadbeefn, 0xcafen],
  [b.R - 1n, 2n],
  [99999999999n, 31337n],
  [0x2ecdba1cd7a0f9d2e0e1f5b8a4c6739fn, 0x51a8f0c3d9b26e74a1f0538cd2b9e647n]
]

async function main () {
  const { bls12_381: noble } = await import('@noble/curves/bls12-381.js')
  const G1n = noble.G1.Point.BASE
  const G2n = noble.G2.Point.BASE
  let checks = 0

  // 1. the generators agree — if these differ nothing below means anything
  {
    const g1 = G1n.toAffine()
    assert.strictEqual(b.G1.x, g1.x, 'G1.x')
    assert.strictEqual(b.G1.y, g1.y, 'G1.y')
    const g2 = G2n.toAffine()
    assert.strictEqual(b.G2.x[0], g2.x.c0, 'G2.x.c0')
    assert.strictEqual(b.G2.x[1], g2.x.c1, 'G2.x.c1')
    assert.strictEqual(b.G2.y[0], g2.y.c0, 'G2.y.c0')
    assert.strictEqual(b.G2.y[1], g2.y.c1, 'G2.y.c1')
    checks += 6
    console.log('  generators                       ok')
  }

  // 2. group arithmetic — the pairing is only as right as the points it eats
  for (const k of [2n, 3n, 17n, 0xdeadbeefn, b.R - 1n]) {
    const mine1 = b.g1mul(k)
    const th1 = G1n.multiply(k).toAffine()
    assert.strictEqual(mine1.x, th1.x, `g1mul(${k}).x`)
    assert.strictEqual(mine1.y, th1.y, `g1mul(${k}).y`)
    const mine2 = b.g2mul(k)
    const th2 = G2n.multiply(k).toAffine()
    assert.strictEqual(mine2.x[0], th2.x.c0, `g2mul(${k}).x.c0`)
    assert.strictEqual(mine2.x[1], th2.x.c1, `g2mul(${k}).x.c1`)
    assert.strictEqual(mine2.y[0], th2.y.c0, `g2mul(${k}).y.c0`)
    assert.strictEqual(mine2.y[1], th2.y.c1, `g2mul(${k}).y.c1`)
    checks += 6
  }
  console.log('  G1 and G2 scalar multiplication  ok')

  // 3. the pairing itself, exactly — all twelve Fp coefficients
  for (const [a, c] of PAIRS) {
    const mine = flat(b.pairing(b.g1mul(a), b.g2mul(c)))
    const theirs = nobleFlat(noble.pairing(G1n.multiply(a), G2n.multiply(c)))
    for (let i = 0; i < 12; i++) {
      assert.strictEqual(mine[i], theirs[i], `e(${a}G1, ${c}G2) coefficient ${i}`)
    }
    checks += 12
  }
  console.log(`  the pairing, all 12 coefficients ok  (${PAIRS.length} pairs)`)

  // 4. properties an independent implementation cannot vouch for by agreeing:
  //    that the result is in the order-r subgroup and that the map is bilinear.
  {
    const e = b.pairing(b.G1, b.G2)
    assert.ok(b.f12eq(b.f12pow(e, b.R), b.F12_ONE), 'e(G1,G2)^r != 1')
    assert.ok(!b.f12eq(e, b.F12_ONE), 'pairing is degenerate')
    const e23 = b.pairing(b.g1mul(2n), b.g2mul(3n))
    assert.ok(b.f12eq(e23, b.f12pow(e, 6n)), 'e(2P,3Q) != e(P,Q)^6')
    checks += 3
    console.log('  order-r, non-degenerate, bilinear ok')
  }

  // 5. the two optimisations that have no counterpart in the reference, checked
  //    against the general routines they replace. Both are places where an
  //    earlier version of this file was wrong in a way bilinearity did not catch.
  {
    // cyclotomic squaring, on an element known to be in the subgroup
    const ml = b.millerLoop(b.G1, b.G2)
    let e = b.f12mulRaw(b.f12conj(ml), b.f12inv(ml))
    e = b.f12mulRaw(b.f12frobN(e, 2), e)
    assert.ok(b.f12eq(b.f12mulRaw(e, b.f12conj(e)), b.F12_ONE), 'easy part is not cyclotomic')
    assert.ok(b.f12eq(b.cyclotomicSqr(e), b.f12sqr(e)), 'cyclotomicSqr != f12sqr')
    assert.ok(b.f12eq(b.cyclotomicSqr(b.cyclotomicSqr(e)), b.f12sqr(b.f12sqr(e))), 'cyclotomicSqr twice')
    checks += 3

    // sparse line multiplication, against the dense product it stands for
    const l = b.lineDouble(b.G2, b.G1)
    assert.ok(b.f12eq(b.f12mulLine(ml, l), b.f12mulRaw(ml, b.lineDense(l))), 'f12mulLine != f12mulRaw (double)')
    const l2 = b.lineAdd(b.g2mul(3n), b.G2, b.G1)
    assert.ok(b.f12eq(b.f12mulLine(ml, l2), b.f12mulRaw(ml, b.lineDense(l2))), 'f12mulLine != f12mulRaw (add)')
    checks += 2
    console.log('  cyclotomic squaring, sparse line ok')
  }

  console.log(`\n${checks} assertions — src/bls12381.js agrees with @noble/curves.`)
}

main().catch((e) => { console.error(e.message || e); process.exit(1) })
