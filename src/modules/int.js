'use strict'

const { defineModule } = require('../module')
const { mod, powmod, invmod, bitsOf } = require('../bigint')

// MODULAR ARITHMETIC — the floor everything else stands on.
//
// Script's OP_MOD is TRUNCATED, not Euclidean: (−3) MOD 5 is −3, measured, not
// assumed (tools/probe-limits.js). So "reduce mod n" is only correct here when
// the value entering OP_MOD is known non-negative, and every module below either
// establishes that or adds n first. This is the whole reason modsub exists as a
// module rather than as three opcodes someone writes inline.
//
// The modulus is a compile-time parameter, pushed ONCE and copied with OP_PICK
// for each reduction. For RSA-sized work that one decision is the difference
// between a 400-byte script and a 4,000-byte one.

/** Push the modulus as a local and return the name it lives under. */
function withModulus (asm, n, name = '_n') {
  asm.num(n, name)
  return name
}

const modadd = defineModule({
  name: 'int.modadd',
  doc: 'r = (a + b) mod n, for a, b already in [0, n)',
  inputs: ['a', 'b'],
  outputs: ['r'],
  model: ({ a, b }, { n }) => ({ r: mod(a + b, n) }),
  emit: (asm, { n }) => {
    asm.add('sum')                       // a + b ≥ 0 given the precondition
    asm.num(n, '_n')
    asm.mod('r')
  },
  notes: ['sound only for inputs already reduced into [0, n) — the caller owes that'],
  cases: [
    { name: 'small', inputs: { a: 7n, b: 9n }, params: { n: 11n } },
    { name: 'wraps', inputs: { a: 10n, b: 10n }, params: { n: 11n } },
    { name: 'zero', inputs: { a: 0n, b: 0n }, params: { n: 11n } },
    { name: '2048-bit', inputs: { a: (1n << 2000n) + 3n, b: (1n << 2040n) + 5n }, params: { n: (1n << 2048n) - 1557n } }
  ]
})

const modsub = defineModule({
  name: 'int.modsub',
  doc: 'r = (a − b) mod n, non-negative — the module that exists because OP_MOD is truncated',
  inputs: ['a', 'b'],
  outputs: ['r'],
  model: ({ a, b }, { n }) => ({ r: mod(a - b, n) }),
  emit: (asm, { n }) => {
    asm.sub('diff')                      // may be negative: OP_MOD would keep the sign
    asm.num(n, '_n')
    asm.add('shifted')                   // + n lands it in (0, 2n)
    asm.num(n, '_n2')
    asm.mod('r')
  },
  cases: [
    { name: 'positive', inputs: { a: 9n, b: 7n }, params: { n: 11n } },
    { name: 'borrows', inputs: { a: 3n, b: 8n }, params: { n: 11n } },
    { name: 'to zero', inputs: { a: 5n, b: 5n }, params: { n: 11n } },
    { name: '2048-bit borrow', inputs: { a: 1n, b: (1n << 2040n) + 5n }, params: { n: (1n << 2048n) - 1557n } }
  ]
})

const modmul = defineModule({
  name: 'int.modmul',
  doc: 'r = (a · b) mod n',
  inputs: ['a', 'b'],
  outputs: ['r'],
  model: ({ a, b }, { n }) => ({ r: mod(a * b, n) }),
  emit: (asm, { n }) => {
    asm.mul('prod')
    asm.num(n, '_n')
    asm.mod('r')
  },
  cases: [
    { name: 'small', inputs: { a: 7n, b: 9n }, params: { n: 11n } },
    { name: 'by zero', inputs: { a: 0n, b: 9n }, params: { n: 11n } },
    { name: '256-bit', inputs: { a: (1n << 250n) + 7n, b: (1n << 248n) + 11n }, params: { n: (1n << 256n) - 189n } },
    { name: '2048-bit', inputs: { a: (1n << 2040n) + 7n, b: (1n << 2039n) + 11n }, params: { n: (1n << 2048n) - 1557n } }
  ]
})

/**
 * r = x^e mod n, with a PUBLIC compile-time exponent, unrolled square-and-multiply.
 *
 * Cost is linear in the bit length of e — which is why RSA verification is cheap
 * (e = 65537 is 17 bits) and RSA signing is not (d is as wide as n, and secret
 * besides). An exponent that must stay secret cannot be unrolled this way at all;
 * it would have to be witnessed bit by bit, and each bit constrained.
 */
const modexp = defineModule({
  name: 'int.modexp',
  doc: 'r = x^e mod n, e a public compile-time exponent',
  inputs: ['x'],
  outputs: ['r'],
  model: ({ x }, { n, e }) => ({ r: powmod(x, e, n) }),
  emit: (asm, { n, e }) => {
    const bits = bitsOf(e)                        // MSB first; bits[0] is always 1
    const N = withModulus(asm, n)                 // pushed once, picked thereafter
    asm.pick('x', 'r')                            // r = x, consuming the leading 1 bit
    for (let i = 1; i < bits.length; i++) {
      asm.pick('r', '_r2'); asm.mul('_sq')        // r²
      asm.pick(N, '_n'); asm.mod('r')
      if (bits[i]) {
        asm.pick('x', '_x'); asm.mul('_xr')       // · x
        asm.pick(N, '_n'); asm.mod('r')
      }
    }
    asm.roll('r')                                 // [.., x, n, r]
    asm.nip()                                     // drop the modulus
    asm.nip()                                     // drop x
  },
  cases: [
    { name: '3^7 mod 11', inputs: { x: 3n }, params: { n: 11n, e: 7n } },
    { name: 'x^65537 mod 257-bit', inputs: { x: (1n << 200n) + 12345n }, params: { n: (1n << 256n) - 189n, e: 65537n } },
    { name: 'x^65537 mod 2048-bit (RSA-sized)', inputs: { x: (1n << 2000n) + 7n }, params: { n: (1n << 2048n) - 1557n, e: 65537n } },
    { name: 'x^3 mod 2048-bit (the small-exponent case)', inputs: { x: (1n << 1024n) + 9n }, params: { n: (1n << 2048n) - 1557n, e: 3n } }
  ]
})

/**
 * The modular inverse, WITNESSED rather than computed.
 *
 * Computing it means the extended Euclidean algorithm — a data-dependent loop,
 * which an unrolled Script cannot express at all without bounding it by the
 * modulus size. Checking it is one multiplication. So the spender supplies it.
 *
 * The two range checks are not decoration. Without them `inv + n` is accepted
 * too — it satisfies the same congruence — and the module stops being a
 * function of its input. The test kit attacks exactly that.
 */
const modinv = defineModule({
  name: 'int.modinv',
  doc: 'r = a⁻¹ mod n, supplied by the spender and checked (a·r ≡ 1, 0 ≤ r < n)',
  inputs: ['a', { name: 'inv', witness: true }],
  outputs: ['r'],
  hint: ({ a }, { n }) => ({ inv: invmod(a, n) }),
  model: ({ a }, { n }) => ({ r: invmod(a, n) }),
  emit: (asm, { n }) => {
    // canonicity: 0 ≤ inv < n. Drop either bound and the witness is no longer unique.
    asm.pick('inv', '_i1'); asm.num(0, '_zero'); asm.geVerify()
    asm.pick('inv', '_i2'); asm.num(n, '_n1'); asm.ltVerify()
    // soundness: a · inv ≡ 1 (mod n)
    asm.pick('a', '_a'); asm.pick('inv', '_i3'); asm.mul('_prod')
    asm.num(n, '_n2'); asm.mod('_res')
    asm.num(1, '_one'); asm.numEqualVerify()
    asm.roll('inv'); asm.rename('r')
    asm.nip()                                     // drop a
  },
  cases: [
    { name: '3⁻¹ mod 11', inputs: { a: 3n }, params: { n: 11n } },
    { name: '1⁻¹ mod 11', inputs: { a: 1n }, params: { n: 11n } },
    { name: '256-bit prime field', inputs: { a: (1n << 200n) + 7n }, params: { n: (1n << 256n) - 189n } }
  ]
})

module.exports = { modadd, modsub, modmul, modexp, modinv }
