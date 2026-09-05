'use strict'

const { defineModule } = require('../module')
const { mod, powmod, invmod, bitsOf } = require('../bigint')

/**
 * The domain these modules are correct on, as a fact rather than a sentence.
 *
 * Every one of them documented "for a, b already in [0, n)" and enforced
 * nothing, and every one of them returns a NON-CANONICAL NEGATIVE outside it —
 * measured, not supposed: modadd(−3, 1) mod 11 is −2, modmul(−3, 4) mod 11 is
 * −1. OP_MOD truncates, so a negative anywhere upstream stays negative, and a
 * result congruent to the right answer is not the same as the right answer.
 *
 * The modulus may be a literal or the NAME of a live value, and a name carries
 * no number — so a module whose contract is stated in terms of the modulus has
 * to be told what it is. `nn` is that, and it is required rather than assumed,
 * because assuming it would mean silently having no contract at all.
 */
function numericModulus (params, who) {
  const nn = params.nn !== undefined ? params.nn : params.n
  if (typeof nn === 'bigint' || typeof nn === 'number') return BigInt(nn)
  throw new Error(`${who}: the modulus is '${params.n}', a value on the stack, so its number is not known here — ` +
    'pass nn: <the modulus> alongside it, or the contract this module states would quietly mean nothing')
}

function residues (params, who) {
  const nn = params.nn !== undefined ? params.nn : params.n
  if (typeof nn === 'bigint' || typeof nn === 'number') {
    return { range: { lo: 0n, hi: BigInt(nn) } }
  }
  throw new Error(`${who}: the modulus is '${params.n}', a value on the stack, so its number is not known here — ` +
    'pass nn: <the modulus> alongside it, or the contract this module states would quietly mean nothing')
}
const reduced = (who) => (params) => {
  const r = residues(params, who)
  return { a: r, b: r }
}

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

/**
 * Put the modulus where the next opcode can read it.
 *
 * `n` is either a BigInt — pushed as a literal — or the NAME of a value already
 * live on the stack, which is copied instead. The second form is what makes
 * composition affordable: a 256-bit modulus is a 33-byte push, and a curve
 * operation needs it six times. Pushed once by the caller and picked, those six
 * references cost two bytes each.
 */
function withModulus (asm, n, name = '_n') {
  if (typeof n === 'string') asm.pick(n, name)
  else asm.num(n, name)
  return name
}

/**
 * Put a literal modulus on the stack BEFORE the requirement checks run, so they
 * can copy it instead of pushing it again — and so the module's own reduction
 * can copy it too.
 *
 * A 2048-bit modulus is a 259-byte push. Bounding two inputs and then reducing
 * with it costs three of those pushed separately and one pushed once: 797 bytes
 * against 285. The prologue exists for exactly that, and for nothing else.
 */
const PN = '_pn'
function pushModulus (asm, n) { if (typeof n !== 'string') asm.num(n, PN) }
const modulusName = (n) => (typeof n === 'string' ? n : PN)
const pushedItself = (n) => typeof n !== 'string'

/** Bring the inputs back above whatever the prologue pushed. */
function liftInputs (asm, n, names) {
  if (!pushedItself(n)) return
  for (const x of names) asm.roll(x)
}
/** Drop the modulus the prologue pushed, leaving the result on top. */
function dropModulus (asm, n) { if (pushedItself(n)) asm.nip() }

const modadd = defineModule({
  name: 'int.modadd',
  doc: 'r = (a + b) mod n, for a, b already in [0, n)',
  inputs: ['a', 'b'],
  outputs: ['r'],
  requires: reduced('int.modadd'),
  ensures: (p) => ({ r: residues(p, 'int.modadd') }),
  model: ({ a, b }, { n }) => ({ r: mod(a + b, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    liftInputs(asm, n, ['a', 'b'])
    asm.add('sum')                       // a + b ≥ 0 given the requirement
    asm.pick(modulusName(n), '_n')
    asm.mod('r')
    dropModulus(asm, n)
  },
  notes: ['correct only for inputs already reduced into [0, n) — now stated as a requirement, so the caller either proves it or the check is emitted'],
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
  requires: reduced('int.modsub'),
  ensures: (p) => ({ r: residues(p, 'int.modsub') }),
  model: ({ a, b }, { n }) => ({ r: mod(a - b, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    liftInputs(asm, n, ['a', 'b'])
    asm.sub('diff')                      // may be negative: OP_MOD would keep the sign
    asm.pick(modulusName(n), '_n')
    asm.add('shifted')                   // + n lands it in (0, 2n)
    asm.pick(modulusName(n), '_n2')
    asm.mod('r')
    dropModulus(asm, n)
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
  requires: reduced('int.modmul'),
  ensures: (p) => ({ r: residues(p, 'int.modmul') }),
  model: ({ a, b }, { n }) => ({ r: mod(a * b, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    liftInputs(asm, n, ['a', 'b'])
    asm.mul('prod')
    asm.pick(modulusName(n), '_n')
    asm.mod('r')
    dropModulus(asm, n)
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
  requires: (p) => ({ x: residues(p, 'int.modexp') }),
  ensures: (p) => ({ r: residues(p, 'int.modexp') }),
  model: ({ x }, { n, e }) => ({ r: powmod(x, e, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n, e }) => {
    const bits = bitsOf(e)                        // MSB first; bits[0] is always 1
    const N = modulusName(n)                      // pushed once, picked thereafter
    if (!pushedItself(n)) asm.pick(N, PN)         // a named modulus is copied in
    liftInputs(asm, n, ['x'])
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
  requires: (p) => ({ a: residues(p, 'int.modinv') }),
  ensures: (p) => ({ r: residues(p, 'int.modinv') }),
  hint: ({ a }, { n }) => ({ inv: invmod(a, n) }),
  model: ({ a }, { n }) => ({ r: invmod(a, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const N = modulusName(n)
    // canonicity: 0 ≤ inv < n, in one opcode, and RECORDED — so a caller that
    // consumes the result inherits the bound instead of re-establishing it.
    // The bound needs the modulus as a NUMBER; where it lives is a separate
    // question, and pushBound answers it by finding the value already on the
    // stack when there is one.
    asm.bound('inv', 0n, numericModulus(params, 'int.modinv'), '_bi')
    // soundness: a · inv ≡ 1 (mod n)
    asm.pick('a', '_a'); asm.pick('inv', '_i3'); asm.mul('_prod')
    asm.pick(N, '_n2'); asm.mod('_res')
    asm.num(1, '_one'); asm.numEqualVerify()
    asm.roll('inv'); asm.rename('r')
    asm.roll('a'); asm.drop()                     // drop a
    dropModulus(asm, n)
  },
  cases: [
    { name: '3⁻¹ mod 11', inputs: { a: 3n }, params: { n: 11n } },
    { name: '1⁻¹ mod 11', inputs: { a: 1n }, params: { n: 11n } },
    { name: '256-bit prime field', inputs: { a: (1n << 200n) + 7n }, params: { n: (1n << 256n) - 189n } },
    // Zero has no inverse, and no witness makes it look as though it does.
    { name: '0⁻¹ mod 11', refuse: 'zero is not invertible', inputs: { a: 0n, inv: 1n }, params: { n: 11n } },
    { name: '0⁻¹, witness 0', refuse: 'zero is not invertible', inputs: { a: 0n, inv: 0n }, params: { n: 11n } },
    // Nor does a value sharing a factor with a composite modulus.
    { name: '3⁻¹ mod 9', refuse: '3 and 9 are not coprime', inputs: { a: 3n, inv: 3n }, params: { n: 9n } }
  ]
})

module.exports = { modadd, modsub, modmul, modexp, modinv }
