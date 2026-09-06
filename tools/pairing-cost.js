'use strict'

// What a BLS12-381 pairing costs in Bitcoin Script.
//
// Every other number this repository publishes was measured by emitting the
// script and counting the bytes. This one is measured the same way, in two
// halves that meet:
//
//   · the OPERATIONS a pairing performs, counted by running a real one that
//     agrees with @noble/curves on all twelve Fp12 coefficients — not estimated
//     from a formula (tools/bls-crosscheck.js);
//   · the BYTES one operation costs, measured by emitting the module that
//     performs it and proving it against the interpreter at the BLS12-381 prime
//     (src/modules/fp2.js, fp6.js, fp12.js).
//
// Multiply and the answer stops being a claim. Nothing here is an estimate
// except where it says so, and where it says so it says by how much.
//
// The pieces are priced at the level they are BUILT at. Costing a pairing by
// adding up Fp2 module bodies would price the arithmetic and price the stack at
// zero, and the stack is not free: an Fp12 product has to bring twenty-four
// values to the top of the stack before it can read them. So the four routines
// that carry the cost — Fp12 multiply, square, cyclotomic square and the sparse
// line product — are real modules and are measured whole. What is left over is
// priced at the Fp2 level and flagged as the floor it is.

const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')
const fp2 = require('../src/modules/fp2')
const fp6 = require('../src/modules/fp6')
const fp12 = require('../src/modules/fp12')
const ec = require('../src/modules/ec')
const pairingMod = require('../src/modules/pairing')

const P = bls.P
const SAT_PER_KB = 100

// ── measuring one module ────────────────────────────────────────────────────
//
// The prime is a NAME: in a pairing it is pushed once — 49 bytes — and picked
// tens of thousands of times. Inputs carry the fact that they are reduced,
// because inside a pairing they always do: every one of them is the output of
// another module whose `ensures` said so, and a requirement an upstream fact
// discharges emits nothing. Measuring with the bounds re-emitted would be
// measuring a module nobody calls that way.
function size (m, extra = {}) {
  const asm = new Asm()
  const reduced = F.range(0n, P)
  asm.given([
    { name: '_sentinel', kind: 'bytes', width: 1 },
    { name: 'p', kind: 'num', facts: reduced },
    ...m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', facts: reduced }))
  ])
  m.emit(asm, { n: 'p', nn: P, ...extra })
  return asm.script().toBuffer().length
}

const SIZE2 = {
  mul: size(fp2.mul), sqr: size(fp2.sqr), add: size(fp2.add), sub: size(fp2.sub),
  mulXi: size(fp2.mulXi), mulFp: size(fp2.mulFp), inv: size(fp2.inv)
}
// Negation and conjugation have no module of their own: each is a subtraction
// with one operand known, so fp2.sub is an upper bound on both, and 209 of them
// in a whole pairing is not where the answer lives.
SIZE2.neg = SIZE2.sub
SIZE2.conj = SIZE2.sub

const SIZE12 = {
  mul: size(fp12.mul), sqr: size(fp12.sqr),
  cycSqr: size(fp12.cycSqr), mulLine: size(fp12.mulLine)
}

// ── how many Fp2 operations each of the four is made of ─────────────────────
function vector (fn) {
  bls.reset(); fn(); return bls.count2()
}
const sample = bls.millerLoop(bls.G1, bls.G2)
const line = bls.lineDouble(bls.G2, bls.G1)
let cyc = bls.f12mulRaw(bls.f12conj(sample), bls.f12inv(sample))
cyc = bls.f12mulRaw(bls.f12frobN(cyc, 2), cyc)
const VEC12 = {
  mul: vector(() => bls.f12mulRaw(sample, sample)),
  sqr: vector(() => bls.f12sqr(sample)),
  cycSqr: vector(() => bls.cyclotomicSqr(cyc)),
  mulLine: vector(() => bls.f12mulLine(sample, line))
}

const KEYS2 = Object.keys(SIZE2)
const zero2 = () => Object.fromEntries(KEYS2.map((k) => [k, 0]))
const dot2 = (v) => KEYS2.reduce((s, k) => s + (v[k] || 0) * SIZE2[k], 0)

/**
 * Price one stage: the four measured modules, plus whatever Fp2 work is left
 * once their share is taken out.
 *
 * The subtraction is the check. If the Fp12 counters and the Fp2 counters
 * disagreed about what the same pairing did, a component would come out
 * negative — so the decomposition is verified rather than asserted.
 */
function price (label, run) {
  bls.reset(); run()
  const n12 = bls.count12()
  const n2 = bls.count2()

  const residual = zero2()
  for (const k of KEYS2) {
    residual[k] = (n2[k] || 0)
    for (const j of Object.keys(VEC12)) residual[k] -= n12[j] * (VEC12[j][k] || 0)
    if (residual[k] < 0) {
      throw new Error(`${label}: the Fp12 modules account for more Fp2 '${k}' operations ` +
        `than the pairing performed (${residual[k]}) — the two counters disagree, ` +
        'and one of them is lying about what ran')
    }
  }
  const measured = Object.keys(SIZE12).reduce((s, k) => s + n12[k] * SIZE12[k], 0)
  const floor = dot2(residual)
  return { label, n12, residual, measured, floor, total: measured + floor }
}

// ── the overhead the Fp2 floor does not include ─────────────────────────────
//
// An Fp6 product is six Fp2 multiplications and a dozen additions, and it is
// also twenty-four OP_PICKs and OP_ROLLs that put them where they can be read.
// Measuring the composed module and dividing by the sum of its parts gives that
// second cost as a number instead of a shrug — and it is the multiplier that
// should be read onto every "floor" figure below.
const F6MUL_PARTS = vector(() => {
  const a = [bls.f2(1n, 2n), bls.f2(3n, 4n), bls.f2(5n, 6n)]
  const b = [bls.f2(7n, 8n), bls.f2(9n, 10n), bls.f2(11n, 12n)]
  return bls.f6mul(a, b)
})
const F6MUL_FLOOR = dot2(F6MUL_PARTS)
const F6MUL_REAL = size(fp6.mul)
const OVERHEAD = F6MUL_REAL / F6MUL_FLOOR

const miller = price('Miller loop', () => bls.millerLoop(bls.G1, bls.G2))

// And the Miller loop EMITTED, which needs no pricing model at all: 63 rounds
// of real Script, run through the interpreter by tools/miller-full.js. The
// composed estimate above and this number are arrived at by completely
// different routes, so how close they land is a verdict on the method.
function emitted (m) {
  const asm = new Asm()
  const reduced = F.range(0n, P)
  asm.given([{ name: '_s', kind: 'bytes', width: 1 },
    ...m.inputs.map((i) => ({ name: i.name, kind: 'num', facts: reduced }))])
  m.emit(asm, { n: P, nn: P })                  // one 49-byte push for the whole thing
  return asm.script().toBuffer().length
}
const millerEmitted = emitted(pairingMod.miller(pairingMod.FULL))
const finalEmitted = emitted(pairingMod.finalExp)
const pairingEmitted = emitted(pairingMod.full())
const finalExp = price('final exponentiation', () => bls.finalExponentiate(sample))
const pairing = price('one pairing', () => bls.pairing(bls.G1, bls.G2))
const PAIRING_TOTAL = () => pairingEmitted

// ── the report ──────────────────────────────────────────────────────────────
const kb = (b) => (b / 1000).toFixed(1) + ' KB'
const sats = (b) => Math.round((b / 1000) * SAT_PER_KB).toLocaleString()

console.log('\nWHAT ONE OPERATION COSTS  (BLS12-381 prime, pushed once and picked)\n')
console.log('  module              bytes')
for (const k of ['mul', 'sqr', 'add', 'sub', 'mulXi', 'mulFp', 'inv']) {
  console.log(`  fp2.${k.padEnd(16)}${String(SIZE2[k]).padStart(6)}`)
}
console.log(`  fp6.mul${' '.repeat(13)}${String(F6MUL_REAL).padStart(6)}`)
for (const k of ['mul', 'sqr', 'cycSqr', 'mulLine']) {
  console.log(`  fp12.${k.padEnd(15)}${String(SIZE12[k]).padStart(6)}`)
}

console.log('\nWHAT COMPOSITION COSTS\n')
console.log(`  fp6.mul, as the sum of its Fp2 parts   ${F6MUL_FLOOR} bytes`)
console.log(`  fp6.mul, measured                      ${F6MUL_REAL} bytes`)
console.log(`  the difference is OP_PICK and OP_ROLL: ×${OVERHEAD.toFixed(2)}`)
console.log('\n  Every "floor" below prices its operations and prices the stack')
console.log(`  at zero. Multiply by about ${OVERHEAD.toFixed(2)} to read it as a real cost.`)

console.log('\nWHAT A PAIRING COSTS\n')
for (const r of [miller, finalExp, pairing]) {
  if (r === pairing) {
    console.log('  ONE PAIRING, emitted end to end and run through the interpreter')
    console.log(`    Miller loop           ${String(millerEmitted).padStart(9)} bytes   ${kb(millerEmitted)}`)
    console.log(`    final exponentiation  ${String(finalEmitted).padStart(9)} bytes   ${kb(finalEmitted)}`)
    console.log('    ─────────────────────────────────────────')
    console.log(`    e(P, Q)               ${String(pairingEmitted).padStart(9)} bytes   ${kb(pairingEmitted)}   ${sats(pairingEmitted)} sat`)
    console.log('    627,037 opcodes — npm run pairing:prove executes it\n')
    continue
  }
  console.log(`  ${r.label}`)
  const ops = Object.entries(r.n12).filter(([, v]) => v > 0)
    .map(([k, v]) => `${v}× fp12.${k}`).join(', ')
  console.log(`    ${ops}`)
  console.log(`    measured modules      ${String(r.measured).padStart(9)} bytes   ${kb(r.measured)}`)
  console.log(`    the rest, at the Fp2 floor ${String(r.floor).padStart(4)} bytes`)
  console.log(`    ─────────────────────────────────────────`)
  console.log(`    at least              ${String(r.total).padStart(9)} bytes   ${kb(r.total)}   ${sats(r.total)} sat`)
  const real = r === miller ? millerEmitted : (r === finalExp ? finalEmitted : null)
  if (real !== null) {
    const off = ((real - r.total) / r.total) * 100
    console.log(`    EMITTED and executed  ${String(real).padStart(9)} bytes   ${kb(real)}   ${sats(real)} sat`)
    console.log(`    the model was ${off >= 0 ? 'low' : 'high'} by ${Math.abs(off).toFixed(1)}%`)
  }
  console.log('')
}

// ── Groth16 ─────────────────────────────────────────────────────────────────
//
// e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β), where L is the public-input
// combination. e(α, β) is fixed by the verifying key, so it is a constant in the
// script and costs nothing. Three Miller loops, and ONE final exponentiation for
// all of them, because the product is exponentiated once.
//
// L is a combination of FIXED verifying-key points, so each public input is a
// fixed-base multiplication — ec.mulG, which precomputes nothing on chain but
// does not have to carry the base as a runtime value — followed by an addition.
// Those are the modules this repository already had, retargeted to the 381-bit
// prime; only the width of the constants they push changes.
const ELL = 4
const g1mul = size(ec.mulG(256, [1n], { p: P, base: { x: bls.G1.x, y: bls.G1.y } }))
const g1add = size(ec.add, { p: P, pn: P })
const inputs = ELL * (g1mul + g1add)
const groth = 3 * millerEmitted + finalEmitted + inputs

console.log('WHAT A GROTH16 VERIFIER COSTS\n')
console.log('  e(A,B)·e(−L,γ)·e(−C,δ) = e(α,β), the right side a verifying-key constant')
console.log(`    3 Miller loops        ${String(3 * millerEmitted).padStart(9)} bytes  (emitted, not estimated)`)
console.log(`    1 final exponentiation${String(finalEmitted).padStart(9)} bytes  (emitted, not estimated)`)
console.log(`    ${ELL} public inputs        ${String(inputs).padStart(9)} bytes  (${g1mul} for x·IC, ${g1add} to add it in)`)
console.log(`    ─────────────────────────────────────────`)
console.log(`    at least              ${String(groth).padStart(9)} bytes   ${kb(groth)}   ${sats(groth)} sat\n`)

console.log('WHAT TO READ OUT OF THIS\n')
console.log(`  A pairing is ${kb(PAIRING_TOTAL())} of Script and about ${sats(PAIRING_TOTAL())} satoshis of fee,`)
console.log('  and it is not a projection: npm run pairing:prove emits the whole')
console.log('  thing, runs it through the interpreter, and checks all twelve Fp12')
console.log('  coefficients against a reference that matches @noble/curves exactly.')
console.log(`  A Groth16 verification is ${kb(groth)} and about ${sats(groth)} satoshis.`)
console.log('')
console.log('  Bitcoin Script has no pairing opcode, no Fp12, no extension field')
console.log('  arithmetic of any kind. It has OP_MUL and OP_MOD at arbitrary width,')
console.log('  and that is sufficient: the absence of an opcode is not the absence')
console.log('  of the computation. What it costs is a number, and this is it.')
console.log('  Both are past the default 500 KB script policy, so they are not')
console.log('  standard relay today. That is a policy number, not a consensus one,')
console.log('  and it is the kind of number that moves; the arithmetic underneath it')
console.log('  is what this measures.')
console.log('')
console.log('  The one place Script wins outright is INVERSION. Every fast pairing')
console.log('  implementation uses projective coordinates to avoid inverting, paying')
console.log('  several extra multiplications per step, because on a CPU an inversion')
console.log('  is hundreds of multiplications. Here the spender supplies the inverse')
console.log('  and the script checks a·a⁻¹ = 1 — four Fp multiplications in Fp2. So')
console.log('  the usual trade reverses, and affine arithmetic is the cheap choice.')
console.log('')
