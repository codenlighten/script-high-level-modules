'use strict'

// THE GROTH16 VERIFICATION EQUATION, emitted and executed.
//
// A Groth16 proof is three curve points and the check is one equation:
//
//     e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)
//
// where α, β, γ, δ come from the verifying key and L is the public inputs
// combined into a G1 point. The right-hand side is fixed by the verifying key,
// so it is a constant in the locking script — 576 bytes of Fp12 — and comparing
// against it rather than folding e(α, β) in as a fourth pair saves 68 lines and
// about 204 KB.
//
// That is `pairing.verify(3, e(α, β))`: a product of three pairings against a
// compile-time constant. This builds it, runs it through
// bsv.Script.Interpreter under relay policy flags, and checks that a valid
// proof is accepted.
//
// WHAT THIS IS NOT: a complete verifier. It checks the equation for the L it is
// given, and a complete verifier must also bind L to the public inputs —
// L = IC₀ + Σ xᵢ·ICᵢ, which is ℓ fixed-base scalar multiplications on G1 at
// about 39,910 bytes each (docs/cost.md). Those are priced but not yet emitted:
// src/ec.js is written for secp256k1 and generalising it to an arbitrary short
// Weierstrass curve is its own piece of work. The equation above is the hard
// nine tenths and it is the part that is done.

const { proveAll } = require('../src/testkit')
const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')

const R = bls.R
const invR = (a) => {
  let r = 1n; let b = ((a % R) + R) % R; let e = R - 2n
  while (e > 0n) { if (e & 1n) r = r * b % R; b = b * b % R; e >>= 1n }
  return r
}

// A VALID INSTANCE, built from the group law rather than from a circuit.
//
// e(aG₁, bG₂) = e(G₁, G₂)^(ab), so the whole equation collapses to one identity
// among scalars: a·b = αβ + lγ + cδ (mod r). Choose every scalar but one and
// solve for the last, and the result is a genuine instance of the equation the
// verifier checks. What that does NOT establish is that the proof came from a
// circuit — Groth16's soundness is not what is under test here. The verifier is.
const K = { alpha: 0x2ecdba1cd7a0f9d2n, beta: 0x51a8f0c3d9b26e74n, gamma: 0x1f0538cd2b9e647n, delta: 0xcafebabedeadbeefn }
const PROOF = { l: 0x1234567890abcdefn, c: 0xfedcba0987654321n, a: 0x777777777777777n }
PROOF.b = (K.alpha * K.beta + PROOF.l * K.gamma + PROOF.c * K.delta) % R * invR(PROOF.a) % R

const A = bls.g1mul(PROOF.a)
const B = bls.g2mul(PROOF.b)
const L = bls.g1neg(bls.g1mul(PROOF.l))
const GAMMA = bls.g2mul(K.gamma)
const C = bls.g1neg(bls.g1mul(PROOF.c))
const DELTA = bls.g2mul(K.delta)
const EXPECTED = bls.pairing(bls.g1mul(K.alpha), bls.g2mul(K.beta))

const pairs = [{ P: A, Q: B }, { P: L, Q: GAMMA }, { P: C, Q: DELTA }]
const inputs = pairing.writePairs(pairs, 3)

// A proof that is not a proof. Every point is still on the curve, every
// witnessed inverse is still correct for the points supplied — the hint
// recomputes them — so nothing fails until the equation itself does. That is
// the case worth having: a verifier that accepts a valid proof and does not
// notice an invalid one is not a verifier, and forged WITNESSES are a different
// question from a forged PROOF.
const forgedA = pairing.writePairs(
  [{ P: bls.g1mul(PROOF.a + 1n), Q: B }, { P: L, Q: GAMMA }, { P: C, Q: DELTA }], 3)
const forgedC = pairing.writePairs(
  [{ P: A, Q: B }, { P: L, Q: GAMMA }, { P: bls.g1neg(bls.g1mul(PROOF.c + 1n)), Q: DELTA }], 3)

const m = pairing.verify(3, EXPECTED, {
  maxWitnessAttacks: Number(process.env.GROTH16_ATTACKS || 2),
  cases: [
    { name: 'a valid proof', inputs, params: { n: bls.P, nn: bls.P } },
    { name: 'A off by one generator', refuse: 'the equation does not hold for this A', inputs: forgedA, params: { n: bls.P, nn: bls.P } },
    { name: 'C off by one generator', refuse: 'the equation does not hold for this C', inputs: forgedC, params: { n: bls.P, nn: bls.P } }
  ]
})

const asm = new Asm()
asm.given([{ name: '_s', kind: 'bytes', width: 1 },
  ...m.inputs.map((i) => ({ name: i.name, kind: 'num', facts: F.range(0n, bls.P) }))])
m.emit(asm, { n: bls.P, nn: bls.P })
const bytes = asm.script().toBuffer().length

const started = Date.now()
console.log('\n  e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)\n')
console.log(`    3 Miller loops sharing one accumulator, one final exponentiation`)
console.log(`    ${63 * 3 + 5 * 3} lines, 63 squarings between them, ${m.inputs.filter((i) => i.witness).length} witnessed numbers`)
console.log(`    locking script  ${bytes.toLocaleString()} bytes\n`)

const { failures } = proveAll([[m, {}]])

const separate = 935334 * 3
console.log(`\n  Three separate pairings would be ${separate.toLocaleString()} bytes.`)
console.log(`  As a product they are ${bytes.toLocaleString()} — the ${separate - bytes >= 0 ? 'saving' : 'cost'} is ${Math.abs(separate - bytes).toLocaleString()} bytes,`)
console.log('  and it is the 126 squarings and two final exponentiations that go.')
console.log(`\n  ${((Date.now() - started) / 1000).toFixed(1)} s to run.\n`)
process.exit(failures.length ? 1 : 0)
