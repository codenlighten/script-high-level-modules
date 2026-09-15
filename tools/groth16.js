'use strict'

// A GROTH16 VERIFIER, emitted and executed.
//
//     e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)
//
// A, B and C come from the unlocking script. γ, δ and L are pushed as constants
// by the locking script, and that distinction is the whole of the soundness: a
// spender who could choose γ could choose a γ that makes the equation hold for
// a proof of nothing. L is a constant because the statement is fixed when the
// coin is locked — a covenant that says "pay out to whoever proves THIS" knows
// its public inputs when it is written, so the ℓ scalar multiplications a
// general verifier would need happen off chain, once, for free.
//
// e(α, β) is fixed by the verifying key too, so it is a compile-time Fp12
// constant. Comparing against it rather than folding it in as a fourth pair is
// 68 fewer lines and about 204 KB cheaper.
//
// Three pairings on one Miller accumulator and one final exponentiation.
// Three separate pairings would be 2.8 MB; as a product they are 1.35.

const { proveAll } = require('../src/testkit')
const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')
const g16 = require('../src/modules/groth16')
const points = require('../src/modules/points')

const f = g16.fixture([3n, 5n])
const P381 = bls.P

// A proof that is not a proof. Every point is still on the curve and every
// witnessed inverse is still correct for the points supplied — the hint
// recomputes them — so nothing fails until the equation does. Forged WITNESSES
// are a different question from a forged PROOF, and a verifier has to refuse
// both.
const bend = (field, delta) => {
  const s = { ...f.scalars }
  s[field] += delta
  const A = bls.g1mul(s.a); const B = bls.g2mul(s.b); const C = bls.g1mul(s.c)
  return { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }
}

// Points on their curves and outside their subgroups. The whole verifier
// refuses these for two reasons at once — the subgroup check, and an equation
// that does not hold for them — so it cannot say which did the work.
// tools/groth16-split.js can, and does.
const A3 = points.outside.g1({ x: f.proof.Ax, y: f.proof.Ay })
const Bh = points.outside.g2({ x: [f.proof.Bx0, f.proof.Bx1], y: [f.proof.By0, f.proof.By1] })

const m = g16.verifier(f.vk, f.publicInputs, {
  maxWitnessAttacks: Number(process.env.GROTH16_ATTACKS || 2),
  cases: [
    { name: 'a valid proof', inputs: f.proof, params: { n: P381, nn: P381 } },
    { name: 'A off by one generator', refuse: 'the equation does not hold for this A', inputs: bend('a', 1n), params: { n: P381, nn: P381 } },
    { name: 'C off by one generator', refuse: 'the equation does not hold for this C', inputs: bend('c', 1n), params: { n: P381, nn: P381 } },
    // Not a wrong proof — not a proof. Before the curve checks these were
    // refused by the equation, which is the wrong reason to refuse them.
    { name: 'A not on the curve', refuse: 'a pair of field elements is not a point', inputs: { ...f.proof, Ay: (f.proof.Ay + 1n) % P381 }, params: { n: P381, nn: P381 } },
    { name: 'B not on the twist', refuse: 'a pair of Fp2 elements is not a twist point', inputs: { ...f.proof, By1: (f.proof.By1 + 1n) % P381 }, params: { n: P381, nn: P381 } },
    { name: 'A + (0, 2), outside G1', refuse: 'on the curve, of order 3r, and not in G1', inputs: { ...f.proof, Ax: A3.x, Ay: A3.y }, params: { n: P381, nn: P381 } },
    { name: 'B + a cofactor point, outside G2', refuse: 'on the twist and not in G2', inputs: { ...f.proof, Bx0: Bh.x[0], Bx1: Bh.x[1], By0: Bh.y[0], By1: Bh.y[1] }, params: { n: P381, nn: P381 } }
  ]
})

const asm = new Asm()
asm.given([{ name: '_s', kind: 'bytes', width: 1 },
  ...m.inputs.map((i) => ({ name: i.name, kind: 'num', facts: F.range(0n, P381) }))])
m.emit(asm, { n: P381, nn: P381 })
const bytes = asm.script().toBuffer().length

const started = Date.now()
console.log('\n  e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)\n')
console.log(`    from the unlocking script   A, B, C — the proof`)
console.log(`    from the locking script     γ, δ, L, and e(α, β) to compare against`)
console.log(`    ${f.publicInputs.length} public input(s), fixed when the coin was locked`)
console.log(`    204 lines, 63 squarings between them, ${m.inputs.filter((i) => i.witness).length} witnessed numbers`)
console.log(`    locking script  ${bytes.toLocaleString()} bytes\n`)

const { failures } = proveAll([[m, {}]])

console.log(`\n  ${((Date.now() - started) / 1000).toFixed(1)} s to run.`)
console.log('\n  A verifier whose public inputs are chosen at SPEND time is a different')
console.log('  object: it needs L computed on chain, which is one fixed-base scalar')
console.log('  multiplication on G1 per input at about 39,910 bytes (docs/cost.md).\n')
process.exit(failures.length ? 1 : 0)
