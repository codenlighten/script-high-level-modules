'use strict'

// A GROTH16 PROOF THIS REPOSITORY DID NOT MAKE, checked by Bitcoin Script.
//
// tools/groth16.js proves the verifier against a fixture built from the group
// law: every scalar chosen and one solved for. That establishes the verifier
// checks the intended relation. It does not establish that the relation is the
// one a real proving stack produces, because nothing outside this repository
// was involved.
//
// These vectors were produced by snarkjs over BLS12-381 — its own trusted
// setup, its own prover, its own field arithmetic — for the circuit c = a·b
// with c public, a = 3, b = 11. See test/vectors/groth16-bls12381/README.md.
//
// Three things are checked, and the third is the one worth having:
//
//   the real proof is accepted
//   a displaced proof is refused
//   the real proof is refused by a verifier built for a DIFFERENT statement
//
// The last says the public inputs are bound into the coin. A verifier that
// accepted a valid proof of something else would be checking arithmetic and not
// checking a claim.

const path = require('path')
const { proveAll } = require('../src/testkit')
const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')
const g16 = require('../src/modules/groth16')

const DIR = path.join(__dirname, '..', 'test', 'vectors', 'groth16-bls12381')
const vkJson = require(path.join(DIR, 'vk.json'))
const proofJson = require(path.join(DIR, 'proof.json'))
const publicJson = require(path.join(DIR, 'public.json'))

const P = bls.P
const params = { n: P, nn: P }
const g1 = (p) => ({ x: BigInt(p[0]), y: BigInt(p[1]) })
const g2 = (p) => ({ x: [BigInt(p[0][0]), BigInt(p[0][1])], y: [BigInt(p[1][0]), BigInt(p[1][1])] })

const vk = {
  alpha: g1(vkJson.vk_alpha_1),
  beta: g2(vkJson.vk_beta_2),
  gamma: g2(vkJson.vk_gamma_2),
  delta: g2(vkJson.vk_delta_2),
  IC: vkJson.IC.map(g1)
}
const publicInputs = publicJson.map((x) => BigInt(x))
const A = g1(proofJson.pi_a)
const B = g2(proofJson.pi_b)
const C = g1(proofJson.pi_c)
const proof = { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }

// Before any Script: does the equation hold under this implementation's
// pairing? If snarkjs and this disagreed about coordinates or about which
// equation Groth16 is, everything below would be testing a coincidence.
const L = g16.combine(vk.IC, publicInputs)
const lhs = bls.f12mulRaw(bls.f12mulRaw(bls.pairing(A, B), bls.pairing(bls.g1neg(L), vk.gamma)), bls.pairing(bls.g1neg(C), vk.delta))
const agrees = bls.f12eq(lhs, bls.pairing(vk.alpha, vk.beta))

console.log('\n  a Groth16 proof from snarkjs, over BLS12-381\n')
console.log(`    circuit           c = a·b, c public`)
console.log(`    public signal     ${publicInputs.join(', ')}`)
console.log(`    equation holds under this pairing: ${agrees}`)
if (!agrees) { console.log('\n  the proof does not satisfy the equation here — nothing below would mean anything\n'); process.exit(1) }

// A proof of the same shape that is not this proof.
const displaced = { ...proof, Ax: bls.g1mul(2n, A).x, Ay: bls.g1mul(2n, A).y }

const m = g16.verifier(vk, publicInputs, {
  maxWitnessAttacks: Number(process.env.GROTH16_ATTACKS || 2),
  cases: [
    { name: 'the proof snarkjs made', inputs: proof, params },
    { name: 'A doubled', refuse: 'the equation does not hold for this A', inputs: displaced, params }
  ]
})

// And the same proof against a verifier for a different statement. L is a
// compile-time constant, so this is a DIFFERENT LOCKING SCRIPT — which is the
// point: the statement is the coin.
const other = g16.verifier(vk, [publicInputs[0] + 1n], {
  maxWitnessAttacks: 1,
  cases: [{ name: 'a proof of 33 against a coin that asks for 34', refuse: 'the statement is bound into the script', inputs: proof, params }]
})

const size = (mod) => {
  const asm = new Asm()
  asm.given([{ name: '_s', kind: 'bytes', width: 1 },
    ...mod.inputs.map((i) => ({ name: i.name, kind: 'num', facts: F.range(0n, P) }))])
  mod.emit(asm, params)
  return asm.script().toBuffer().length
}
console.log(`    locking script    ${size(m).toLocaleString()} bytes\n`)

const started = Date.now()
const { failures } = proveAll([[m, {}], [other, {}]])
console.log(`\n  ${((Date.now() - started) / 1000).toFixed(1)} s`)
console.log('\n  The proof was made by an implementation that has never seen this one,')
console.log('  and Bitcoin Script accepted it.\n')
process.exit(failures.length ? 1 : 0)
