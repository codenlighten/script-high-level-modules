'use strict'

// A COIN THAT ONLY MOVES FOR SOMEONE OVER 21.
//
// Everything else in this repository is a measurement. This is the thing the
// measurements were for: a Bitcoin output whose spending condition is a
// mathematical claim about a person, checked by the network, revealing nothing.
//
//   the statement   "I am at least 21 years old as of 2026."
//   what is public  the year, and the age required
//   what is not     the birth year
//
// The proof is Groth16 over BLS12-381, produced by snarkjs — an independent
// setup, prover and field implementation. The verifier is Bitcoin Script: no
// pairing opcode, no extension-field type, no inversion primitive.
//
// Three outcomes, which is the whole product:
//
//   a valid proof of the right statement    the coin moves
//   a proof from someone underage           the coin does not move
//   a valid proof of a DIFFERENT statement   the coin does not move
//
// The third is the one that is easy to get wrong and the one that matters. The
// statement is fixed when the coin is locked, so a proof of "at least 21" is
// not a key to a coin that asked for "at least 30" — they are different coins.

const path = require('path')
const { proveAll } = require('../src/testkit')
const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')
const g16 = require('../src/modules/groth16')

const DIR = path.join(__dirname, '..', 'test', 'vectors', 'groth16-age')
const load = (f) => require(path.join(DIR, f))
const P = bls.P
const params = { n: P, nn: P }
const g1 = (p) => ({ x: BigInt(p[0]), y: BigInt(p[1]) })
const g2 = (p) => ({ x: [BigInt(p[0][0]), BigInt(p[0][1])], y: [BigInt(p[1][0]), BigInt(p[1][1])] })
const asProof = (j) => {
  const A = g1(j.pi_a); const B = g2(j.pi_b); const C = g1(j.pi_c)
  return { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }
}

const vkJson = load('vk.json')
const vk = {
  alpha: g1(vkJson.vk_alpha_1), beta: g2(vkJson.vk_beta_2),
  gamma: g2(vkJson.vk_gamma_2), delta: g2(vkJson.vk_delta_2),
  IC: vkJson.IC.map(g1)
}
const YEAR = 2026n
const honest = asProof(load('proof.json'))
const underage = asProof(load('proof-underage.json'))

const size = (m) => {
  const asm = new Asm()
  asm.given([{ name: '_s', kind: 'bytes', width: 1 },
    ...m.inputs.map((i) => ({ name: i.name, kind: 'num', facts: F.range(0n, P) }))])
  m.emit(asm, params)
  return asm.script().toBuffer().length
}

// The coin the bar puts on the counter: at least 21, as of 2026.
const coin21 = g16.verifier(vk, [YEAR, 21n], {
  maxWitnessAttacks: Number(process.env.DEMO_ATTACKS || 1),
  cases: [
    { name: 'a valid proof of being over 21', inputs: honest, params },
    { name: 'someone underage, proving anyway', refuse: 'the proof does not verify — no 7-bit decomposition of a negative number exists', inputs: underage, params }
  ]
})
// A different coin, asking a different question. Same proof, same prover.
const coin30 = g16.verifier(vk, [YEAR, 30n], {
  maxWitnessAttacks: 1,
  cases: [{ name: 'a proof of 21 offered to a coin that asked for 30', refuse: 'the statement is fixed when the coin is locked', inputs: honest, params }]
})

console.log(`
  A COIN THAT ONLY MOVES FOR SOMEONE OVER 21

    the statement    "I am at least 21 years old as of ${YEAR}."
    public           the year, and the age required
    private          the birth year — never on chain, never in the proof

    the prover       snarkjs, Groth16 over BLS12-381
    the verifier     Bitcoin Script — ${size(coin21).toLocaleString()} bytes, no pairing opcode
`)

const started = Date.now()
const { failures } = proveAll([[coin21, {}], [coin30, {}]])

console.log(`
  ${((Date.now() - started) / 1000).toFixed(1)} s.

    a valid proof of the right statement   the coin moves
    a proof from someone underage          the coin does not move
    a valid proof of a different statement the coin does not move

  The third is the one worth looking at twice. It is the SAME proof, from the
  same prover, and it is valid — for a claim the second coin did not make. The
  public inputs are compiled into the locking script, so "at least 21" and "at
  least 30" are different coins and a proof of one is not a key to the other.

  Nothing about the birth year is on chain. The network learned that a person
  was old enough and nothing else, and it enforced payment on that basis.
`)
process.exit(failures.length ? 1 : 0)
