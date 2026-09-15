'use strict'

// A GROTH16 VERIFIER ACROSS THREE INPUTS OF ONE TRANSACTION.
//
// The whole verifier is past the 500,000-byte script policy, and its Miller
// loop alone — three pairings already sharing one accumulator — is past it too.
// So a two-way cut is not enough; the loop itself is cut, at round 31.
//
//     input 0   A, C ∈ G1; rounds 1–31 of three loops; publishes S₁
//     input 1   rounds 32–63, resuming from S₁; B ∈ G2; publishes S₂
//     input 2   the final exponentiation of S₂ against e(α, β)
//
// One data output carries everything the three must agree on — the proof, the
// state after round 31, the state after round 63 — and each stage computes its
// own part and witnesses the rest. All three build the blob and require it to
// be the committed output, so the witnessed halves are the computed ones.
//
// Three parts, each a different question:
//
//   1. is each stage sound on its own?      proved and attacked, stage by stage
//   2. is each SUBGROUP check load-bearing? a point outside its subgroup, given
//                                           to a stage built without the check
//                                           and to one built with it
//   3. does the transaction bind them?      built, ground and verified whole
//
// The transaction itself is built by src/groth16spend.js, which is also what
// bin/deploy-groth16.js puts on chain.

const path = require('path')
const bls = require('../src/bls12381')
const split = require('../src/modules/groth16split')
const points = require('../src/modules/points')
const spendlib = require('../src/groth16spend')
const { proveAll } = require('../src/testkit')

const n = (x) => x.toLocaleString('en-US')
const D = path.join(__dirname, '..', 'test', 'vectors', 'groth16-age')
const vkJson = require(path.join(D, 'vk.json'))
const proofJson = require(path.join(D, 'proof.json'))
const g1 = (p) => ({ x: BigInt(p[0]), y: BigInt(p[1]) })
const g2 = (p) => ({ x: [BigInt(p[0][0]), BigInt(p[0][1])], y: [BigInt(p[1][0]), BigInt(p[1][1])] })
const vk = {
  alpha: g1(vkJson.vk_alpha_1), beta: g2(vkJson.vk_beta_2),
  gamma: g2(vkJson.vk_gamma_2), delta: g2(vkJson.vk_delta_2), IC: vkJson.IC.map(g1)
}
const A = g1(proofJson.pi_a); const B = g2(proofJson.pi_b); const C = g1(proofJson.pi_c)
const proof = { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }
const STATEMENT = [2026n, 21n]

const v = split.verifier(vk, STATEMENT, { proof })

// ── part one: are the three stages sound on their own? ──────────────────────
//
// Each stage is proved against the interpreter on the real proof, and then
// attacked: every witnessed input is a value the SPENDER supplies, so for a
// sample of them the kit substitutes forgeries and requires refusal. A stage
// that computed the right answer but accepted a wrong witness would be worse
// than useless — the composition would carry the forgery forward.
{
  console.log('\n  1. the three stages, against the interpreter\n')
  const t0 = Date.now()
  const { failures } = proveAll([[v.stage1, {}], [v.stage2, {}], [v.stage3, {}]])
  if (failures.length) { console.log('\n  a stage did not hold up\n'); process.exit(1) }
  console.log(`  (${((Date.now() - t0) / 1000).toFixed(0)} s)`)
}

// ── part two: is each subgroup check the thing that refuses? ────────────────
//
// A refusal only shows a check matters if something ELSE would have accepted.
// The whole verifier refuses these proofs anyway — the pairing equation fails
// for them too — so the whole verifier cannot say which check did the work.
// A stage can: stage 1 checks no equation at all, it computes rounds 1–31 and
// publishes the result, and stage 2 computes rounds 32–63. So each is built
// twice, without the subgroup checks and with them, and given a proof whose
// point is on its curve and outside its subgroup:
//
//   A + (0, 2)        (0, 2) has order 3, so this is on the curve, of order 3r
//   B + [r]R          [r]R is a twist point killed by h₂ — on the twist, not in G2
//
// Without the checks each stage must ACCEPT, and with them it must REFUSE.
{
  console.log('\n  2. the subgroup checks, isolated\n')
  const shiftedA = points.fast.g1add(A, { x: 0n, y: 2n })
  const cofactor2 = (() => {
    for (let a = 1n; ; a++) {
      const R = bls.g2lift([a, 1n])
      if (R) return points.fast.g2mul(bls.R, R)
    }
  })()
  const shiftedB = points.fast.g2add(B, cofactor2)
  if (bls.g1InSubgroup(shiftedA) || !bls.g1onCurve(shiftedA)) throw new Error('the shifted A is not what this test needs')
  if (bls.g2InSubgroup(shiftedB) || !bls.g2onCurve(shiftedB)) throw new Error('the shifted B is not what this test needs')
  const proofA = { ...proof, Ax: shiftedA.x, Ay: shiftedA.y }
  const proofB = { ...proof, Bx0: shiftedB.x[0], Bx1: shiftedB.x[1], By0: shiftedB.y[0], By1: shiftedB.y[1] }
  const sib = (index) => ({ count: 3, index })

  const without = split.verifier(vk, STATEMENT, {
    subgroup: false,
    proof,
    cases: {
      1: [{ name: 'A + (0, 2), no subgroup check', spend: { proof: proofA, siblings: sib(0) }, params: {} }],
      2: [{ name: 'B + a cofactor point, no subgroup check', spend: { proof: proofB, siblings: sib(1) }, params: {} }]
    }
  })
  const withChecks = split.verifier(vk, STATEMENT, {
    proof,
    cases: {
      1: [{ name: 'A + (0, 2)', refuse: 'A is on the curve and not in G1', spend: { proof: proofA, siblings: sib(0) }, params: {} }],
      2: [{ name: 'B + a cofactor point', refuse: 'B is on the twist and not in G2', spend: { proof: proofB, siblings: sib(1) }, params: {} }]
    }
  })
  const t0 = Date.now()
  const { failures } = proveAll([
    [without.stage1, {}], [withChecks.stage1, {}],
    [without.stage2, {}], [withChecks.stage2, {}]
  ])
  if (failures.length) { console.log('\n  a subgroup check is not what decides these\n'); process.exit(1) }
  console.log(`\n  Without the checks both stages carry a point outside its subgroup forward;`)
  console.log(`  with them both refuse it. (${((Date.now() - t0) / 1000).toFixed(0)} s)`)
}

// ── part three: does the transaction bind them together? ────────────────────
//
// The three coins are outputs 0, 1 and 2 of ONE funding transaction, because
// that is what each stage's sibling check requires: it rebuilds the whole
// prevouts list from a single witnessed txid and compares the hash against the
// preimage's own hashPrevouts. Spending any of them alone is refused —
// tools/attack-siblings.js is the demonstration of why that matters.
{
  const FUNDING = 'a7'.repeat(32)
  const coins = [0, 1, 2].map((vout) => ({ txid: FUNDING, vout, satoshis: 1 }))
  const { tx, locks, unlocks, grind } = spendlib.buildSpend(v, proof, coins)
  console.log(`\n  3. the transaction\n`)
  console.log(`    fast filter agrees with the library on ${grind.filterChecked} nLockTimes (${grind.filterCanonical} canonical)`)

  const started = Date.now()
  const results = spendlib.verifyInputs(tx, locks, coins)
  const names = ['A, C ∈ G1; rounds 1–31', 'rounds 32–63; B ∈ G2', 'final exponentiation vs e(α,β)']
  results.forEach((r, i) => {
    console.log(`    input ${i}  ${names[i].padEnd(32)} ${n(locks[i].toBuffer().length).padStart(9)} B lock  ${n(unlocks[i].toBuffer().length).padStart(9)} B unlock  ${r.ok ? 'ACCEPTED' : 'REFUSED — ' + r.err}`)
  })
  console.log(`    output   the blob all three commit to      ${n(split.BLOB_BYTES).padStart(9)} B — ${split.BLOB_NAMES.length} field elements`)
  const policy = 500000
  const over = [...locks, ...unlocks].filter((s) => s.toBuffer().length > policy)
  console.log(`\n    ${over.length ? `${over.length} script(s) OVER` : 'every locking and unlocking script is under'} the ${n(policy)}-byte policy`)
  console.log(`    triple grind: ${n(grind.tries)} nLockTimes, ${grind.past1} cleared input 0, ${grind.past2} cleared inputs 0 and 1 — ${grind.seconds.toFixed(1)} s`)
  console.log(`    transaction ${n(tx.toBuffer().length)} bytes, ${((Date.now() - started) / 1000).toFixed(1)} s to verify all three inputs\n`)

  if (results.some((r) => !r.ok) || over.length) process.exit(1)
  console.log('  A zero-knowledge proof of age, verified by Bitcoin Script — points in their')
  console.log('  subgroups, pairing equation and all — in a computation no single script is')
  console.log('  allowed to be large enough to hold.\n')
}
