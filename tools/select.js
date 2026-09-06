'use strict'

// WHICH IMPLEMENTATION, AND WHY — decided by measurement, not by reputation.
//
// This repository has several pairs of modules that compute the same function
// by different schedules. Which is cheaper is a fact about the target, and this
// target's cost model reverses conventional wisdom in more than one place, so
// the question is settled here by emitting both and counting.
//
// The interesting output is not the winner. It is that the selector arrives at
// the same conclusions the implementation reached by hand — compressed
// squaring, cyclotomic squaring, a witnessed inverse — without being told them.

const bls = require('../src/bls12381')
const fp12 = require('../src/modules/fp12')
const fp2 = require('../src/modules/fp2')
const { select } = require('../src/select')

const P = bls.P
const params = { n: P, nn: P }

/** Elements of the cyclotomic subgroup, which is where half of this is defined. */
const cyc = (k) => {
  const f = bls.millerLoop(bls.g1mul(k), bls.g2mul(k + 1n))
  let e = bls.f12mulRaw(bls.f12conj(f), bls.f12inv(f))
  return bls.f12mulRaw(bls.f12frobN(e, 2), e)
}
const twelve = (p) => [...['00', '01', '10', '11', '20', '21'].map((s) => `${p}A${s}`),
  ...['00', '01', '10', '11', '20', '21'].map((s) => `${p}B${s}`)]
const spread = (f, p) => {
  const out = {}
  twelve(p).forEach((name, i) => { out[name] = f[i < 6 ? 0 : 1][Math.floor((i % 6) / 2)][i % 2] })
  return out
}
const subgroupVectors = [2n, 3n, 7n, 12345n].map((k) => spread(cyc(k), 'a'))

const CONTESTS = [
  {
    what: 'f ↦ f² in Fp12',
    domain: 'the cyclotomic subgroup',
    candidates: [
      { name: 'fp12.sqr', module: fp12.sqr, params },
      { name: 'fp12.cycSqr', module: fp12.cycSqr, params }
    ],
    vectors: subgroupVectors
  },
  {
    what: 'f ↦ f^|x| in Fp12',
    domain: 'the cyclotomic subgroup',
    candidates: [
      { name: 'fp12.powX', module: fp12.powX, params },
      { name: 'fp12.powXc', module: fp12.powXc, params }
    ],
    vectors: subgroupVectors.slice(0, 2)
  }
]

// And a contest that must FAIL, because the point of the agreement step is that
// it can. fp12.sqr and fp12.cycSqr compute the same function on the cyclotomic
// subgroup and different functions off it, so run outside the domain they are
// not interchangeable and the selector must refuse rather than pick a winner.
const OFF_DOMAIN = {
  what: 'f ↦ f² in Fp12',
  domain: 'ALL of Fp12 — a claim that is false',
  candidates: [
    { name: 'fp12.sqr', module: fp12.sqr, params },
    { name: 'fp12.cycSqr', module: fp12.cycSqr, params }
  ],
  vectors: [(() => {
    const o = {}
    twelve('a').forEach((k, i) => { o[k] = BigInt(i * 7919 + 3) })
    return o
  })()]
}

const objective = process.argv.find((a) => a.startsWith('--optimize='))?.split('=')[1] || 'total'
const pad = (s, n) => String(s).padStart(n)

console.log(`\n  instruction selection, minimising ${objective}\n`)
let failures = 0

for (const contest of CONTESTS) {
  const r = select(contest.what, { ...contest, objective, prime: P })
  console.log(`  ${r.what}   —   agreement checked on ${contest.vectors.length} vectors from ${r.domain}`)
  if (!r.agreed) { console.log('    THEY DISAGREE:'); for (const d of r.disagreements) console.log(`      ${d}`); failures++; continue }
  console.log('    candidate        lock      unlock       total    opcodes   stack   fee')
  for (const c of r.table) {
    const mark = c.name === r.chosen ? '  ◀' : ''
    console.log(`    ${c.name.padEnd(14)}${pad(c.bytes.toLocaleString(), 8)}${pad(c.unlockBytes.toLocaleString(), 12)}${pad(c.total.toLocaleString(), 12)}${pad(c.opcodes.toLocaleString(), 11)}${pad(c.maxStack, 8)}${pad(c.feeSat.toLocaleString(), 6)}${mark}`)
  }
  const [a, b] = r.table
  const w = r.table.find((c) => c.name === r.chosen)
  const l = r.table.find((c) => c.name !== r.chosen)
  console.log(`    chosen: ${r.chosen} — ${((1 - w.total / l.total) * 100).toFixed(1)}% smaller in total, ${w.witnessValues - l.witnessValues >= 0 ? '+' : ''}${w.witnessValues - l.witnessValues} witnessed values\n`)
}

// the refusal
{
  const r = select(OFF_DOMAIN.what, { ...OFF_DOMAIN, objective, prime: P })
  if (r.agreed) {
    console.log('  the off-domain contest AGREED, which means the agreement check is not working')
    failures++
  } else {
    console.log(`  off the subgroup, the same two candidates are refused rather than ranked:`)
    console.log(`    ${r.disagreements[0]}`)
    console.log('    which is the right answer — outside its domain fp12.cycSqr is not a squaring,')
    console.log('    and "cheaper" without "and equivalent, here" is not a finding.\n')
  }
}

console.log('  Nothing above was told that compression or the cyclotomic identities win.')
console.log('  The selector emitted both and counted, and the cost model did the rest.\n')
process.exit(failures ? 1 : 0)
