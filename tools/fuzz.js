'use strict'

// DIFFERENTIAL FUZZING: the model against the Script, on inputs nobody chose.
//
// Every module is checked against its own cases, and the cases are the ones
// somebody thought of. That is the weakness the last four bugs lived in — each
// was a value outside the range anybody had written a case for.
//
// So this generates inputs instead of choosing them, and for each one asks two
// questions the suite otherwise asks only where a case exists:
//
//   does the Script compute what the model says?
//   does the module's own `ensures` hold of what the model returned?
//
// The domains come from `requires`. That is the payoff for having stated them:
// the same declaration that decides where a bound is emitted also says what the
// module is defined on, so the fuzzer samples the domain rather than guessing at
// it. A module with no stated domain and no `fuzz` hook is SKIPPED and said to
// be skipped — a fuzzer that quietly tests nothing is worse than none.
//
// The seed is printed. A failure here has to be reproducible or it is a rumour.

const { proveModule, build, complete, checkEnsures } = require('../src/testkit')
const { evaluate } = require('../src/run')
const { factsFor } = require('../src/module')
const int = require('../src/modules/int')
const bytes = require('../src/modules/bytes')
const u32 = require('../src/modules/u32')
const ec = require('../src/modules/ec')
const schnorr = require('../src/modules/schnorr')
const ecJs = require('../src/ec')
const fp2mod = require('../src/modules/fp2')
const fp6mod = require('../src/modules/fp6')
const fp12mod = require('../src/modules/fp12')
const g2mod = require('../src/modules/g2')
const BLS = require('../src/bls12381').P

// A module whose promise is true of the cases somebody wrote and false of the
// domain it claims. The cases below are the ones a careful author would write —
// small, edge-ish, and all inside the false promise — so the suite passes it and
// only generated inputs find the lie. This is the fuzzer's own check: it runs
// first, and if it does not fail, nothing after it means anything.
const { defineModule } = require('../src/module')
const { mod } = require('../src/bigint')
const overpromising = defineModule({
  name: 'broken.overpromise',
  doc: 'computes (a + b) mod n and promises a range it does not keep',
  inputs: ['a', 'b'],
  outputs: ['r'],
  requires: ({ n }) => ({ a: { range: { lo: 0n, hi: n } }, b: { range: { lo: 0n, hi: n } } }),
  ensures: () => ({ r: { range: { lo: 0n, hi: 100n } } }),
  model: ({ a, b }, { n }) => ({ r: mod(a + b, n) }),
  emit: (asm, { n }) => { asm.add('s'); asm.num(n, '_n'); asm.mod('r') },
  cases: [
    { name: 'small', inputs: { a: 7n, b: 9n }, params: { n: 1000003n } },
    { name: 'zero', inputs: { a: 0n, b: 0n }, params: { n: 1000003n } },
    { name: 'edge', inputs: { a: 40n, b: 50n }, params: { n: 1000003n } }
  ]
})

const SEED = Number(process.env.FUZZ_SEED || 20260905)
const ROUNDS = Number(process.env.FUZZ_ROUNDS || 40)

/** xorshift128, so a failing run reproduces from its seed alone. */
function rng (seed) {
  let a = seed >>> 0 || 1; let b = 362436069; let c = 521288629; let d = 88675123
  return () => {
    const t = a ^ (a << 11)
    a = b; b = c; c = d
    d = (d ^ (d >>> 19)) ^ (t ^ (t >>> 8))
    return (d >>> 0) / 0x100000000
  }
}

/** A BigInt in [lo, hi), biased toward the edges where the bugs live. */
function pickBig (rnd, lo, hi) {
  const span = hi - lo
  const r = rnd()
  if (r < 0.12) return lo                                  // the low edge
  if (r < 0.24) return hi - 1n                             // the high edge
  if (r < 0.30) return lo + 1n
  let v = 0n
  const bits = span.toString(2).length
  for (let i = 0; i < bits; i += 30) v = (v << 30n) | BigInt(Math.floor(rnd() * (1 << 30)))
  return lo + (v % span)
}

const pickBytes = (rnd, n) => Buffer.from(Array.from({ length: n }, () => Math.floor(rnd() * 256)))

/**
 * The inputs for one fuzz round, or null when the module does not say enough
 * about its domain for a generated input to be meaningful.
 */
function domainFor (m, params, rnd) {
  const need = factsFor(m.requires, params)
  const out = {}
  for (const slot of m.inputs) {
    const want = need[slot.name]
    if (want && want.range) { out[slot.name] = pickBig(rnd, want.range.lo, want.range.hi); continue }
    const width = slot.width !== undefined ? slot.width : params.width
    if (slot.kind === 'bytes' && width !== undefined) { out[slot.name] = pickBytes(rnd, width); continue }
    if (!slot.witness) return null                         // not enough is known
  }

  // Which of those the module works out for itself. Asking it is better than a
  // rule about which inputs are witnesses: `schnorr.liftX` takes an x-only key
  // AND the y for it, both marked witness, and only the second is derived. A
  // generated value for a derived witness would be a wrong one, and would take
  // precedence over the honest answer.
  if (m.hint) {
    let derived = {}
    try { derived = m.hint(out, params) || {} } catch (e) { /* it may need what we do not have */ }
    for (const k of Object.keys(derived)) delete out[k]
  }
  return out
}

const hmac = require('../src/modules/hmac')
const sha256 = require('../src/modules/sha256')
const merkleMod = require('../src/modules/merkle')
const crypto = require('crypto')
const mleaves = Array.from({ length: 4 }, (_, i) => crypto.createHash('sha256').update('m' + i).digest())
const mtree = merkleMod.tree(mleaves)

const TARGETS = [
  ['int.modadd', int.modadd, { n: (1n << 256n) - 189n }],
  ['int.modsub', int.modsub, { n: (1n << 256n) - 189n }],
  ['int.modmul', int.modmul, { n: (1n << 256n) - 189n }],
  ['int.modexp', int.modexp, { n: (1n << 256n) - 189n, e: 65537n }],
  ['int.modinv', int.modinv, { n: (1n << 256n) - 189n }],
  ['u32.rotr', u32.rotr, { k: 7 }],
  ['u32.shr', u32.shr, { k: 3 }],
  ['u32.xor', u32.xor, {}],
  ['u32.add', u32.add, {}],
  ['u32.ch', u32.ch, {}],
  ['u32.maj', u32.maj, {}],
  ['sha256.sigma0', u32.sigma0, {}],
  ['sha256.Sigma1', u32.Sigma1, {}],
  ['bytes.reverse', bytes.reverse, { width: 32 }],
  ['bytes.beToNum', bytes.beToNum, { width: 32 }],
  ['ec.add', ec.add, {}],
  ['ec.double', ec.double, {}],
  ['schnorr.liftX', schnorr.liftX, {}],
  // Structured inputs, generated by the modules themselves.
  ['hmac.sha256', hmac.sha256, { keyLen: 32, algo: 'sha256' }],
  ['hmac.sha1', hmac.sha1, { keyLen: 20, algo: 'sha1' }],
  ['merkle.verify', merkleMod.verify(mtree.root, { depth: 2, leaves: mleaves }), { depth: 2, root: mtree.root }],
  ['sha256.block', sha256.block, {}, 8],
  ['schnorr.verify', schnorr.verifier(['seed']), {}, 6],
  // The pairing tower, over the BLS12-381 prime. Every one of these states its
  // domain as an interval, so the fuzzer samples it rather than guessing —
  // except the two whose domain is a SUBGROUP, which no interval can say, and
  // which therefore carry a fuzz hook that runs an easy part to get one.
  ['fp2.mul', fp2mod.mul, { n: BLS }],
  ['fp2.sqr', fp2mod.sqr, { n: BLS }],
  ['fp2.add', fp2mod.add, { n: BLS }],
  ['fp2.sub', fp2mod.sub, { n: BLS }],
  ['fp2.neg', fp2mod.neg, { n: BLS }],
  ['fp2.conj', fp2mod.conj, { n: BLS }],
  ['fp2.mulXi', fp2mod.mulXi, { n: BLS }],
  ['fp2.mulFp', fp2mod.mulFp, { n: BLS }],
  ['fp2.inv', fp2mod.inv, { n: BLS }],
  ['fp6.mul', fp6mod.mul, { n: BLS }, 8],
  ['fp6.sqr', fp6mod.sqr, { n: BLS }, 8],
  ['fp6.mulV', fp6mod.mulV, { n: BLS }, 8],
  ['fp12.mul', fp12mod.mul, { n: BLS }, 4],
  ['fp12.sqr', fp12mod.sqr, { n: BLS }, 4],
  ['fp12.cycSqr', fp12mod.cycSqr, { n: BLS }, 4],
  ['fp12.mulLine', fp12mod.mulLine, { n: BLS }, 4],
  ['fp12.conj', fp12mod.conj, { n: BLS }, 4],
  ['fp12.frob', fp12mod.frob, { n: BLS }, 4],
  ['fp12.inv', fp12mod.inv, { n: BLS }, 3],
  ['g2.stepDouble', g2mod.stepDouble, { n: BLS }, 6],
  ['g2.stepAdd', g2mod.stepAdd, { n: BLS }, 6]
]

let checked = 0; let skipped = 0; let failures = 0
console.log(`\n  seed ${SEED}, ${ROUNDS} rounds each`)

// The fuzzer's own check, before anything it says can be believed.
{
  const params = { n: 1000003n }
  const rnd = rng(SEED)
  let caught = null
  const suitePassed = proveModule(overpromising, { params, quiet: true }).failures.length === 0
  for (let i = 0; i < 200 && !caught; i++) {
    const inputs = domainFor(overpromising, params, rnd)
    if (!inputs) break
    const values = complete(overpromising, params, inputs)
    const broken = checkEnsures(overpromising, params, overpromising.model(values, params))
    if (broken.length) caught = broken[0]
  }
  console.log(`\n  selfcheck  a module that overpromises: its own cases ${suitePassed ? 'pass' : 'FAIL'}, generated inputs ${caught ? 'catch it' : 'DO NOT catch it'}`)
  if (caught) console.log(`             ${caught}`)
  if (!suitePassed || !caught) { console.log('\n  the fuzzer cannot be trusted to find anything'); process.exit(1) }
}
console.log('')

for (const [name, m, baseParams, rounds] of TARGETS) {
  const rnd = rng(SEED + name.length)
  let ran = 0; let refused = 0; let bad = null
  const n = rounds || ROUNDS

  for (let i = 0; i < n && !bad; i++) {
    // A module with structure a range cannot describe generates its own input,
    // and may say which parameters go with it — a Merkle proof determines the
    // depth it is a proof for.
    let params = baseParams
    let inputs
    if (m.fuzz) {
      const g = m.fuzz(rnd, params)
      if (g && g.inputs) { inputs = g.inputs; params = { ...params, ...(g.params || {}) } } else inputs = g
    } else {
      inputs = domainFor(m, params, rnd)
    }
    if (inputs === null || inputs === undefined) break

    let values, expected
    try {
      values = complete(m, params, inputs)
      expected = m.model(values, params)
    } catch (e) {
      // Not every point in a domain is in the module's PRECONDITION — ec.add is
      // undefined on two points with the same x, and the model says so by
      // throwing. Those are the cases the module refuses, and the suite already
      // covers them; here they are simply not fuzz material.
      refused++
      continue
    }

    const broken = checkEnsures(m, params, expected)
    if (broken.length) { bad = `its own promise does not hold — ${broken[0]}`; break }

    try {
      const built = build(m, params, values)
      const r = evaluate(built.unlock, built.lock)
      if (!r.ok) bad = `the Script refused what the model accepted: ${r.error}`
    } catch (e) { bad = e.message }
    ran++
  }

  if (ran === 0 && !bad) { skipped++; console.log(`  skip  ${name.padEnd(16)} its domain is not stated, and it declares no fuzz hook`); continue }
  checked++
  if (bad) { failures++; console.log(`  FAIL  ${name.padEnd(16)} ${bad}`) } else {
    console.log(`  ok    ${name.padEnd(16)} ${ran} random inputs agreed${refused ? `, ${refused} outside the precondition` : ''}`)
  }
}

console.log(`\n  ${checked} modules fuzzed, ${skipped} skipped, ${failures} disagreed`)
process.exit(failures ? 1 : 0)
