'use strict'

// EVERY MEASURED NUMBER, AS ONE MACHINE-READABLE FILE.
//
// This repository already learned once that a number written into prose drifts:
// docs/index.md claimed RSA verification was 955 bytes for months after it
// became 969, and docs/optimization.md claimed ec.add was 139 long after a
// missing-bound audit had made it 167. Both are generated now.
//
// A paper is the same problem with a longer half-life and no `npm test`. So
// every figure any write-up should quote is produced here, measured from the
// code, and written to results.json — which is checked in, checked by
// `--check`, and is the only thing a document should ever read a number from.
//
//     source ──► measurement ──► results.json ──► every table, every claim
//
// rather than
//
//     source ──► someone remembers ──► a number in a PDF
//
// Nothing here is transcribed and nothing is rounded. Where a figure cannot be
// measured — an opcode count that needs the interpreter, a fee that depends on
// a policy — it is absent rather than approximated.

const fs = require('fs')
const path = require('path')
const { execSync } = require('child_process')

const { Asm } = require('../src/asm')
const F = require('../src/facts')
const { countOps } = require('../src/run')
const bls = require('../src/bls12381')
const fp2 = require('../src/modules/fp2')
const fp6 = require('../src/modules/fp6')
const fp12 = require('../src/modules/fp12')
const g2mod = require('../src/modules/g2')
const pairing = require('../src/modules/pairing')
const groth16 = require('../src/modules/groth16')

const P = bls.P
const OUT = path.join(__dirname, '..', 'results.json')

/**
 * Emit a module and measure it, with the prime as a literal pushed once.
 *
 * Inputs carry the fact that they are reduced, because inside a composition
 * they always do — every one is the output of a module whose `ensures` said so,
 * and a requirement an upstream fact discharges emits nothing. Measuring with
 * the bounds re-emitted would measure a module nobody calls that way.
 */
function emit (m, modulus, params) {
  const asm = new Asm()
  const reduced = F.range(0n, P)
  const slots = [{ name: '_s', kind: 'bytes', width: 1 }]
  // A slot whose range is [p, p+1) IS p, which is how findExact() lets a bound
  // copy the modulus instead of pushing 49 bytes of it again. Declaring the
  // named modulus without that fact made fp2.inv's "marginal" size come out
  // LARGER than its standalone size — the measurement was of a module that
  // could not see the constant it was standing next to.
  if (typeof modulus === 'string') slots.push({ name: modulus, kind: 'num', facts: F.range(P, P + 1n) })
  slots.push(...m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', facts: reduced })))
  asm.given(slots)
  m.emit(asm, { n: modulus, nn: P, ...params })
  return asm.script()
}

/**
 * TWO numbers, because a module has two honest sizes and quoting one of them as
 * the other is how a table starts lying.
 *
 * `bytes` is the module standalone: it pushes the 381-bit prime itself, 49
 * bytes, which a locking script has to do once.
 *
 * `marginal` is the module with the prime already on the stack, referenced by
 * OP_PICK. That is what it costs as the ten-thousandth operation in a pairing,
 * and for fp2.mul the difference between the two is more than the module.
 */
function measure (m, params = {}) {
  const standalone = emit(m, P, params)
  let marginal = standalone
  try { marginal = emit(m, 'p', params) } catch (err) { /* pushes its own prime */ }
  return {
    bytes: standalone.toBuffer().length,
    marginal: marginal.toBuffer().length,
    opcodes: countOps(standalone),
    witnesses: m.inputs.filter((i) => i.witness).length
  }
}

const commit = (() => {
  try { return execSync('git rev-parse HEAD', { cwd: path.join(__dirname, '..') }).toString().trim() } catch (e) { return null }
})()

// ── the tower ───────────────────────────────────────────────────────────────
const modules = {}
const add = (name, m, params) => { modules[name] = measure(m, params) }
add('fp2.mul', fp2.mul); add('fp2.sqr', fp2.sqr); add('fp2.add', fp2.add)
add('fp2.sub', fp2.sub); add('fp2.neg', fp2.neg); add('fp2.conj', fp2.conj)
add('fp2.mulXi', fp2.mulXi); add('fp2.mulFp', fp2.mulFp); add('fp2.inv', fp2.inv)
add('fp6.mul', fp6.mul); add('fp6.sqr', fp6.sqr); add('fp6.mulV', fp6.mulV)
add('fp12.mul', fp12.mul); add('fp12.sqr', fp12.sqr); add('fp12.cycSqr', fp12.cycSqr)
add('fp12.mulLine', fp12.mulLine); add('fp12.conj', fp12.conj); add('fp12.frob', fp12.frob)
add('fp12.inv', fp12.inv); add('fp12.powX', fp12.powX)
add('g2.stepDouble', g2mod.stepDouble); add('g2.stepAdd', g2mod.stepAdd)

// ── the pairing ─────────────────────────────────────────────────────────────
const plan = pairing.schedule(pairing.FULL)
const miller = measure(pairing.miller(pairing.FULL))
const finalExp = measure(pairing.finalExp)
const e = measure(pairing.full())
const products = [1, 2, 3].map((k) => {
  const one = measure(pairing.product(k))
  return { pairs: k, bytes: one.bytes, opcodes: one.opcodes, witnesses: one.witnesses, separately: k * e.bytes, saved: k * e.bytes - one.bytes }
})

const fx = groth16.fixture([3n, 5n])
const verifier = groth16.verifier(fx.vk, fx.publicInputs, {
  cases: [{ name: 'a valid proof', inputs: fx.proof, params: { n: P, nn: P } }]
})
const groth = measure(verifier)

// ── what the network has actually run ───────────────────────────────────────
//
// Stated as a fraction, because "both halves" was claimed once and was wrong:
// f^|x| is ONE of the five ladders the final exponentiation runs, not the
// exponentiation. The Miller-loop stage is complete; the rest is a share.
const ledger = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'deployments.json'), 'utf8'))
const deployments = (Array.isArray(ledger) ? ledger : ledger.deployments || []).map((d) => ({
  name: d.name, claim: d.claim, lockBytes: d.lockBytes || d.lock_bytes || null, deploy: d.deploy || d.txid || null, spend: d.spend || null
}))

const onchain = {
  millerComplete: true,
  millerShare: miller.bytes / e.bytes,
  ladderShareOfFinalExp: modules['fp12.powX'].bytes / finalExp.bytes,
  ladderShareOfPairing: modules['fp12.powX'].bytes / e.bytes,
  pairingShareOnChain: (miller.bytes + modules['fp12.powX'].bytes) / e.bytes,
  note: 'the Miller-loop stage is complete on chain; of the final exponentiation only one of its five f^|x| ladders is'
}

// ── operation counts, from running a real pairing ───────────────────────────
const count = (fn) => { bls.reset(); fn(); return { fp2: bls.count2(), fp12: bls.count12() } }
const sample = bls.millerLoop(bls.G1, bls.G2)

const results = {
  generated: new Date().toISOString().slice(0, 10),
  commit,
  curve: {
    name: 'BLS12-381',
    p: '0x' + P.toString(16),
    r: '0x' + bls.R.toString(16),
    x: '-0x' + (-bls.X).toString(16),
    tower: 'Fp2 = Fp[u]/(u^2+1); Fp6 = Fp2[v]/(v^3-xi), xi = u+1; Fp12 = Fp6[w]/(w^2-v)'
  },
  feeRateSatPerKB: 100,
  scriptPolicyBytes: 500000,
  modules,
  pairing: {
    miller: { ...miller, tangents: plan.filter((s) => s.kind === 'double').length, chords: plan.filter((s) => s.kind === 'add').length, lines: plan.length, squarings: pairing.FULL },
    finalExp: { ...finalExp, ladders: bls.HARD_TERMS.reduce((m, t) => Math.max(m, t.j), 0), terms: bls.HARD_TERMS.length, frobenius: bls.HARD_TERMS.reduce((s, t) => s + t.i, 0) },
    e,
    products,
    groth16: { ...groth, publicInputs: fx.publicInputs.length, spenderChooses: verifier.inputs.filter((i) => !i.witness).map((i) => i.name) },
    onchain
  },
  operations: {
    miller: count(() => bls.millerLoop(bls.G1, bls.G2)),
    finalExp: count(() => bls.finalExponentiate(sample)),
    pairing: count(() => bls.pairing(bls.G1, bls.G2))
  },
  deployments
}

const text = JSON.stringify(results, null, 2) + '\n'
const check = process.argv.includes('--check')
const existing = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : ''

/** The date and the commit move on their own; everything else must not. */
const stable = (s) => {
  try {
    const o = JSON.parse(s)
    delete o.generated; delete o.commit
    return JSON.stringify(o)
  } catch (err) { return null }
}

if (check) {
  if (stable(existing) !== stable(text)) {
    console.log('results: results.json is out of date — run `npm run results`')
    process.exit(1)
  }
  console.log(`results: results.json matches the code (${Object.keys(modules).length} modules measured)`)
} else {
  fs.writeFileSync(OUT, text)
  console.log(`results: wrote results.json — ${Object.keys(modules).length} modules, ${deployments.length} deployments`)
  console.log(`  one pairing            ${e.bytes.toLocaleString()} bytes, ${e.opcodes.toLocaleString()} opcodes`)
  console.log(`  a Groth16 verifier     ${groth.bytes.toLocaleString()} bytes, ${groth.opcodes.toLocaleString()} opcodes`)
  console.log(`  on mainnet             ${(onchain.pairingShareOnChain * 100).toFixed(1)}% of a pairing, by bytes`)
}
