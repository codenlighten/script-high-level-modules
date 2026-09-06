'use strict'

// The whole Miller loop, emitted and executed.
//
// Everything else about pairings in this repository is a measurement that gets
// multiplied. This is not: it emits all 63 rounds of the optimal ate pairing's
// Miller loop as one locking script, hands it to bsv.Script.Interpreter under
// relay policy flags, and checks the twelve Fp12 coefficients that come back
// against the reference implementation. There is no estimate anywhere in it.
//
// It takes about fifteen seconds, which is why it is its own tool. The suite
// proves a two-round loop, which catches every structural mistake this can
// make; this one catches the ones that only appear at depth.

const { proveAll } = require('../src/testkit')
const pairing = require('../src/modules/pairing')
const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')

const started = Date.now()
const attacks = Number(process.env.MILLER_ATTACKS || 3)
const m = pairing.miller(pairing.FULL, { maxWitnessAttacks: attacks })
m.cases = m.cases.slice(0, 1)

const plan = pairing.schedule(pairing.FULL)
console.log(`\n  the Miller loop over ${pairing.FULL} bits of the BLS parameter`)
console.log(`    ${plan.filter((s) => s.kind === 'double').length} tangents, ${plan.filter((s) => s.kind === 'add').length} chords, ${plan.length} line products`)
console.log(`    ${plan.length} witnessed Fp2 inverses — ${plan.length * 2} numbers the spender chooses,`)
console.log('    every one bounded into [0, p) and checked against a·a⁻¹ = 1\n')

const { failures } = proveAll([[m, {}]])

// And the same script, measured without the harness around it.
const asm = new Asm()
const reduced = F.range(0n, bls.P)
asm.given([{ name: '_s', kind: 'bytes', width: 1 },
  ...m.inputs.map((i) => ({ name: i.name, kind: 'num', facts: reduced }))])
m.emit(asm, { n: bls.P, nn: bls.P })
const bytes = asm.script().toBuffer().length

console.log(`  ${bytes.toLocaleString()} bytes of locking script, ${((Date.now() - started) / 1000).toFixed(1)} s to emit and run`)
console.log('')
process.exit(failures.length ? 1 : 0)
