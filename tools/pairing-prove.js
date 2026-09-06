'use strict'

// A BLS12-381 PAIRING, EMITTED AND EXECUTED.
//
// Not measured and multiplied. Not modelled. This builds e(P, Q) as a single
// locking script, hands it to bsv.Script.Interpreter under the same relay
// policy flags as every other test here, and compares the twelve Fp12
// coefficients that come back against the reference implementation — which
// itself agrees with @noble/curves byte for byte (tools/bls-crosscheck.js).
//
// Bitcoin Script has no pairing opcode. No Fp12, no Fp6, no Fp2, no
// extension-field arithmetic of any kind. It has OP_MUL and OP_MOD at
// arbitrary width, and this is what that turns out to be sufficient for.
//
// Most of the numbers in the unlocking script are witnesses the spender chooses
// — 136 coefficients for the 68 Fp2 inverses the loop needs, twelve for the one
// Fp12 inversion, and sixty for the decompressions the compressed ladders make
// — and every one is bounded into [0, p) and checked. A pairing that accepted a
// second witness for the same input would not be a pairing.

const { proveAll } = require('../src/testkit')
const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')

/** Emit a module and count its bytes, without running it. */
function bytesOf (m, params) {
  const asm = new Asm()
  const reduced = F.range(0n, bls.P)
  asm.given([{ name: '_s', kind: 'bytes', width: 1 },
    ...m.inputs.map((i) => ({ name: i.name, kind: 'num', facts: reduced }))])
  m.emit(asm, params)
  return asm.script().toBuffer().length
}

const started = Date.now()
const attacks = Number(process.env.PAIRING_ATTACKS || 2)
const plan = pairing.schedule(pairing.FULL)
const loop = pairing.miller(pairing.FULL)
const P = { n: bls.P, nn: bls.P }

console.log('\n  e(P, Q) on BLS12-381, as Bitcoin Script\n')
console.log(`    Miller loop            ${bytesOf(loop, P).toLocaleString().padStart(9)} bytes`)
console.log(`      ${plan.filter((s) => s.kind === 'double').length} tangents, ${plan.filter((s) => s.kind === 'add').length} chords, ${plan.length} line products`)
console.log(`    final exponentiation   ${bytesOf(pairing.finalExp, P).toLocaleString().padStart(9)} bytes`)
console.log(`      easy part, then ${bls.HARD_TERMS.length} terms over 6 shared ladders`)
console.log('')

const whole = pairing.full({ maxWitnessAttacks: attacks })
const { failures } = proveAll([[whole, {}]])

console.log(`\n  ${whole.inputs.filter((i) => i.witness).length} witnessed numbers, every one bounded into [0, p) and checked.`)
console.log(`  ${((Date.now() - started) / 1000).toFixed(1)} s to emit and run.\n`)
process.exit(failures.length ? 1 : 0)
