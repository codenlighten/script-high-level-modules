'use strict'

// OPTIONAL: FIELD MODULES WITH THEIR REDUCTIONS RE-DECIDED.
//
//   RELAX=1 node tools/pairing-chain.js
//
// Every Fp2 module returns canonical coefficients, so a composition of them
// reduces after nearly every addition: 97% of the OP_MODs in the Groth16 stages
// belong to fp2.add, fp2.sub, fp2.mul, fp2.mulXi and fp2.sqr. Inside fp12.sqr,
// fp12.mulLine and the rest, almost none of those reductions are needed — the
// next thing done with the value is more ring arithmetic — only the twelve
// outputs have to be canonical. §1 of docs/optimization.md, one level up.
//
// relaxed(m) is m with its emitted code replaced by scriptmin's relax() of that
// code (see scriptmin's src/relax.js):
//
//   - the module is emitted as usual, into a scratch Asm, with a numeric
//     modulus and inputs known to be canonical — the form it takes inside a
//     pairing, with no input checks;
//   - relax() lifts that script to its arithmetic circuit (it refuses anything
//     that is not OP_ADD/OP_SUB/OP_MUL/OP_MOD by p), drops every reduction,
//     recompiles with lazy reduction taking p from the stack, and requires the
//     result to equal the emitted script output for output on canonical
//     inputs;
//   - the module keeps m's name suffixed, its inputs, outputs, requires,
//     ensures, model and cases, so the kit proves it exactly as it proves m.
//
// Off by default: RELAX=1 changes the stage scripts, and the chain walkers
// compare what they rebuild with mainnet byte for byte.

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const bsv = require('@smartledger/bsv')
const { defineModule } = require('./module')
const { Asm } = require('./asm')
const F = require('./facts')

const CACHE = path.join(__dirname, '..', '.scriptmin-cache')
const MAX_BITS = 768

const enabled = () => process.env.RELAX === '1'

function numeric (params, who) {
  const nn = params.nn !== undefined ? params.nn : params.n
  if (typeof nn !== 'bigint') throw new Error(`${who}.relaxed: needs the modulus as a number (params.n or params.nn)`)
  return nn
}

function scriptmin () {
  try {
    return require('scriptmin')
  } catch (e) {
    throw new Error('RELAX=1 needs the optional dependency scriptmin')
  }
}

function scriptminCommit () {
  try {
    const lock = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'node_modules', '.package-lock.json'), 'utf8'))
    return lock.packages['node_modules/scriptmin'].resolved.split('#').pop()
  } catch (e) {
    return 'unknown'
  }
}

const built = new Map()

/**
 * The relaxed script for m at modulus nn: it expects m's inputs, then p on top,
 * and leaves m's outputs. Also returns the peak stack depth it reaches, counted
 * from the bottom of its inputs, for Asm's maxStack.
 */
function relaxedScript (m, nn) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', facts: F.range(0n, nn) })))
  m.emit(asm, { n: nn })
  const emitted = asm.script().toBuffer()
  const commit = scriptminCommit()
  const key = crypto.createHash('sha256').update(`relaxed|${commit}|${MAX_BITS}|${m.name}|`).update(emitted).digest('hex')
  if (built.has(key)) return built.get(key)

  const file = path.join(CACHE, key + '.json')
  let entry
  if (fs.existsSync(file)) {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'))
    entry = { script: Buffer.from(j.script, 'hex'), peak: j.peak }
  } else {
    const sm = scriptmin()
    const r = sm.relax(emitted, { modulus: nn, modulusInput: true, maxBits: MAX_BITS })
    const { heights } = require('scriptmin/src/analysis')
    const hm = heights(sm.parse(r.script), m.inputs.length + 1, 0).hm
    entry = { script: r.script, peak: Math.max(...hm) }
    fs.mkdirSync(CACHE, { recursive: true })
    fs.writeFileSync(file, JSON.stringify({ module: m.name, commit, maxBits: MAX_BITS, script: r.script.toString('hex'), peak: entry.peak, report: r.report }, (k, v) => (typeof v === 'bigint' ? String(v) : v)))
    if (process.env.SCRIPTMIN_QUIET !== '1') {
      console.log(`    relaxed    ${m.name.padEnd(24)} ${String(r.report.original.bytes).padStart(6)} → ${String(r.report.relaxed.bytes).padStart(6)} B, ${r.report.original.mod} → ${r.report.relaxed.mod} OP_MOD`)
    }
  }
  built.set(key, entry)
  return entry
}

/**
 * Relax a block of emitted code in place.
 *
 * `script` is the block as it would be emitted, compiled separately: its
 * inputs first (deepest first), p pushed as a constant wherever it needs it,
 * and exactly its outputs left behind. The relaxed block takes the same inputs
 * and p on top instead, so it is spliced in after rolling `inputs` to the top
 * in order and copying p from `modulus` (a slot name).
 */
function relaxBlock (asm, { key, script, inputs, outputs, nn, modulus }) {
  const commit = scriptminCommit()
  const id = crypto.createHash('sha256').update(`block|${commit}|${MAX_BITS}|${key}|`).update(script).digest('hex')
  let entry = built.get(id)
  if (!entry) {
    const file = path.join(CACHE, id + '.json')
    if (fs.existsSync(file)) {
      const j = JSON.parse(fs.readFileSync(file, 'utf8'))
      entry = { script: Buffer.from(j.script, 'hex'), peak: j.peak }
    } else {
      const sm = scriptmin()
      const r = sm.relax(script, { modulus: nn, modulusInput: true, maxBits: MAX_BITS })
      const { heights } = require('scriptmin/src/analysis')
      entry = { script: r.script, peak: Math.max(...heights(sm.parse(r.script), inputs.length + 1, 0).hm) }
      fs.mkdirSync(CACHE, { recursive: true })
      fs.writeFileSync(file, JSON.stringify({ block: key, commit, maxBits: MAX_BITS, script: r.script.toString('hex'), peak: entry.peak, report: r.report }, (k, v) => (typeof v === 'bigint' ? String(v) : v)))
      if (process.env.SCRIPTMIN_QUIET !== '1') {
        console.log(`    relaxed    ${key.padEnd(24)} ${String(r.report.original.bytes).padStart(6)} → ${String(r.report.relaxed.bytes).padStart(6)} B, ${r.report.original.mod} → ${r.report.relaxed.mod} OP_MOD`)
      }
    }
    built.set(id, entry)
  }
  for (const name of inputs) asm.roll(name)
  asm.pick(modulus, '_nRelaxed')
  const base = asm.stack.length - (inputs.length + 1)
  if (base + entry.peak > asm.maxStack) asm.maxStack = base + entry.peak
  asm.s.add(bsv.Script.fromBuffer(entry.script))
  asm.stack.length = base
  for (const name of outputs) asm.stack.push({ name, kind: 'num', facts: F.range(0n, nn), origin: name })
  return outputs
}

const relaxedModules = new Map()

/** m, with its reductions re-decided. Same contract, same cases. */
function relaxed (m) {
  if (relaxedModules.has(m)) return relaxedModules.get(m)
  const r = defineModule({
    name: m.name + '.relaxed',
    doc: m.doc + ' — reductions re-decided by scriptmin relax',
    inputs: m.inputs,
    outputs: m.outputs,
    requires: m.requires,
    ensures: m.ensures,
    model: m.model,
    prologue: m.prologue,
    fuzz: m.fuzz,
    cases: m.cases,
    notes: m.notes,
    emit: (asm, params) => {
      const nn = numeric(params, m.name)
      const { script, peak } = relaxedScript(m, nn)
      // The calling convention has put the inputs on top. p goes above them:
      // the prologue pushed it when the modulus is a number; otherwise it is
      // copied from its slot.
      if (typeof params.n === 'string') asm.pick(params.n, '_nRelaxed')
      const top = asm.stack.length
      const base = top - (m.inputs.length + 1)
      for (let k = 0; k < m.inputs.length; k++) {
        const slot = asm.stack[base + k]
        if (slot.name !== m.inputs[k].name) {
          throw new Error(`${r.name}: expected input '${m.inputs[k].name}' at depth ${top - 1 - base - k}, found '${slot.name}'`)
        }
      }
      if (base + peak > asm.maxStack) asm.maxStack = base + peak
      asm.s.add(bsv.Script.fromBuffer(script))
      asm.stack.length = base
      for (const o of m.outputs) {
        asm.stack.push({ name: o.name, kind: 'num', facts: F.range(0n, nn), origin: o.name })
      }
    }
  })
  relaxedModules.set(m, r)
  return r
}

/** m, relaxed when RELAX=1. */
const choose = (m) => (enabled() ? relaxed(m) : m)

module.exports = { relaxed, choose, enabled, relaxedScript, relaxBlock }
