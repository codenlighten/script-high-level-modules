'use strict'

// OPTIONAL: SHRINK A STAGE'S LOCKING SCRIPT WITH SCRIPTMIN.
//
//   SCRIPTMIN=1 node tools/groth16-chain.js
//
// Off by default, and off means byte for byte what was deployed: the chain
// walkers compare rebuilt scripts against mainnet and must keep matching.
//
// When on, a stage's locking script is replaced by scriptmin's output, which
// scriptmin proves equivalent to the original region by region (same stack
// failures, same final stacks, same set of checks). That proof is required
// here, not trusted: an optimized script whose proof did not pass is an error.
//
// Only for scripts that do not read their own bytes. A stage's OP_PUSH_TX
// preimage contains its locking script, which is fine — the preimage is ground
// against whatever script is deployed — but a script that inspects its own code
// (the carrier in src/modules/carry.js) must never go through here, and every
// stage embeds the carrier's body, so the carrier stays exactly as emitted.
//
// Optimizing the 473 KB final exponentiation takes about a minute, so results
// are cached on disk by the hash of the input script (.scriptmin-cache/).

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const bsv = require('@smartledger/bsv')

const OP_CODESEPARATOR = 0xab
const CACHE = path.join(__dirname, '..', '.scriptmin-cache')

const enabled = () => process.env.SCRIPTMIN === '1'

/**
 * Which scriptmin built the bytes: the commit npm installed it from. A minimized
 * script is only reproducible with the same optimizer, so deployments record
 * this and the chain walkers check it.
 */
function scriptminVersion () {
  try {
    const lock = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'node_modules', '.package-lock.json'), 'utf8'))
    const resolved = lock.packages['node_modules/scriptmin'].resolved
    return resolved.includes('#') ? resolved.split('#').pop() : resolved
  } catch (e) {
    try { return require('scriptmin/package.json').version } catch (e2) { return null }
  }
}

/** Fields for a deployment record: which scriptmin built it, if any. */
const provenance = () => (enabled() ? { scriptmin: scriptminVersion() } : {})

function load () {
  try {
    return require('scriptmin')
  } catch (e) {
    throw new Error('SCRIPTMIN=1 needs the optional dependency scriptmin (npm install github:codenlighten/scriptmin)')
  }
}

function codeSeparators (sm, buf) {
  return sm.parse(buf).filter((op) => op.code === OP_CODESEPARATOR).length
}

/**
 * The minimized script, or the script unchanged when SCRIPTMIN is not set.
 * `force` minimizes regardless, for rebuilding a deployment that was minimized.
 */
function minimize (script, { label = 'script', force = false } = {}) {
  if (!force && !enabled()) return script
  const sm = load()
  const input = script.toBuffer()
  // Keyed by optimizer as well as input, so a newer scriptmin never serves bytes
  // an older one produced.
  const key = crypto.createHash('sha256').update(String(scriptminVersion())).update(input).digest('hex')
  const cached = path.join(CACHE, key + '.hex')
  if (fs.existsSync(cached)) return bsv.Script.fromBuffer(Buffer.from(fs.readFileSync(cached, 'utf8').trim(), 'hex'))

  const t0 = Date.now()
  const { script: out, report } = sm.optimize(input, { differential: 0 })
  if (!report.verification.symbolic || !report.verification.symbolic.ok) {
    throw new Error(`scriptmin: no equivalence proof for ${label}`)
  }
  if (codeSeparators(sm, out) !== codeSeparators(sm, input)) {
    throw new Error(`scriptmin: ${label} changed its OP_CODESEPARATORs`)
  }
  fs.mkdirSync(CACHE, { recursive: true })
  fs.writeFileSync(cached, out.toString('hex'))
  if (process.env.SCRIPTMIN_QUIET !== '1') {
    console.log(`    scriptmin  ${label.padEnd(24)} ${input.length.toLocaleString('en-US').padStart(9)} → ${out.length.toLocaleString('en-US').padStart(9)} B  (−${report.reductionPct.toFixed(1)}%, proof passed, ${((Date.now() - t0) / 1000).toFixed(0)} s)`)
  }
  return bsv.Script.fromBuffer(out)
}

module.exports = { minimize, enabled, scriptminVersion, provenance }
