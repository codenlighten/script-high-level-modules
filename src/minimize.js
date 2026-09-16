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

// Which scriptmin built the bytes. A minimized script is only reproducible with
// the same optimizer, so a deployment records the commit that built it, and the
// chain walkers rebuild it with that commit. New builds use `scriptmin`; an
// older commit a deployment still needs is installed beside it as
// `scriptmin-<first 7 hex digits>` (see optionalDependencies).

function lockEntry (pkg) {
  try {
    const lock = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'node_modules', '.package-lock.json'), 'utf8'))
    return lock.packages['node_modules/' + pkg] || null
  } catch (e) {
    return null
  }
}

/** The commit an installed scriptmin package was built from, or null. */
function installedCommit (pkg) {
  const entry = lockEntry(pkg)
  if (!entry || !entry.resolved || !entry.resolved.includes('#')) return null
  return entry.resolved.split('#').pop()
}

/** The commit new builds are minimized with. */
function scriptminVersion () {
  return installedCommit('scriptmin')
}

/** The installed package that is exactly `commit`, or null. */
function packageFor (commit) {
  if (!commit) return null
  if (installedCommit('scriptmin') === commit) return 'scriptmin'
  const alias = 'scriptmin-' + commit.slice(0, 7)
  return installedCommit(alias) === commit ? alias : null
}

const installHint = (commit) =>
  `npm install scriptmin-${commit.slice(0, 7)}@github:codenlighten/scriptmin#${commit}`

/** Fields for a deployment record: which scriptmin built it, if any. */
const provenance = () => (enabled() ? { scriptmin: scriptminVersion() } : {})

function load (commit) {
  const pkg = packageFor(commit)
  if (!pkg) {
    if (!commit) throw new Error('SCRIPTMIN=1 needs the optional dependency scriptmin')
    throw new Error(`scriptmin ${commit.slice(0, 12)} is not installed: ${installHint(commit)}`)
  }
  return require(pkg)
}

function codeSeparators (sm, buf) {
  return sm.parse(buf).filter((op) => op.code === OP_CODESEPARATOR).length
}

/**
 * The minimized script, or the script unchanged when SCRIPTMIN is not set.
 * `force` minimizes regardless and `version` names the scriptmin commit to use,
 * for rebuilding a deployment exactly as it was built.
 */
function minimize (script, { label = 'script', force = false, version = null } = {}) {
  if (!force && !enabled()) return script
  const commit = version || scriptminVersion()
  const sm = load(commit)
  const input = script.toBuffer()
  // Keyed by optimizer as well as input, so one scriptmin never serves bytes
  // another produced.
  const key = crypto.createHash('sha256').update(String(commit)).update(input).digest('hex')
  const cached = path.join(CACHE, key + '.hex')
  if (fs.existsSync(cached)) return bsv.Script.fromBuffer(Buffer.from(fs.readFileSync(cached, 'utf8').trim(), 'hex'))

  const t0 = Date.now()
  const { script: out, report } = sm.optimize(input, { differential: 0 })
  if (!report.verification.symbolic || !report.verification.symbolic.ok) {
    throw new Error(`scriptmin ${String(commit).slice(0, 7)}: no equivalence proof for ${label}`)
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

module.exports = { minimize, enabled, scriptminVersion, packageFor, installHint, provenance }
