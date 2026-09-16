'use strict'

// WILL IT RELAY? — the measurement that would have predicted a refusal.
//
//   node tools/relay-budget.js
//
// A transaction can be valid, and be mined, and still be one a node will not
// pass along. Nodes bound how long they will spend validating work that arrives
// from a peer — `maxnonstdtxvalidationduration`, 1000 ms by default — because a
// transaction that is cheap to send and expensive to check is a denial of
// service otherwise.
//
// This repository learned that the expensive way. A three-input Groth16 spend
// verified locally, funded, broadcast, and then sat unmined for 128 blocks; a
// mining pool's API returned `too-long-validation-time`, and its operator
// explained that their node allows a peer-relayed transaction about a second.
// The spend reached a block only because the pool submitted it to their own node
// directly.
//
// So this times every spend this repository has put on chain, in the same
// interpreter, on whatever machine runs it. The absolute numbers are a property
// of this machine — a node's C++ is far quicker — which is why what it reports
// is a RATIO against the transactions whose fate is known:
//
//     pairing.publish ▸ pairing.consume   relayed and was mined
//     groth16 stage1 ▸ stage2 ▸ stage3    refused by relay, mined by hand
//
// Anything at or above the second is a transaction to expect trouble from.
// Anything near or below the first has relayed in practice.

const fs = require('fs')
const path = require('path')
const os = require('os')
const bsv = require('@smartledger/bsv')
const woc = require('../src/woc')
const onchain = require('../src/onchain')
const { policyFlags } = require('../src/run')

// `--write` records the measurement, which is the part that was missing.
//
// Sizes are generated into results.json and checked, so they cannot drift.
// Timings were not, because they are a property of the machine rather than of
// the code — and the result was three articles quoting three different runs for
// the SAME two transactions, 2,793 ms in one and 2,749 in another. Absent
// measurement does not become honest by being absent; it becomes unciteable.
//
// So one run is recorded here, with the machine that produced it, and anything
// quoting a millisecond quotes this file.
const OUT = path.join(__dirname, '..', 'relay.json')

const n = (x) => x.toLocaleString('en-US')
const raw = new Map()
async function rawTx (txid) {
  if (!raw.has(txid)) raw.set(txid, new bsv.Transaction(await woc.rawTx(txid)))
  return raw.get(txid)
}

/** Every input of a spend, verified and timed, the way a node would have to. */
async function timeSpend (spendId) {
  const spend = await rawTx(spendId)
  let total = 0
  for (let i = 0; i < spend.inputs.length; i++) {
    const input = spend.inputs[i]
    const parent = await rawTx(input.prevTxId.toString('hex'))
    const out = parent.outputs[input.outputIndex]
    const interp = new bsv.Script.Interpreter()
    const t0 = process.hrtime.bigint()
    const ok = interp.verify(input.script, out.script, spend, i, policyFlags(), new bsv.crypto.BN(out.satoshis))
    total += Number(process.hrtime.bigint() - t0) / 1e6
    if (!ok) throw new Error(`${spendId} input ${i}: ${interp.errstr}`)
  }
  return { ms: total, inputs: spend.inputs.length, bytes: spend.toBuffer().length }
}

async function main () {
  const entries = onchain.ledger().deployments
  // Deployments whose spend is worth timing: the ones with scripts big enough
  // for the question to arise at all.
  const interesting = entries.filter((e) => (e.lockBytes || 0) > 40000)
  console.log('\n  every large spend this repository has on chain, timed in bsv.Script.Interpreter\n')
  console.log(`    ${'deployment'.padEnd(38)} ${'inputs'.padStart(6)} ${'tx bytes'.padStart(11)} ${'ms'.padStart(8)}   relative`)

  const rows = []
  for (const e of interesting) {
    let r
    try { r = await timeSpend(e.spend) } catch (err) { console.log(`    ${e.target.padEnd(38)} ${err.message.slice(0, 60)}`); continue }
    rows.push({ name: e.target, key: e.key, ...r })
    // A CHAINED deployment is spent by one transaction per stage, and `spend`
    // names only the last of them. Every link is timed, because the question
    // this tool asks — will a node pass this along? — is asked of each
    // transaction separately. Without them the first link had no recorded
    // time at all, and a table quoting it had to reach for another tool's run.
    if (e.chain) {
      for (const [i, c] of e.chain.entries()) {
        if (c.txid === e.spend) continue
        let lr
        try { lr = await timeSpend(c.txid) } catch (err) { console.log(`    ${c.name.padEnd(38)} ${err.message.slice(0, 60)}`); continue }
        rows.push({ name: `${c.name}, link ${i + 1}`, key: `${e.key}.link${i + 1}`, ...lr })
      }
    }
  }
  const pairing = rows.find((r) => r.key === 'pairingSplit')
  const groth = rows.find((r) => r.key === 'groth16Split')
  for (const r of rows.sort((a, b) => a.ms - b.ms)) {
    const rel = pairing ? (r.ms / pairing.ms).toFixed(2) + '×' : '—'
    const note = groth && r.ms >= groth.ms ? '  ← refused by relay' : (pairing && r.key === 'pairingSplit' ? '  ← relayed, mined' : '')
    console.log(`    ${r.name.padEnd(38)} ${String(r.inputs).padStart(6)} ${n(r.bytes).padStart(11)} ${r.ms.toFixed(0).padStart(8)}   ${rel.padStart(6)}${note}`)
  }

  if (pairing && groth) {
    console.log(`\n  The line is somewhere between ${pairing.ms.toFixed(0)} ms and ${groth.ms.toFixed(0)} ms on this machine:`)
    console.log('  the first relayed and was mined, the second was refused for its validation')
    console.log('  time and reached a block only by direct submission to a pool.')
  }
  console.log('\n  These are this machine\'s numbers, not a node\'s. What transfers is the ratio,')
  console.log('  and the rule it implies: keep a spend at or under the one that relayed.\n')

  if (process.argv.includes('--write')) {
    if (!pairing) throw new Error('no baseline: the spend that relayed is not in the ledger')
    const record = {
      generated: new Date().toISOString().slice(0, 10),
      // The machine is part of the measurement. A figure quoted without it is
      // a number with no units.
      machine: { cpu: (os.cpus()[0] || {}).model?.trim() || 'unknown', arch: process.arch, node: process.version },
      note: 'bsv.Script.Interpreter milliseconds, one idle run on the machine named above. A node\'s C++ is far quicker; what transfers is `relative`.',
      baseline: { key: pairing.key, name: pairing.name, ms: Math.round(pairing.ms), fate: 'relayed and was mined' },
      refused: groth ? { key: groth.key, name: groth.name, ms: Math.round(groth.ms), fate: 'refused by relay for validation time, mined by direct submission' } : null,
      spends: rows.map((r) => ({
        key: r.key,
        name: r.name,
        inputs: r.inputs,
        bytes: r.bytes,
        ms: Math.round(r.ms),
        relative: Number((r.ms / pairing.ms).toFixed(2))
      }))
    }
    fs.writeFileSync(OUT, JSON.stringify(record, null, 2) + '\n')
    console.log(`  relay.json written — ${record.spends.length} spends timed on ${record.machine.cpu}\n`)
  }
}

// `--check` is the other half of `--write`, and needs no network: a recorded
// measurement is only worth recording if the documents quote THAT run. Three
// articles once quoted three different runs for the same two transactions —
// 2,793 ms in one, 2,749 in another — because nothing compared them.
//
// Only figures a document states as a number are listed. Prose that rounds to
// seconds is deliberately not checked here: 3.0 and 3,031 are the same claim,
// and a check that cannot tell them apart would fail for being right.
function checkDocs () {
  if (!fs.existsSync(OUT)) return ['relay.json does not exist — run `npm run relay:write`']
  const rec = JSON.parse(fs.readFileSync(OUT, 'utf8'))
  const num = (x) => x.toLocaleString('en-US')
  const spend = (k) => {
    const s = rec.spends.find((v) => v.key === k)
    if (!s) throw new Error(`relay.json has no spend keyed ${k}`)
    return num(s.ms)
  }
  const link1 = spend('pairingChain.link1')
  const chain = spend('pairingChain')
  const base = num(rec.baseline.ms)
  const refused = num(rec.refused.ms)
  const need = {
    'paper/paper.md': [link1, chain, base, refused],
    'docs/pairing.md': [link1, chain, base, refused, spend('slhdsa'), spend('millerFull')],
    'README.md': [chain, base],
    'articles/medium-part-2.md': [link1, chain],
    'articles/medium-part-3.md': [spend('slhdsa'), base, refused]
  }
  const missing = []
  for (const [file, figures] of Object.entries(need)) {
    const text = fs.readFileSync(path.join(__dirname, '..', file), 'utf8').replace(/\s+/g, ' ')
    for (const f of figures) if (!text.includes(f)) missing.push(`${file} does not quote ${f} ms`)
  }
  return missing
}

if (process.argv.includes('--check')) {
  const missing = checkDocs()
  if (missing.length) {
    console.log('relay: the documents quote a different run than relay.json records —')
    for (const m of missing) console.log(`  ${m}`)
    console.log('  run `npm run relay:write` and move the prose onto it, or restore the figures.')
    process.exit(1)
  }
  const rec = JSON.parse(fs.readFileSync(OUT, 'utf8'))
  console.log(`relay: every quoted timing matches relay.json (${rec.generated}, ${rec.spends.length} spends timed)`)
} else {
  main().catch((e) => { console.error(`\n  ${e.message}\n`); process.exit(1) })
}
