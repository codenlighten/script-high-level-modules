'use strict'

// SLH-DSA-SHA2-128s IN BITCOIN SCRIPT, piece by piece and then whole.
//
//   1. the pieces      one XMSS layer at the bottom and at the top, and FORS,
//                      each against src/slhdsa.js on a real signature's values
//   2. the verifier    noble's signatures accepted; a signature over another
//                      message refused; every region of the signature forged
//   3. the coin        a spend signed over its own sighash accepted; a valid
//                      signature over a different transaction refused
//   4. the price       locking and unlocking bytes, opcodes, and how long the
//                      interpreter takes — measured before anything is funded,
//                      because a Groth16 spend taught this repository that a
//                      valid transaction miners will not validate is not a
//                      transaction on chain

const bsv = require('@smartledger/bsv')
const { proveAll } = require('../src/testkit')
const { Asm } = require('../src/asm')
const { policyFlags, countOps } = require('../src/run')
const slh = require('../src/slhdsa')
const mod = require('../src/modules/slhdsa')
const vec = require('../test/vectors/slhdsa-sha2-128s')

const n = (x) => x.toLocaleString('en-US')
const pk = vec.publicKey
const [first, second] = vec.cases

function prove (entries, what) {
  const t0 = Date.now()
  const { failures } = proveAll(entries)
  if (failures.length) { console.log(`\n  ${what} did not hold up\n`); process.exit(1) }
  console.log(`  (${((Date.now() - t0) / 1000).toFixed(1)} s)`)
}

// ── 1. the pieces ───────────────────────────────────────────────────────────
{
  console.log('\n  1. the pieces, against the reference\n')
  const tr = slh.trace(mod.NAME, first.message, first.signature, pk)
  if (!tr.ok) throw new Error('the reference does not verify the vector it is supposed to')
  const layerCase = (L) => ({ name: `layer ${L.layer}, leaf ${L.leaf}`, inputs: { M: L.M, sigX: L.sigX, leaf: BigInt(L.leaf), tree: L.tree } })
  const bottom = tr.layers[0]
  const top = tr.layers[tr.layers.length - 1]
  const wrongLeaf = { ...layerCase(bottom), name: 'layer 0 with the wrong leaf index', refuse: 'the Merkle path is for a different leaf' }
  wrongLeaf.inputs = { ...wrongLeaf.inputs, leaf: BigInt((bottom.leaf + 1) % 512) }
  prove([
    [mod.xmss(pk, { layer: 0, cases: [layerCase(bottom)] }), {}],
    [mod.xmss(pk, { layer: top.layer, cases: [layerCase(top)] }), {}],
    [mod.fors(pk, { cases: [{ name: 'FORS of the first vector', inputs: { md: tr.md, sigF: tr.sigFors, leaf: BigInt(tr.idxLeaf), tree: tr.idxTree } }] }), {}]
  ], 'a piece')
}

// ── 2. the verifier ─────────────────────────────────────────────────────────
{
  console.log('\n  2. the whole verifier\n')
  const v = mod.verifier(pk, {
    cases: [
      { name: first.name, inputs: { msg: first.message, sig: first.signature } },
      { name: second.name, inputs: { msg: second.message, sig: second.signature } },
      { name: 'a valid signature over a different message', refuse: 'the signature is for the other vector', inputs: { msg: first.message, sig: second.signature } }
    ]
  })
  prove([[v, {}]], 'the verifier')
}

// ── 3. the coin ─────────────────────────────────────────────────────────────
let coin
{
  console.log('\n  3. a coin only an SLH-DSA signature over its own spend can move\n')
  coin = mod.spender(pk, {
    sign: vec.sign,
    cases: [
      { name: 'signed over this spend', spend: {} },
      {
        name: 'a valid signature over something else',
        refuse: 'a signature of another message is not a signature of this transaction',
        spend: {},
        inputs: { sig: first.signature }
      }
    ]
  })
  prove([[coin, {}]], 'the coin')
}

// ── 4. the price ────────────────────────────────────────────────────────────
{
  console.log('\n  4. what it costs, and how long a node would spend on it\n')
  const asm = new Asm()
  asm.given(coin.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  coin.emit(asm, {})
  asm.num(1, 'ok')
  const lock = asm.script()

  const SATS = 1000
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.alloc(32, 0x5a), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lock, SATS)
  tx.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(new bsv.PrivateKey().toAddress()), satoshis: SATS - 200 }))
  const w = coin.witnessFor({ tx, lockingScript: lock, satoshis: SATS })
  const { pushData } = require('../src/num')
  const unlock = new bsv.Script().add(pushData(w.preimage)).add(pushData(w.sig))
  tx.inputs[0].setScript(unlock)

  const times = []
  let ok = false
  for (let r = 0; r < 3; r++) {
    const interp = new bsv.Script.Interpreter()
    const t0 = process.hrtime.bigint()
    ok = interp.verify(unlock, lock, tx, 0, policyFlags(), new bsv.crypto.BN(SATS))
    times.push(Number(process.hrtime.bigint() - t0) / 1e6)
    if (!ok) { console.log(`  REFUSED: ${interp.errstr}`); process.exit(1) }
  }
  const best = Math.min(...times)
  console.log(`    locking script     ${n(lock.toBuffer().length).padStart(9)} bytes, ${n(countOps(lock))} opcodes`)
  console.log(`    unlocking script   ${n(unlock.toBuffer().length).padStart(9)} bytes — the preimage carries the locking script, plus a ${n(w.sig.length)}-byte signature`)
  console.log(`    spend transaction  ${n(tx.toBuffer().length).padStart(9)} bytes`)
  console.log(`    interpreter        ${best.toFixed(0)} ms to validate (best of 3: ${times.map((x) => x.toFixed(0)).join(', ')})`)
  console.log(`    for comparison     2,793 ms for the two-input pairing spend that was mined,`)
  console.log(`                       3,924 ms for the three-input Groth16 spend miners refused`)
  console.log(`                       (same interpreter, same machine — tools measured on 2026-09-15)\n`)
}
