'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { defineModule } = require('../module')
const { Asm } = require('../asm')
const txmod = require('./tx')

// CARRYING A COMPUTATION ACROSS TRANSACTIONS, NOT ACROSS INPUTS.
//
// §8.2 and §8.3 of the paper cut a computation too large for one script across
// the INPUTS of one transaction, bound by a shared output commitment. That works,
// and it ran into the limit nobody had priced: a node bounds how long it will
// spend validating a transaction relayed by a peer, so a spend carrying three
// 400 KB stages was refused by relay and reached a block only because a pool
// accepted it by hand.
//
// The answer is to make the unit of relay the unit of work: ONE STAGE PER
// TRANSACTION, with the state passed along a chain of small coins.
//
//     tx₁   stage 1 coin                        → carrier(∅, s₁)
//     tx₂   stage 2 coin + carrier(∅, s₁)       → carrier(s₁, s₂)
//     tx₃   stage 3 coin + carrier(s₁, s₂)      → carrier(s₂, s₃)
//
// THE CARRIER IS A PAIR, and that is the whole trick. Each carrier holds two
// fields, `prev` and `cur`. It requires its successor to be the same script with
// **its own cur as the successor's prev**, and a `cur` it does not constrain. The
// stage coin in the same transaction requires the successor to be the same script
// with `prev` the state it consumed and `cur` the state it computed. Both hash
// the same output:
//
//     carrier:  output = body ‖ myCur ‖ X          X witnessed, free
//     stage:    output = body ‖ p     ‖ F(p)       p witnessed, free
//
// so p = myCur and X = F(p). The stage cannot read the carrier's script, and does
// not have to: equality of the bytes they each rebuild is what pins them together.
//
// WHAT THIS DOES NOT ESTABLISH, and the single-transaction version did. There,
// hashPrevouts let every stage check that the spend consumed exactly its siblings
// — all outputs of one funding transaction, at fixed indices. Here the carrier
// comes from the PREVIOUS transaction, whose txid nothing could know when the
// stage coins were written, so no stage can insist the carrier beside it is
// genuine. A spender may take a stage coin with a state of their choosing and
// produce a carrier nobody should believe.
//
// What the chain gives a reader is therefore a shape to check rather than one
// transaction's validity: each link is enforced by the two scripts in it, and
// that the coins spent were the intended ones is read off the chain — the funding
// transaction's outputs carry the stage scripts, and each transaction spends the
// stage coin and the carrier its predecessor made. tools/pairing-chain.js checks
// exactly that, and says so rather than leaving it implied.

/** The push opcode a state field of this width needs, minimally. */
function pushPrefix (n) {
  if (n < 0x4c) return Buffer.from([n])
  if (n <= 0xff) return Buffer.from([0x4c, n])
  if (n <= 0xffff) return Buffer.from([0x4d, n & 0xff, (n >> 8) & 0xff])
  throw new Error(`carry: a ${n}-byte state wants a pushdata this does not build`)
}

/** A varint, as a transaction serialises a script's length. */
function varint (n) {
  if (n < 0xfd) return Buffer.from([n])
  if (n <= 0xffff) return Buffer.from([0xfd, n & 0xff, (n >> 8) & 0xff])
  return Buffer.from([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff])
}

/**
 * The coin that carries a pair of states forward.
 *
 * Its own script ends with `prev ‖ cur`, each `stateWidth` bytes, after a
 * top-level OP_RETURN — inert data at a constant offset from the end, the same
 * shape tx.transition uses and the same shape already on chain.
 */
function carry ({ stateWidth = 32, fee = 0, cases } = {}) {
  const W = stateWidth
  return defineModule({
    name: 'tx.carry',
    doc: `carry ${W} bytes on: the spend must recreate this coin with my cur as its prev, and a cur another input pins`,
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      { name: 'next', kind: 'bytes', width: W, witness: true }
    ],
    outputs: [],
    contextual: true,
    witnessFor: (ctx) => carryWitness(ctx, W, fee),
    hint: () => ({}),
    model: () => ({}),
    emit: (asm, params) => {
      const f = params.fee === undefined ? fee : params.fee
      txmod.emitAuthenticate(asm)
      txmod.emitScriptCode(asm, '_code')

      // the script's own bytes: body ‖ prev ‖ cur, the last two fixed width
      asm.roll('_code')
      asm.op('OP_SIZE', 0, [{ name: '_cl', kind: 'num' }])
      asm.num(2 * W, '_2w'); asm.sub('_cut')
      asm.split('_body', '_pair')
      asm.roll('_pair'); asm.splitAt(W, '_prev', '_cur')

      // the successor: the same body, my cur as its prev, and the witnessed next
      asm.roll('_body'); asm.roll('_cur'); asm.cat('_s1')
      asm.roll('next'); asm.cat('_succ')

      // the one output it may pay: what came in, less the fee
      txmod.emitValueIn(asm, '_v')
      if (f) { asm.num(f, '_fee'); asm.sub('_vout') } else { asm.rename('_vout') }
      asm.num2bin(8, '_voutLE')
      asm.roll('_succ'); asm.cat('_txout')
      asm.hash256('_h')
      txmod.emitCommitted(asm, '_committed')
      asm.equalVerify()

      asm.discard('_prev'); asm.discard('preimage')
    },
    attacks: (honest, params, name) => {
      if (name === 'next') {
        const v = Buffer.from(honest.next)
        const other = Buffer.from(v); other[0] ^= 0x01
        return [{ label: 'a successor the spend does not pay to', value: other }]
      }
      return txmod.preimageAttacks(honest, params, name)
    },
    tail: (params) => Buffer.concat([
      Buffer.from([0x6a]),
      pushPrefix(2 * W),
      params.state || Buffer.alloc(2 * W)
    ]),
    cases: cases || [
      {
        name: 'a state carried on',
        spend: { state: Buffer.concat([Buffer.alloc(W, 0x11), Buffer.alloc(W, 0x22)]), next: Buffer.alloc(W, 0x33) },
        params: { state: Buffer.concat([Buffer.alloc(W, 0x11), Buffer.alloc(W, 0x22)]) }
      },
      {
        name: 'the first link, from nothing',
        spend: { state: Buffer.concat([Buffer.alloc(W), Buffer.alloc(W, 0xab)]), next: Buffer.alloc(W, 0xcd) },
        params: { state: Buffer.concat([Buffer.alloc(W), Buffer.alloc(W, 0xab)]) }
      }
    ],
    notes: [
      'enforces only that its cur becomes the successor\'s prev — what the successor\'s cur may be is the other input\'s business',
      'cannot check that the coin beside it is the stage it expects: an outpoint does not name a script'
    ]
  })
}

/** The spender's side: build the successor, put it on the transaction, grind. */
function carryWitness ({ tx, lockingScript, satoshis, spend = {}, inputIndex = 0 }, W, fee) {
  const code = lockingScript.toBuffer()
  const cur = code.subarray(code.length - W)
  const next = spend.next || Buffer.alloc(W)
  const successor = bsv.Script.fromBuffer(Buffer.concat([code.subarray(0, code.length - 2 * W), cur, next]))

  tx.outputs.length = 0
  tx.addOutput(new bsv.Transaction.Output({ script: successor, satoshis: satoshis - fee }))
  tx._outputAmount = undefined

  const g = PushTx.grind(tx, inputIndex, lockingScript, satoshis, { field: 'sequence' })
  return { preimage: g.preimage, next }
}

/**
 * A carrier coin's locking script, for a given pair of states.
 *
 * The body — everything before the two state fields — is a constant of the
 * width and the fee, which is what lets a stage coin rebuild the carrier's bytes
 * without ever seeing the carrier.
 */
function carrierScript (W, { prev, cur }, { fee = 0 } = {}) {
  const m = carry({ stateWidth: W, fee })
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, {})
  asm.num(1, 'true')
  const state = Buffer.concat([prev || Buffer.alloc(W), cur || Buffer.alloc(W)])
  return new bsv.Script(Buffer.concat([asm.script().toBuffer(), m.tail({ state })]))
}

/** Everything of a carrier output that is fixed: the amount, the length, the body. */
function carrierPrefix (W, { fee = 0, satoshis = 1 } = {}) {
  const full = carrierScript(W, {}, { fee }).toBuffer()
  const body = full.subarray(0, full.length - 2 * W)
  const amount = Buffer.alloc(8)
  amount.writeBigUInt64LE(BigInt(satoshis))
  return Buffer.concat([amount, varint(full.length), body])
}

/**
 * The stage's side of the link: this spend's only output is the carrier coin
 * carrying exactly these two fields.
 *
 * The carrier proves `prev` is what it was holding; this proves `cur` is what
 * the stage computed from it. Neither reads the other.
 */
function commitCarry (W, { fee = 0, satoshis = 1, cases } = {}) {
  const prefix = carrierPrefix(W, { fee, satoshis })
  return defineModule({
    name: 'tx.commitCarry',
    doc: `the spend's only output must be the carrier coin carrying these two ${W}-byte fields`,
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      { name: 'prev', kind: 'bytes', width: W },
      { name: 'cur', kind: 'bytes', width: W }
    ],
    outputs: [],
    contextual: true,
    witnessFor: ({ tx, lockingScript, satoshis: value, spend = {}, inputIndex = 0 }) => {
      tx.outputs.length = 0
      tx.addOutput(new bsv.Transaction.Output({
        script: carrierScript(W, { prev: spend.prev, cur: spend.cur }, { fee }),
        satoshis
      }))
      tx._outputAmount = undefined
      const g = PushTx.grind(tx, inputIndex, lockingScript, value, { field: 'sequence' })
      return { preimage: g.preimage }
    },
    hint: () => ({}),
    model: () => ({}),
    emit: (asm) => {
      txmod.emitAuthenticate(asm)
      asm.data(prefix, '_pfx')
      asm.roll('prev'); asm.cat('_o1')
      asm.roll('cur'); asm.cat('_txout')
      asm.hash256('_h')
      txmod.emitCommitted(asm, '_committed')
      asm.equalVerify()
      asm.discard('preimage')
    },
    attacks: (honest, params, name) => txmod.preimageAttacks(honest, params, name),
    cases: cases || [
      {
        name: 'the carrier this stage must pay',
        spend: { prev: Buffer.alloc(W, 0x11), cur: Buffer.alloc(W, 0x22) },
        inputs: { prev: Buffer.alloc(W, 0x11), cur: Buffer.alloc(W, 0x22) }
      },
      {
        name: 'a cur the spend does not pay',
        refuse: 'the output carries a different state',
        spend: { prev: Buffer.alloc(W, 0x11), cur: Buffer.alloc(W, 0x22) },
        inputs: { prev: Buffer.alloc(W, 0x11), cur: Buffer.alloc(W, 0x33) }
      }
    ],
    notes: [
      'the carrier beside it pins prev; this pins cur; neither can read the other\'s script',
      'the output set must be exactly the carrier, so the stage coin\'s whole value becomes fee'
    ]
  })
}

module.exports = { carry, commitCarry, carrierScript, carrierPrefix, carryWitness, pushPrefix, varint }
