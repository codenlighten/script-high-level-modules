'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { defineModule } = require('../module')

// READING THE SPENDING TRANSACTION.
//
// Every module before this one computes over values the spender handed it.
// None of them can say anything about the transaction doing the spending —
// which is why `totp.verify` carries the note that its `time` is an input, and
// that a spender free to choose it will choose whatever makes their code valid.
//
// This is the module that closes that. OP_PUSH_TX is the standard construction:
// the locking script builds an ECDSA signature in-script out of the preimage the
// spender pushed, and OP_CHECKSIG only accepts it if the message it derives
// internally — the genuine BIP-143 sighash of THIS spend — equals
// HASH256(preimage). A passing check proves the pushed bytes are this
// transaction, and the script can then read its own fields.
//
// WHAT nLOCKTIME ACTUALLY PROVES, WHICH IS LESS THAN IT LOOKS.
//
// nLockTime is written by the spender. Reading it out of an authenticated
// preimage proves only what the spender claimed. It becomes a statement about
// real time solely because of a consensus rule elsewhere: a transaction whose
// input sequence is non-final cannot be *mined* before its nLockTime. So:
//
//   the covenant enforces  →  this transaction cannot be mined before T
//   it cannot enforce      →  T is the present time
//
// A spender may always claim a T further in the future than now, and wait. The
// module therefore refuses a final sequence, because without that check the
// locktime is not even a lower bound — it is a number the spender wrote down.
// OP_CHECKLOCKTIMEVERIFY does not help: it is a no-op after Genesis.
//
// THE GRIND. The in-script signature is only a canonical, low-S DER for about a
// quarter of preimages, so the spender varies a malleable field until it is. A
// covenant that pins nLockTime cannot grind on nLockTime, so the grind sweeps
// the sequence downward from 0xfffffffe — which stays non-final, and so keeps
// the locktime rule in force. That is `field: 'sequence'` below, and it is the
// reason the two constraints do not collide.

const SIGHASH_ALL_FORKID = 0x41
const FINAL = 0xffffffff

/**
 * Grind on the output value, for a spend that has pinned both nLockTime and the
 * sequence.
 *
 * The in-script signature is only canonical for some preimages, so SOMETHING
 * about the transaction has to vary. The library grinds nLockTime or the
 * sequence; a covenant that pins both leaves neither, and a real spender would
 * then vary what they always can — the satoshis going to their own change. This
 * does the same, a satoshi at a time, and it is what lets a case pin a FINAL
 * sequence and still hold a genuine preimage to be refused for the right reason.
 */
function grindValue (tx, inputIndex, lockingScript, satoshis, maxTries = 5000) {
  const helpers = require('@smartledger/bsv/lib/covenant/helpers')
  const out = tx.outputs[tx.outputs.length - 1]
  const base = out.satoshis
  for (let i = 0; i < maxTries; i++) {
    if (base - i < 1) break
    out.satoshis = base - i
    const preimage = helpers.rawPreimage(tx, inputIndex, lockingScript, satoshis, SIGHASH_ALL_FORKID)
    if (PushTx.sFromPreimage(preimage)) return { preimage, tries: i + 1, field: 'value', nonce: i }
  }
  throw new Error('tx: the output-value grind found no canonical preimage')
}

/** The last n bytes of the string on top. OP_RIGHT consumes the string and n. */
function right (asm, n, out) {
  asm.num(n, '_rn')
  return asm.op('OP_RIGHT', 2, [{ name: out, kind: 'bytes', width: n }])
}

/** The first n bytes of the string on top. */
function left (asm, n, out) {
  asm.num(n, '_ln')
  return asm.op('OP_LEFT', 2, [{ name: out, kind: 'bytes', width: n }])
}

/**
 * Authenticate the preimage and read nLockTime out of it.
 *
 * Authentication and extraction are ONE module on purpose. Split in two, a
 * caller could hand an unauthenticated preimage to the extractor and read a
 * field of a transaction that does not exist. There is no way to obtain a field
 * here without the proof that came with it.
 */
// The two fixed destinations the output cases pay to. Throwaway, and fixed so a
// case reproduces byte for byte.
const PAY_A = bsv.PrivateKey.fromBuffer(Buffer.from('11'.repeat(32), 'hex')).toAddress()
const PAY_B = bsv.PrivateKey.fromBuffer(Buffer.from('22'.repeat(32), 'hex')).toAddress()

/**
 * The spender's side of any preimage module: grind until the in-script signature
 * is canonical, then push the result.
 *
 * The grind has to vary something, and it must not be something the spend has
 * pinned. A covenant reading nLockTime grinds the sequence; one pinning both
 * grinds the output value, which is what a real spender would vary — their own
 * change. A case that pins all three is telling the truth about a transaction
 * that cannot be built.
 */
function locktimeWitnessFor ({ tx, lockingScript, satoshis, spend = {} }) {
  const pinned = (f) => spend[f] !== undefined
  const field = !pinned('sequence') ? 'sequence' : !pinned('nLockTime') ? 'nLockTime' : null
  const g = field
    ? PushTx.grind(tx, 0, lockingScript, satoshis, { field })
    : grindValue(tx, 0, lockingScript, satoshis)
  return { preimage: g.preimage }
}

/** Forgeries of a preimage: change a byte, change the field, cut it short. */
function preimageAttacks (honest, params, name) {
  const v = Buffer.from(honest[name])
  const flipped = Buffer.from(v); flipped[0] ^= 0x01
  const field = Buffer.from(v); field[v.length - 8] ^= 0x01
  const outs = Buffer.from(v); outs[v.length - 40] ^= 0x01
  return [
    { label: 'a byte of the preimage changed', value: flipped },
    { label: 'the locktime field rewritten', value: field },
    { label: 'the output commitment rewritten', value: outs },
    { label: 'the preimage truncated', value: v.subarray(0, v.length - 1) }
  ]
}

const locktime = defineModule({
  name: 'tx.locktime',
  doc: 'prove the preimage is this spend, and read its nLockTime',
  inputs: [{ name: 'preimage', kind: 'bytes', witness: true }],
  outputs: [{ name: 'locktime', kind: 'num' }],
  contextual: true,
  // The spender's side: grind the sequence until the in-script signature is
  // canonical, then push the resulting preimage.
  witnessFor: locktimeWitnessFor,
  hint: () => ({}),
  model: ({ preimage }) => ({ locktime: BigInt(preimage.readUInt32LE(preimage.length - 8)) }),
  emit: (asm) => {
    // 1. the preimage is this transaction
    asm.pick('preimage', '_pi')
    asm.clause((s) => PushTx.pushTxCore(s), 1, [{ name: '_ok', kind: 'num' }])
    asm.verify()

    // 2. the field offsets below are the SIGHASH_ALL|FORKID layout, and the
    //    core pins that flag implicitly; saying so makes it fail fast instead
    //    of reading the wrong bytes if the core is ever re-parameterised
    asm.pick('preimage', '_pf'); right(asm, 4, '_flag')
    asm.data(Buffer.from([SIGHASH_ALL_FORKID, 0, 0, 0]), '_want'); asm.equalVerify()

    // 3. a final sequence means consensus ignores nLockTime entirely
    asm.pick('preimage', '_ps'); right(asm, 44, '_tail44'); left(asm, 4, '_seq')
    asm.data(Buffer.from([0xff, 0xff, 0xff, 0xff]), '_final')
    asm.equal('_isFinal'); asm.op('OP_NOT', 1, [{ name: '_notFinal', kind: 'num' }]); asm.verify()

    // 4. nLockTime: four little-endian bytes, eight from the end
    asm.roll('preimage'); right(asm, 8, '_tail8'); left(asm, 4, '_lt')
    asm.data(Buffer.from([0]), '_sign'); asm.cat('_ltp')     // keep it positive past 2038
    asm.bin2num('locktime')
  },
  attacks: preimageAttacks,
  cases: [
    // The locktime is pinned and the sequence is left free for the grind.
    { name: 'a locktime in the past', spend: { nLockTime: 1600000000 } },
    { name: 'a locktime far in the future', spend: { nLockTime: 2000000000 } },
    { name: 'a block height rather than a time', spend: { nLockTime: 800000 } },
    // Here the SEQUENCE is what the case pins, so the grind moves the locktime.
    {
      name: 'a final sequence',
      refuse: 'consensus ignores nLockTime when the sequence is final, so the value proves nothing',
      spend: { sequence: 0xffffffff }
    }
  ],
  notes: [
    'proves the transaction cannot be MINED before the locktime — not that the locktime is now',
    'refuses a final sequence, without which the locktime is a number the spender wrote down',
    'the spender grinds the SEQUENCE, not the locktime, so the two constraints do not collide'
  ]
})

/**
 * Authenticate the preimage and read the commitment to the spend's OUTPUTS.
 *
 * This is the primitive that turns a verifier into a contract. Every module
 * before it answers "may this coin move?"; hashOutputs is what lets a script
 * also say WHERE. The BIP-143 preimage commits to HASH256 of the whole
 * serialised output set, so pinning that one 32-byte field pins every
 * destination and every amount at once — and pins them as a SET, so an extra
 * output nobody asked for is refused along with a changed one.
 *
 * Authentication and extraction are one module for the same reason as in
 * `locktime`: there is no way to obtain the field without the proof that came
 * with it.
 *
 * It reads the SIGHASH_ALL layout, and says so. Under SIGHASH_SINGLE the field
 * covers one output and under SIGHASH_NONE it covers nothing, so a covenant that
 * pinned it while the spender chose the flag would be pinning something else
 * entirely. The PUSH_TX core fixes the flag implicitly; the check makes it fail
 * loudly rather than quietly reading the wrong bytes.
 */
const hashOutputs = defineModule({
  name: 'tx.hashOutputs',
  doc: 'prove the preimage is this spend, and read what it commits its outputs to',
  inputs: [{ name: 'preimage', kind: 'bytes', witness: true }],
  outputs: [{ name: 'hashOutputs', kind: 'bytes', width: 32 }],
  contextual: true,
  witnessFor: locktimeWitnessFor,
  hint: () => ({}),
  model: ({ preimage }) => ({ hashOutputs: Buffer.from(preimage.subarray(preimage.length - 40, preimage.length - 8)) }),
  emit: (asm) => {
    asm.pick('preimage', '_pi')
    asm.clause((s2) => PushTx.pushTxCore(s2), 1, [{ name: '_ok', kind: 'num' }])
    asm.verify()

    asm.pick('preimage', '_pf'); right(asm, 4, '_flag')
    asm.data(Buffer.from([SIGHASH_ALL_FORKID, 0, 0, 0]), '_want'); asm.equalVerify()

    asm.roll('preimage'); right(asm, 40, '_tail40'); left(asm, 32, 'hashOutputs')
  },
  attacks: preimageAttacks,
  cases: [
    // Spelled out rather than left to the default: a module that reads the
    // transaction's own output commitment must be tested against outputs the
    // case chose, or the case is describing something it cannot see.
    {
      name: 'one output',
      spend: { outputs: [new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(PAY_A), satoshis: 70 })] }
    },
    {
      name: 'two outputs',
      spend: {
        outputs: [
          new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(PAY_A), satoshis: 40 }),
          new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(PAY_B), satoshis: 30 })
        ]
      }
    }
  ],
  notes: ['pins the output SET: an extra output is refused along with a changed one']
})

/**
 * The predicate form: the spend must pay exactly this.
 *
 * `outputs` is the whole set, in order. Anything else — a different amount, a
 * different destination, an extra output, a missing one — changes the hash and
 * the spend is refused.
 */
function requireOutputs (outputs, { cases } = {}) {
  const expected = PushTx.hashOutputs(outputs)
  return defineModule({
    name: 'tx.requireOutputs',
    doc: 'the spend may only pay exactly this set of outputs',
    inputs: [{ name: 'preimage', kind: 'bytes', witness: true }],
    outputs: [],
    contextual: true,
    witnessFor: locktimeWitnessFor,
    hint: () => ({}),
    model: () => ({}),
    emit: (asm) => {
      hashOutputs.emit(asm, {})
      asm.data(expected, '_want'); asm.equalVerify()
    },
    attacks: preimageAttacks,
    cases: cases || [
      { name: 'paying exactly what it must', spend: { outputs: outputs.map(cloneOutput) } },
      {
        name: 'one satoshi less to the same address',
        refuse: 'the amount is inside the commitment',
        spend: { outputs: outputs.map((o, i) => cloneOutput(o, i === 0 ? -1 : 0)) }
      },
      {
        name: 'an extra output appended',
        refuse: 'the commitment is over the whole set, not a subset',
        spend: {
          outputs: [...outputs.map((o) => cloneOutput(o)),
            new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(PAY_B), satoshis: 1 })]
        }
      }
    ],
    notes: ['pins destinations and amounts together, as a set']
  })
}

const cloneOutput = (o, delta = 0) =>
  new bsv.Transaction.Output({ script: o.script, satoshis: o.satoshis + delta })

// ── A COIN THAT REWRITES ITSELF ─────────────────────────────────────────────
//
// Everything else here is a stateless predicate: it verifies, and the coin
// moves. This is the one that carries something forward.
//
// The BIP-143 preimage contains the locking script being spent — scriptCode,
// which starts at offset 104 and is followed by exactly 52 bytes of tail. So a
// script can read ITSELF out of its own preimage, replace a field, and require
// the spend to pay an output carrying the result. The coin becomes its own
// successor, one field different.
//
// THE STATE GOES AT THE END, AFTER OP_RETURN, and that placement is doing real
// work. Post-Genesis a top-level OP_RETURN ends evaluation with the top stack
// item deciding, so trailing bytes are inert data rather than code. Being at the
// end makes the state a CONSTANT offset from the end of the preimage — where the
// front of the script is a varint whose own length depends on how long the
// script is, which is not known while the script is being written. Fixed offsets
// from the back; nothing circular.
//
// And scriptCode carries its own length prefix, which is exactly what a
// serialised output needs in front of its script. Swapping a fixed-width field
// does not change the length, so the prefix is reused untouched and the varint
// never has to be computed at all.
//
// WHAT IT DOES NOT DECIDE. This enforces the mechanics of succession — that the
// successor is this same script with one field replaced, carrying the value that
// came in less a fee. Whether the new state is a LEGAL successor of the old one
// is a separate question, for a separate module: `tx.transition` hands the
// current state out as its output, and whatever consumes it says what may follow
// what. compose.pipe() is how the two are joined.

// The pieces every covenant that reads its own script needs, factored out
// because there are now two of them and there will be more. Each leaves exactly
// what it names on the stack.

/** Prove the preimage is this spend, under the flag the offsets assume. */
function emitAuthenticate (asm) {
  asm.pick('preimage', '_pi')
  asm.clause((sc) => PushTx.pushTxCore(sc), 1, [{ name: '_ok', kind: 'num' }])
  asm.verify()
  asm.pick('preimage', '_pf'); right(asm, 4, '_flag')
  asm.data(Buffer.from([SIGHASH_ALL_FORKID, 0, 0, 0]), '_wantFlag'); asm.equalVerify()
}

/** This script's own bytes, length prefix and all: preimage[104 : len−52]. */
function emitScriptCode (asm, out) {
  asm.pick('preimage', '_p1'); asm.splitAt(104, '_pre', '_rest'); asm.nip()
  asm.op('OP_SIZE', 0, [{ name: '_rl', kind: 'num' }])
  asm.num(52, '_52'); asm.sub('_cut')
  asm.split(out, '_tail'); asm.drop()
}

/** Split the trailing state off the script's bytes. */
function emitSplitState (asm, code, W, bodyOut, stateOut) {
  asm.roll(code)
  asm.op('OP_SIZE', 0, [{ name: '_sl', kind: 'num' }])
  asm.num(W, '_w'); asm.sub('_cut2')
  asm.split(bodyOut, stateOut)
}

/** The satoshis this input carries, as a number. */
function emitValueIn (asm, out) {
  asm.pick('preimage', '_pv'); right(asm, 52, '_t52'); left(asm, 8, '_vin')
  asm.data(Buffer.from([0]), '_vz'); asm.cat('_vinp'); asm.bin2num(out)
}

/** What the transaction committed to paying. */
function emitCommitted (asm, out) {
  asm.pick('preimage', '_pc'); right(asm, 40, '_t40'); left(asm, 32, out)
}

/** A serialised P2PKH output: amount(8 LE) ‖ 0x19 ‖ the standard 25 bytes. */
function emitP2PKHOut (asm, amountName, pkhName, out) {
  asm.roll(amountName); asm.num2bin(8, '_amtLE')
  asm.data(Buffer.from('1976a914', 'hex'), '_pfx'); asm.cat('_o1')
  asm.roll(pkhName); asm.cat('_o2')
  asm.data(Buffer.from('88ac', 'hex'), '_sfx'); asm.cat(out)
}

/**
 * Read this script's own state, and require the spend to recreate the script
 * with `next` in its place.
 *
 * @param stateWidth bytes of state, fixed — the width is what makes the offsets
 *                   constant and the length prefix reusable
 * @param fee        satoshis the successor gives up to the miner
 */
function transition ({ stateWidth = 8, fee = 200, cases } = {}) {
  const W = stateWidth
  return defineModule({
    name: 'tx.transition',
    doc: `read ${W} bytes of state from this script and require the spend to recreate it`,
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      { name: 'next', kind: 'bytes', width: W, witness: true }
    ],
    // Both the current state and the successor come out, because a rule that
    // decides which successors are legal needs to see them together — and this
    // module deliberately does not decide that.
    outputs: [{ name: 'state', kind: 'bytes', width: W }, { name: 'next', kind: 'bytes', width: W }],
    contextual: true,
    witnessFor: (ctx) => recreateWitness(ctx, W, fee),
    hint: () => ({}),
    model: ({ preimage, next }) => ({
      state: Buffer.from(preimage.subarray(preimage.length - 52 - W, preimage.length - 52)),
      next: Buffer.from(next)
    }),
    emit: (asm, params) => {
      const f = params.fee === undefined ? fee : params.fee

      // 1. the preimage is this transaction
      asm.pick('preimage', '_pi')
      asm.clause((sc) => PushTx.pushTxCore(sc), 1, [{ name: '_ok', kind: 'num' }])
      asm.verify()
      asm.pick('preimage', '_pf'); right(asm, 4, '_flag')
      asm.data(Buffer.from([SIGHASH_ALL_FORKID, 0, 0, 0]), '_want'); asm.equalVerify()

      // 2. the script's own bytes: everything from 104 to 52 from the end
      asm.pick('preimage', '_p1'); asm.splitAt(104, '_pre', '_rest'); asm.nip()
      asm.op('OP_SIZE', 0, [{ name: '_rl', kind: 'num' }])
      asm.num(52, '_52'); asm.sub('_cut')
      asm.split('_scriptCode', '_tail'); asm.drop()

      // 3. the state is its last W bytes; the successor is the rest plus `next`
      asm.op('OP_SIZE', 0, [{ name: '_sl', kind: 'num' }])
      asm.num(W, '_w'); asm.sub('_cut2')
      asm.split('_body', 'state')
      asm.pick('_body', '_b1'); asm.pick('next', '_n1'); asm.cat('_nextCode')

      // 4. the output it must pay: value in, less the fee, then the new script
      asm.pick('preimage', '_p2'); right(asm, 52, '_t52'); left(asm, 8, '_vin')
      asm.data(Buffer.from([0]), '_z'); asm.cat('_vinp'); asm.bin2num('_v')
      asm.num(f, '_fee'); asm.sub('_vout')
      asm.num2bin(8, '_voutLE')
      asm.roll('_nextCode'); asm.cat('_txout')
      asm.hash256('_h')

      // 5. against what the transaction committed to paying
      asm.pick('preimage', '_p3'); right(asm, 40, '_t40'); left(asm, 32, '_committed')
      asm.equalVerify()

      asm.discard('_body'); asm.discard('preimage')
      asm.roll('state'); asm.roll('next')
    },
    attacks: (honest, params, name) => {
      if (name === 'next') {
        const v = Buffer.from(honest.next)
        const other = Buffer.from(v); other[0] ^= 0x01
        return [{ label: 'a successor the spend does not pay to', value: other }]
      }
      return preimageAttacks(honest, params, name)
    },
    // The script this covenant lives in ends with its state, after a top-level
    // OP_RETURN. The harness builds that shape rather than a convenient one,
    // because the covenant reads the script it is actually deployed in.
    tail: (params) => Buffer.concat([
      Buffer.from([0x6a]),                                   // OP_RETURN
      Buffer.from([W]),                                      // a W-byte push
      params.state || Buffer.alloc(W)
    ]),
    cases: cases || [
      { name: 'a counter stepping on', spend: { state: leBytes(41n, W), next: leBytes(42n, W) }, params: { state: leBytes(41n, W) } },
      { name: 'the state left unchanged', spend: { state: leBytes(7n, W), next: leBytes(7n, W) }, params: { state: leBytes(7n, W) } },
      { name: 'a state of all ones', spend: { state: Buffer.alloc(W, 0xff), next: leBytes(1n, W) }, params: { state: Buffer.alloc(W, 0xff) } }
    ],
    notes: [
      'enforces the mechanics of succession, not which successor is legal — pipe the state into a rule',
      'the state is fixed width: that is what keeps the offsets constant and the length prefix reusable'
    ]
  })
}

/**
 * The spender's side: build the output the covenant will demand, put it on the
 * transaction, and only then grind — because the preimage commits to it.
 */
const leBytes = (v, w) => { const b = Buffer.alloc(w); b.writeBigUInt64LE(BigInt(v)); return b }

function recreateWitness ({ tx, lockingScript, satoshis, spend = {} }, W, fee) {
  const code = lockingScript.toBuffer()
  const next = spend.next || Buffer.alloc(W)
  const successor = bsv.Script.fromBuffer(Buffer.concat([code.subarray(0, code.length - W), next]))

  tx.outputs.length = 0
  tx.addOutput(new bsv.Transaction.Output({ script: successor, satoshis: satoshis - fee }))
  tx._outputAmount = undefined

  const g = PushTx.grind(tx, 0, lockingScript, satoshis, { field: 'sequence' })
  return { preimage: g.preimage, next }
}

/**
 * Succession that also PAYS.
 *
 * `transition` requires the output set to be exactly the successor, which makes
 * a coin that can carry state and cannot spend money — and a budget that cannot
 * pay anything out is not a budget. This one commits to two outputs: the
 * successor, and a P2PKH payment whose destination and amount it hands to
 * whatever rule sits above it.
 *
 * The value arithmetic is the covenant's, not the spender's: the successor
 * carries what came in, less the payment, less the fee. Nothing is left over to
 * be quietly redirected, because the commitment covers the whole output set.
 */
function transitionPaying ({ stateWidth = 8, fee = 300, cases } = {}) {
  const W = stateWidth
  return defineModule({
    name: 'tx.transitionPaying',
    doc: `recreate this script with ${W} bytes of new state, and pay one output besides`,
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      { name: 'next', kind: 'bytes', width: W, witness: true },
      { name: 'amount', witness: true },
      { name: 'payee', kind: 'bytes', width: 20, witness: true }
    ],
    outputs: [
      { name: 'state', kind: 'bytes', width: W },
      { name: 'next', kind: 'bytes', width: W },
      { name: 'amount', kind: 'num' }
    ],
    contextual: true,
    witnessFor: (ctx) => payingWitness(ctx, W, fee),
    hint: () => ({}),
    model: ({ preimage, next, amount }) => ({
      state: Buffer.from(preimage.subarray(preimage.length - 52 - W, preimage.length - 52)),
      next: Buffer.from(next),
      amount: BigInt(amount)
    }),
    emit: (asm, params) => {
      const f = params.fee === undefined ? fee : params.fee
      emitAuthenticate(asm)
      emitScriptCode(asm, '_scriptCode')
      emitSplitState(asm, '_scriptCode', W, '_body', 'state')

      // the successor: this script with the new state, carrying what is left
      asm.pick('_body', '_b1'); asm.pick('next', '_n1'); asm.cat('_nextCode')
      emitValueIn(asm, '_v')
      asm.num(f, '_fee'); asm.sub('_afterFee')
      asm.pick('amount', '_a1'); asm.sub('_vout')
      asm.num2bin(8, '_voutLE')
      asm.roll('_nextCode'); asm.cat('_txout1')

      // the payment
      asm.pick('amount', '_a2'); asm.pick('payee', '_pk')
      emitP2PKHOut(asm, '_a2', '_pk', '_txout2')

      asm.roll('_txout1'); asm.roll('_txout2'); asm.cat('_outs')
      asm.hash256('_h')
      emitCommitted(asm, '_committed')
      asm.equalVerify()

      asm.discard('_body'); asm.discard('preimage'); asm.discard('payee')
      asm.roll('state'); asm.roll('next'); asm.roll('amount')
    },
    attacks: (honest, params, name) => {
      if (name === 'amount') {
        return [
          { label: 'paying one satoshi more than the spend does', value: BigInt(honest.amount) + 1n },
          { label: 'paying nothing', value: 0n }
        ]
      }
      if (name === 'payee') {
        const v = Buffer.from(honest.payee); v[0] ^= 0x01
        return [{ label: 'a payee the spend does not pay', value: v }]
      }
      if (name === 'next') {
        const v = Buffer.from(honest.next); v[0] ^= 0x01
        return [{ label: 'a successor the spend does not pay to', value: v }]
      }
      return preimageAttacks(honest, params, name)
    },
    tail: (params) => Buffer.concat([Buffer.from([0x6a]), Buffer.from([W]), params.state || Buffer.alloc(W)]),
    cases: cases || (() => {
      const payee = Buffer.alloc(20, 0x5a)
      const other = Buffer.alloc(20, 0x77)
      return [
        {
          name: 'paying 500 and stepping the state',
          spend: { state: leBytes(1000n, W), next: leBytes(500n, W), amount: 500n, payee },
          params: { state: leBytes(1000n, W) }
        },
        {
          name: 'paying one satoshi',
          spend: { state: leBytes(9n, W), next: leBytes(8n, W), amount: 1n, payee: other },
          params: { state: leBytes(9n, W) }
        }
      ]
    })(),
    notes: [
      'commits to BOTH outputs, so nothing is left over to be redirected',
      'the successor carries what came in less the payment less the fee — the covenant does that arithmetic, not the spender'
    ]
  })
}

/** The spender's side: build both outputs, then grind, because it commits to them. */
function payingWitness ({ tx, lockingScript, satoshis, spend = {} }, W, fee) {
  const code = lockingScript.toBuffer()
  const next = spend.next || Buffer.alloc(W)
  const amount = spend.amount === undefined ? 1n : BigInt(spend.amount)
  const payee = spend.payee || Buffer.alloc(20, 0xab)
  const successor = bsv.Script.fromBuffer(Buffer.concat([code.subarray(0, code.length - W), next]))

  tx.outputs.length = 0
  tx.addOutput(new bsv.Transaction.Output({ script: successor, satoshis: satoshis - fee - Number(amount) }))
  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.fromBuffer(Buffer.concat([Buffer.from('76a914', 'hex'), payee, Buffer.from('88ac', 'hex')])),
    satoshis: Number(amount)
  }))
  tx._outputAmount = undefined

  const g = PushTx.grind(tx, 0, lockingScript, satoshis, { field: 'sequence' })
  return { preimage: g.preimage, next, amount, payee }
}

module.exports = { locktime, hashOutputs, requireOutputs, transition, transitionPaying, recreateWitness, payingWitness, leBytes, right, left, grindValue, SIGHASH_ALL_FORKID, FINAL, PushTx }
