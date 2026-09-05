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
const locktime = defineModule({
  name: 'tx.locktime',
  doc: 'prove the preimage is this spend, and read its nLockTime',
  inputs: [{ name: 'preimage', kind: 'bytes', witness: true }],
  outputs: [{ name: 'locktime', kind: 'num' }],
  contextual: true,
  // The spender's side: grind the sequence until the in-script signature is
  // canonical, then push the resulting preimage.
  witnessFor: ({ tx, lockingScript, satoshis, spend = {} }) => {
    // The grind has to vary something, and it must not be something the spend
    // has pinned. A covenant that reads nLockTime grinds the sequence; a case
    // that pins BOTH cannot be ground at all and says so rather than quietly
    // testing a different transaction.
    const pinned = (f) => spend[f] !== undefined
    const field = !pinned('sequence') ? 'sequence' : !pinned('nLockTime') ? 'nLockTime' : null
    const g = field
      ? PushTx.grind(tx, 0, lockingScript, satoshis, { field })
      : grindValue(tx, 0, lockingScript, satoshis)
    return { preimage: g.preimage }
  },
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
  attacks: (honest, params, name) => {
    const v = Buffer.from(honest[name])
    const flipped = Buffer.from(v); flipped[0] ^= 0x01
    const late = Buffer.from(v); late[v.length - 8] ^= 0x01   // the locktime field itself
    return [
      { label: 'a byte of the preimage changed', value: flipped },
      { label: 'the locktime rewritten', value: late },
      { label: 'the preimage truncated', value: v.subarray(0, v.length - 1) }
    ]
  },
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

module.exports = { locktime, right, left, grindValue, SIGHASH_ALL_FORKID, FINAL, PushTx }
