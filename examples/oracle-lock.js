'use strict'

// AN ORACLE THAT SIGNS WITH THE KEY IT ALREADY HAS.
//
// This is what ecdsa.verify is for. The oracle holds an ordinary secp256k1 key
// — the same kind of key that signs its transactions and sits in its
// certificate — and signs a statement about the world with it. The coin moves
// only if that statement was signed by that key.
//
// Until now the BSV answer to this has been Rabin: verifiable with OP_MUL and
// OP_MOD, a few hundred bytes, and a key the oracle must hold specifically for
// the purpose. The trade this example makes concrete is 197 KB of Script
// against not asking the oracle to run a second key.
//
// TWO THINGS THIS EXAMPLE EXISTS TO SAY.
//
// z is hashed IN the script, from the message the spender pushes. Passing z
// directly would prove only that the oracle once signed something; binding it
// to SHA-256 of the statement is what makes the statement the thing being
// attested.
//
// And an oracle signature authorises a MESSAGE, not a TRANSACTION. On its own
// this is a hashlock whose preimage is published on first use. OP_CHECKSIG is
// what binds the spend to this transaction and this owner; both, or neither is
// worth anything.

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { evaluateSpend } = require('../src/run')
const { apply } = require('../src/module')
const { pushNum, pushData } = require('../src/num')
const bytes = require('../src/modules/bytes')
const ecdsaMod = require('../src/modules/ecdsa')
const ecJs = require('../src/ec')

// The oracle's key. A fixed value so the example reproduces byte for byte.
const oracle = bsv.PrivateKey.fromBuffer(Buffer.from('33'.repeat(32), 'hex'))
const Q = ecJs.fromBsv(oracle.publicKey.point)

// The coin's owner, who must also sign the spend.
const owner = bsv.PrivateKey.fromBuffer(Buffer.from('44'.repeat(32), 'hex'))
const ownerPkh = bsv.crypto.Hash.sha256ripemd160(owner.publicKey.toBuffer())

const statement = Buffer.from('BSV/USD close 2026-09-05: 41.87')

const WITNESS_SLOTS = ['sinv', 'ubits', 'utape', 'ufi', 'vbits', 'vtape', 'vfi', 'finv']
const verifier = ecdsaMod.verifier([{ name: 'example', inputs: {} }])

/** The locking script: the owner's key, and the oracle's attestation. */
function lockingScript () {
  const asm = new Asm()
  asm.given([
    { name: 'msg', kind: 'bytes' },
    { name: 'r' }, { name: 's' },
    { name: 'sinv' },
    { name: 'ubits', kind: 'bytes' }, { name: 'utape', kind: 'bytes' }, { name: 'ufi' },
    { name: 'vbits', kind: 'bytes' }, { name: 'vtape', kind: 'bytes' }, { name: 'vfi' },
    { name: 'finv' },
    { name: 'ecdsaSig', kind: 'bytes' },
    { name: 'pubkey', kind: 'bytes' }
  ])

  // 1. this spend, by this owner — the only part that binds to the transaction
  asm.op('OP_DUP', 0, [{ name: 'pk2', kind: 'bytes' }])
  asm.hash160('pkh')
  asm.data(ownerPkh, 'wantPkh')
  asm.equalVerify()
  asm.op('OP_CHECKSIGVERIFY', 2, [])

  // 2. z = SHA-256(statement) mod n, computed here rather than trusted
  asm.roll('msg'); asm.sha256('_h')
  apply(asm, bytes.beToNum, { width: 32 }, ['_h'], ['_zfull'])
  asm.num(ecJs.N, '_N'); asm.mod('z')

  // 3. the oracle's public key is the lock's own constant, not an input
  asm.num(Q.x, 'qx'); asm.num(Q.y, 'qy')

  apply(asm, verifier, {}, ['z', 'r', 's', 'qx', 'qy', ...WITNESS_SLOTS], [])
  asm.num(1, 'true')
  return asm.script()
}

/** What the spender must compute off chain to unlock it. */
function spendWitness (message) {
  const hash = bsv.crypto.Hash.sha256(Buffer.from(message))
  const z = BigInt('0x' + hash.toString('hex')) % ecJs.N
  const sig = bsv.crypto.ECDSA.sign(hash, oracle)
  let s = BigInt('0x' + sig.s.toString(16))
  if (s > ecJs.N / 2n) s = ecJs.N - s              // low-S, as any modern signer emits
  const r = BigInt('0x' + sig.r.toString(16))
  return { z, r, s, w: ecdsaMod.witness({ z, r, s, q: Q }) }
}

const lock = lockingScript()

// `message` is what the unlocking script pushes; `signOver` is what the oracle
// actually signed. Keeping them separate is the whole point — a test that signs
// whatever it pushes is not testing a signature at all.
function spend ({ message = statement, signOver = null, key = owner, mutate } = {}) {
  const { r, s, w } = spendWitness(signOver || message)
  let sig = { r, s, w }
  if (mutate) sig = mutate({ r, s, w })
  return evaluateSpend(lock, ({ sign }) => {
    const u = new bsv.Script()
      .add(pushData(Buffer.from(message)))
      .add(pushNum(sig.r)).add(pushNum(sig.s))
      .add(pushNum(sig.w.sinv))
      .add(pushData(sig.w.ubits)).add(pushData(sig.w.utape)).add(pushNum(sig.w.ufi))
      .add(pushData(sig.w.vbits)).add(pushData(sig.w.vtape)).add(pushNum(sig.w.vfi))
      .add(pushNum(sig.w.finv))
      .add(sign(key)).add(key.publicKey.toBuffer())
    return u
  })
}

const honest = spend()
const stranger = bsv.PrivateKey.fromRandom()
const refusals = [
  ['a statement the oracle did not sign', spend({
    message: Buffer.from('BSV/USD close 2026-09-05: 99.99'), signOver: statement
  })],
  ['the signed statement, one character changed', spend({
    message: Buffer.from('BSV/USD close 2026-09-05: 41.88'), signOver: statement
  })],
  ['the owner’s key replaced by a stranger’s', spend({ key: stranger })],
  ['the oracle signature malleated to (r, n − s)', spend({
    mutate: ({ r, s }) => {
      const s2 = ecJs.N - s
      const z = BigInt('0x' + bsv.crypto.Hash.sha256(statement).toString('hex')) % ecJs.N
      return { r, s: s2, w: ecdsaMod.witness({ z, r, s: s2, q: Q }) }
    }
  })],
  ['a signature from a different oracle key', spend({
    mutate: () => {
      const other = bsv.PrivateKey.fromBuffer(Buffer.from('55'.repeat(32), 'hex'))
      const hash = bsv.crypto.Hash.sha256(statement)
      const z = BigInt('0x' + hash.toString('hex')) % ecJs.N
      const sg = bsv.crypto.ECDSA.sign(hash, other)
      let s = BigInt('0x' + sg.s.toString(16)); if (s > ecJs.N / 2n) s = ecJs.N - s
      const r = BigInt('0x' + sg.r.toString(16))
      return { r, s, w: ecdsaMod.witness({ z, r, s, q: ecJs.fromBsv(other.publicKey.point) }) }
    }
  })]
]

console.log(`
  A coin released by an oracle's ordinary secp256k1 signature

  locking script     ${lock.toBuffer().length.toLocaleString()} bytes
  unlocking script   ${honest.unlockSize.toLocaleString()} bytes
  statement          “${statement}”
  oracle key         ${oracle.publicKey.toString().slice(0, 26)}…

  the owner spends, with the oracle's attestation    ${honest.ok ? 'ACCEPTED' : 'refused — ' + honest.error}`)

for (const [what, r] of refusals) console.log(`  ${what.padEnd(50)} ${r.ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

const ok = honest.ok && refusals.every(([, r]) => !r.ok)
console.log(`\n  ${ok ? 'The oracle signs a statement with the key it already has, and Bitcoin checks it.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
