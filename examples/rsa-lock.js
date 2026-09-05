'use strict'

// A COIN AN RSA AUTHORITY UNLOCKS — the modules assembled into a real,
// deployable locking script, spent against the real interpreter.
//
// And the thing this example exists to say: an RSA signature authorises a
// MESSAGE, not a TRANSACTION. On its own, `rsa.verify` is a hashlock with extra
// steps — the first spend publishes the message and the signature in an
// unlocking script anybody can copy, and the next person redirects the coin to
// themselves. Every off-chain-signature scheme has this shape: Rabin oracles,
// ML-DSA, anything the compiler lowers next.
//
// So the lock below is TWO conditions: OP_CHECKSIG binds the spend to this
// transaction and this key, and rsa.verify establishes that an authority
// approved the statement. Both, or neither is worth anything.

const bsv = require('@smartledger/bsv')
const Op = bsv.Opcode
const { Asm } = require('../src/asm')
const { evaluateSpend } = require('../src/run')
const { apply } = require('../src/module')
const { pushNum, pushData } = require('../src/num')
const rsaMod = require('../src/modules/rsa')
const rsaJs = require('../src/rsa')

const key = rsaMod.fixtureKey()
const params = { n: key.n, e: key.e, emLen: key.emLen }
// A fixed key, so the example reproduces byte for byte. It holds nothing.
const owner = bsv.PrivateKey.fromBuffer(
  Buffer.from('1111111111111111111111111111111111111111111111111111111111111111', 'hex')
)
const ownerPkh = bsv.crypto.Hash.sha256ripemd160(owner.publicKey.toBuffer())

const statement = Buffer.from('shipment 4471 cleared customs 2026-09-05')

/** The locking script: an authority's approval, AND the owner's key. */
function lockingScript () {
  const asm = new Asm()
  asm.given([
    { name: 'msg', kind: 'bytes' },
    { name: 'rsaSig', kind: 'num' },
    { name: 'ecdsaSig', kind: 'bytes' },
    { name: 'pubkey', kind: 'bytes' }
  ])
  // 1. this spend, by this key — the part that binds to the transaction
  asm.op('OP_DUP', 0, [{ name: 'pk2', kind: 'bytes' }])
  asm.hash160('pkh')
  asm.data(ownerPkh, 'wantPkh')
  asm.equalVerify()
  asm.op('OP_CHECKSIGVERIFY', 2, [])
  // 2. the authority's approval of the statement — the part Bitcoin has no
  //    opcode for. apply() moves this script's values into the module's own
  //    input names, which is the whole of what composing two modules means.
  apply(asm, rsaMod.verifier(key), params, ['msg', 'rsaSig'], [])
  asm.num(1, 'true')
  return asm.script()
}

const lock = lockingScript()
const rsaSig = rsaJs.encodeSignature(rsaJs.sign(statement, key.privateKey))

// ── the honest spend ────────────────────────────────────────────────────────
const spend = evaluateSpend(lock, ({ sign }) => new bsv.Script()
  .add(pushData(statement))
  .add(pushNum(rsaSig))
  .add(sign(owner))
  .add(owner.publicKey.toBuffer()))

// ── and what it refuses ─────────────────────────────────────────────────────
const stranger = bsv.PrivateKey.fromRandom()
const refusals = [
  ['a different statement, same authority signature', evaluateSpend(lock, ({ sign }) => new bsv.Script()
    .add(pushData(Buffer.from('shipment 4471 cleared customs 2026-09-06')))
    .add(pushNum(rsaSig)).add(sign(owner)).add(owner.publicKey.toBuffer()))],
  ['a forged authority signature', evaluateSpend(lock, ({ sign }) => new bsv.Script()
    .add(pushData(statement)).add(pushNum(rsaSig + 1n))
    .add(sign(owner)).add(owner.publicKey.toBuffer()))],
  ['the same authority signature, a stranger’s key', evaluateSpend(lock, ({ sign }) => new bsv.Script()
    .add(pushData(statement)).add(pushNum(rsaSig))
    .add(sign(stranger)).add(stranger.publicKey.toBuffer()))],
  ['the authority signature + n (malleated)', evaluateSpend(lock, ({ sign }) => new bsv.Script()
    .add(pushData(statement)).add(pushNum(rsaSig + key.n))
    .add(sign(owner)).add(owner.publicKey.toBuffer()))]
]

console.log(`
  An RSA-2048 authority gate over a P2PKH spend

  locking script     ${lock.toBuffer().length.toLocaleString()} bytes
  unlocking script   ${spend.unlockSize.toLocaleString()} bytes
  statement          “${statement}”

  the owner spends, with the authority's approval   ${spend.ok ? 'ACCEPTED' : 'refused — ' + spend.error}`)

for (const [what, r] of refusals) console.log(`  ${what.padEnd(48)} ${r.ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

const ok = spend.ok && refusals.every(([, r]) => !r.ok)
console.log(`\n  ${ok ? 'The coin moves for the owner with an approved statement, and for nobody else.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
