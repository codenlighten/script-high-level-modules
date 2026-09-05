'use strict'

const crypto = require('crypto')
const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { apply, defineModule } = require('../src/module')
const { predicate } = require('../src/predicate')
const { pushNum, pushData } = require('../src/num')
const compose = require('../src/compose')
const rsaMod = require('../src/modules/rsa')
const rsaJs = require('../src/rsa')
const ecdsaMod = require('../src/modules/ecdsa')
const sha256Mod = require('../src/modules/sha256')
const merkle = require('../src/modules/merkle')
const totp = require('../src/modules/totp')
const recipes = require('../src/recipes')
const txMod = require('../src/modules/tx')
const ecJs = require('../src/ec')

// WHAT GOES ON CHAIN.
//
// Each target is a locking script and the unlocking script that spends it,
// built against the REAL spending transaction rather than a stand-in. They are
// deliberately the modules that make the strongest claims — a signature scheme
// Bitcoin has no opcode for, a hash function rebuilt without the opcode that
// does it, and a covenant that reads its own transaction — because those are
// the ones where "the interpreter accepted it" is worth the least until the
// network has said the same thing.
//
// Every key here is a fixed, throwaway one, so a deployment reproduces byte for
// byte from this file.

const owner = bsv.PrivateKey.fromBuffer(Buffer.from('99'.repeat(32), 'hex'))
const ownerPkh = bsv.crypto.Hash.sha256ripemd160(owner.publicKey.toBuffer())

/** Prefix a locking script with "this spend, by this key". */
function ownedBy (asm) {
  asm.op('OP_DUP', 0, [{ name: '_k2', kind: 'bytes' }])
  asm.hash160('_pkh')
  asm.data(ownerPkh, '_want')
  asm.equalVerify()
  asm.op('OP_CHECKSIGVERIFY', 2, [])
  return asm
}

const targets = {}

// ── 1. RSA-2048, PKCS#1 v1.5, signed by OpenSSL ─────────────────────────────
targets.rsa = (() => {
  const key = rsaMod.fixtureKey()
  const params = { n: key.n, e: key.e, emLen: key.emLen }
  const statement = Buffer.from('script-modules: an RSA-2048 signature, verified by Bitcoin')
  const sig = rsaJs.encodeSignature(rsaJs.sign(statement, key.privateKey))

  const asm = new Asm()
  asm.given([
    { name: 'msg', kind: 'bytes' }, { name: 'rsaSig' },
    { name: 'sig', kind: 'bytes' }, { name: 'pubkey', kind: 'bytes' }
  ])
  ownedBy(asm)
  apply(asm, rsaMod.verifier(key), params, ['msg', 'rsaSig'], [])
  asm.num(1, 'true')

  return {
    name: 'rsa.verify',
    claim: 'an RSA-2048 PKCS#1 v1.5 signature, made by OpenSSL, verified by Bitcoin Script',
    lock: asm.script(),
    unlock: ({ sign }) => new bsv.Script()
      .add(pushData(statement)).add(pushNum(sig))
      .add(sign(owner)).add(owner.publicKey.toBuffer())
  }
})()

// ── 2. ECDSA over an arbitrary message ──────────────────────────────────────
targets.ecdsa = (() => {
  const oracle = bsv.PrivateKey.fromBuffer(Buffer.from('aa'.repeat(32), 'hex'))
  const Q = ecJs.fromBsv(oracle.publicKey.point)
  const statement = Buffer.from('script-modules: signed with an ordinary secp256k1 key')
  const hash = bsv.crypto.Hash.sha256(statement)
  const z = BigInt('0x' + hash.toString('hex')) % ecJs.N
  const raw = bsv.crypto.ECDSA.sign(hash, oracle)
  const r = BigInt('0x' + raw.r.toString(16))
  let s = BigInt('0x' + raw.s.toString(16))
  if (s > ecJs.N / 2n) s = ecJs.N - s
  const w = ecdsaMod.witness({ z, r, s, q: Q })

  const verifier = ecdsaMod.verifier([{ name: 'deployed', inputs: {} }])
  const asm = new Asm()
  asm.given([
    { name: 'z' }, { name: 'r' }, { name: 's' },
    { name: 'sinv' }, { name: 'shtape', kind: 'bytes' },
    { name: 'sig', kind: 'bytes' }, { name: 'pubkey', kind: 'bytes' }
  ])
  ownedBy(asm)
  asm.num(Q.x, 'qx'); asm.num(Q.y, 'qy')
  apply(asm, verifier, {}, ['z', 'r', 's', 'qx', 'qy', 'sinv', 'shtape'], [])
  asm.num(1, 'true')

  return {
    name: 'ecdsa.verify',
    claim: 'a secp256k1 ECDSA signature over an arbitrary message — no OP_CHECKSIG involved',
    lock: asm.script(),
    unlock: ({ sign }) => new bsv.Script()
      .add(pushNum(z)).add(pushNum(r)).add(pushNum(s))
      .add(pushNum(w.sinv)).add(pushData(w.shtape))
      .add(sign(owner)).add(owner.publicKey.toBuffer())
  }
})()

// ── 3. SHA-256 rebuilt from primitives, with OP_SHA256 nowhere in it ────────
targets.sha256 = (() => {
  const msg = Buffer.from('script-modules')
  const blk = sha256Mod.pad(msg)
  const digest = crypto.createHash('sha256').update(msg).digest()

  const asm = new Asm()
  asm.given([{ name: 'blk', kind: 'bytes', width: 64 }, { name: 'sig', kind: 'bytes' }, { name: 'pubkey', kind: 'bytes' }])
  ownedBy(asm)
  sha256Mod.block.emit(asm, {})
  asm.data(digest, 'want'); asm.equal('ok')

  return {
    name: 'sha256.block',
    claim: 'SHA-256 computed from OP_AND, OP_XOR, OP_LSHIFT and OP_ADD — the opcode unused',
    lock: asm.script(),
    unlock: ({ sign }) => new bsv.Script()
      .add(pushData(blk)).add(sign(owner)).add(owner.publicKey.toBuffer())
  }
})()

// ── 4. An authenticator code bound to the transaction's own locktime ────────
targets.timelock = (() => {
  const secret = Buffer.from('12345678901234567890')
  const STEP = 30
  const T = 1600000020
  const code = totp.totpCode(secret, T, { digits: 6, step: STEP })

  // The same recipe the example demonstrates and the suite proves. It used to
  // be written out again here, with different names for the same values.
  const m = recipes.timelockedTotp(secret, { digits: 6, step: STEP, at: T })
  const coin = predicate(m, {}, { owner: owner.publicKey })

  return {
    name: 'tx.locktime ▸ totp.verify',
    claim: 'a covenant that reads its own transaction: the code must match the locked time',
    lock: coin.lockingScript,
    shape: { nLockTime: T },
    // The preimage is produced from the real spend, then the owner signs it.
    unlock: ({ tx, lockingScript, satoshis, sign, shape }) => {
      const produced = m.witnessFor({ tx, lockingScript, satoshis, spend: shape })
      return coin.unlock({ ...produced, key: secret, code }, () => sign(owner))
    }
  }
})()

// ── 5. Three conditions, one coin ───────────────────────────────────────────
targets.vault = (() => {
  const members = ['alice', 'bob', 'carol', 'dave'].map((n) => crypto.createHash('sha256').update(n).digest())
  const tree = merkle.tree(members)
  const secret = Buffer.from('12345678901234567890')
  const commitment = crypto.createHash('sha256').update(secret).digest()
  const T = 1111111109
  const code = totp.totpCode(secret, T, { digits: 6 })
  const carol = tree.proof(2)
  const inputs = {
    ...compose.forPart('totp_', { key: secret, time: BigInt(T), code }),
    ...compose.forPart('merkle_', { leaf: members[2], path: carol.path, dirs: carol.dirs })
  }
  const rules = compose.all('vault', [
    { module: totp.verify, params: { keyLen: secret.length, digits: 6, step: 30, algo: 'sha1', keyCommitment: commitment } },
    { module: merkle.verify(tree.root, { depth: 2, leaves: members }), params: { depth: 2, root: tree.root } }
  ], { cases: [{ name: 'deployed', inputs }] })
  const coin = predicate(rules, {}, { owner: owner.publicKey })

  return {
    name: 'vault',
    claim: 'an allowlist, an authenticator code and an owner key, composed and attacked as one',
    lock: coin.lockingScript,
    unlock: ({ sign }) => coin.unlock(inputs, () => sign(owner))
  }
})()

// ── 6. BIP-340 Schnorr over an arbitrary message ────────────────────────────
targets.schnorr = (() => {
  const schnorrJs = require('../src/schnorr')
  const schnorrMod = require('../src/modules/schnorr')
  const secret = 0xb7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfefn
  const pubkey = schnorrJs.publicKey(secret)
  const statement = Buffer.from('script-modules: BIP-340, canonical by construction')
  const sig = schnorrJs.sign(secret, statement)
  const py = schnorrJs.liftX(schnorrJs.toInt(pubkey)).y
  const s = schnorrJs.toInt(sig.subarray(32))
  const e = schnorrJs.challenge(sig.subarray(0, 32), pubkey, statement)
  const w = require('../src/modules/ec').shamirWitness('sh', 256, s, ecJs.mod(-e, ecJs.N), { x: schnorrJs.toInt(pubkey), y: py }, {})

  const verifier = schnorrMod.verifier(['deployed'])
  const asm = new Asm()
  asm.given([
    { name: 'msg', kind: 'bytes' }, { name: 'sig', kind: 'bytes', width: 64 },
    { name: 'py' }, { name: 'shtape', kind: 'bytes' },
    { name: 'ecdsaSig', kind: 'bytes' }, { name: 'pubkey2', kind: 'bytes' }
  ])
  ownedBy(asm)
  asm.data(pubkey, 'pubkey')
  apply(asm, verifier, {}, ['msg', 'pubkey', 'sig', 'py', 'shtape'], [])
  asm.num(1, 'true')

  return {
    name: 'schnorr.verify',
    claim: 'a BIP-340 Schnorr signature over an arbitrary message, checked against the BIP\'s own vectors',
    lock: asm.script(),
    unlock: ({ sign }) => new bsv.Script()
      .add(pushData(statement)).add(pushData(sig)).add(pushNum(py)).add(pushData(w.shtape))
      .add(sign(owner)).add(owner.publicKey.toBuffer())
  }
})()

// ── 7. A payment the authority directs, not merely permits ──────────────────
targets.authority = (() => {
  const key = rsaMod.fixtureKey()
  const wallet = require('../src/onchain').loadWallet()
  const AMOUNT = 120                        // paid back to the funding address
  const msg = recipes.instruction(wallet.address, AMOUNT)
  const out = recipes.instructedOutput(wallet.address, AMOUNT)
  const m = recipes.authorityPays(key, {
    cases: recipes.authorityPaysCases(wallet.address, AMOUNT, owner.toAddress())
  })
  // No owner: replaying this witness produces the same payment to the same
  // address, so the check that exists to stop a replay has nothing to stop.
  const coin = predicate(m, {}, { owner: null })

  return {
    name: 'rsa.verify ▸ tx.hashOutputs',
    claim: 'the authority names the destination in what it signs, and the chain pays whoever it named',
    lock: coin.lockingScript,
    shape: { outputs: [out] },
    valueFor: (fee) => AMOUNT + fee,
    unlock: ({ tx, lockingScript, satoshis, shape }) => {
      const produced = m.witnessFor({ tx, lockingScript, satoshis, spend: shape })
      return coin.unlock({ ...produced, msg })
    }
  }
})()

module.exports = { targets, owner, ownerPkh }
