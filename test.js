'use strict'

const bsv = require('@smartledger/bsv')

const { proveAll } = require('./src/testkit')
const int = require('./src/modules/int')
const fp2 = require('./src/modules/fp2')
const fp6 = require('./src/modules/fp6')
const fp12 = require('./src/modules/fp12')
const g2mod = require('./src/modules/g2')
const pairingMod = require('./src/modules/pairing')
const bytes = require('./src/modules/bytes')
const rsa = require('./src/modules/rsa')
const u32 = require('./src/modules/u32')
const sha256 = require('./src/modules/sha256')
const hmac = require('./src/modules/hmac')
const totp = require('./src/modules/totp')
const ec = require('./src/modules/ec')
const ecdsa = require('./src/modules/ecdsa')
const merkle = require('./src/modules/merkle')
const compose = require('./src/compose')
const txmod = require('./src/modules/tx')
const recipes = require('./src/recipes')
const schnorr = require('./src/modules/schnorr')
const stateMod = require('./src/modules/state')
const rsaFixture = rsa.fixtureKey()
const payee = bsv.PrivateKey.fromBuffer(Buffer.from('55'.repeat(32), 'hex')).toAddress()
const elsewhereAddr = bsv.PrivateKey.fromBuffer(Buffer.from('66'.repeat(32), 'hex')).toAddress()
const crypto = require('crypto')

const leaves = Array.from({ length: 8 }, (_, i) => crypto.createHash('sha256').update('leaf' + i).digest())
const mtree = merkle.tree(leaves)
const totpSecret = Buffer.from('12345678901234567890')
const totpCommit = crypto.createHash('sha256').update(totpSecret).digest()
const vaultTime = 1111111109n
const vaultProof = mtree.proof(2)
const vault = compose.all('vault', [
  { module: totp.verify, params: { keyLen: 20, digits: 6, step: 30, algo: 'sha1', keyCommitment: totpCommit } },
  { module: merkle.verify(mtree.root, { depth: 3, leaves }), params: { depth: 3, root: mtree.root } }
], {
  cases: [{
    name: 'leaf 2, current code',
    inputs: {
      ...compose.forPart('totp_', { key: totpSecret, time: vaultTime, code: totp.totpCode(totpSecret, Number(vaultTime), { digits: 6 }) }),
      ...compose.forPart('merkle_', { leaf: leaves[2], path: vaultProof.path, dirs: vaultProof.dirs })
    }
  }]
})

const { failures } = proveAll([
  [int.modadd, {}],
  [int.modsub, {}],
  [int.modmul, {}],
  [int.modexp, {}],
  [int.modinv, {}],
  [fp2.mul, {}],
  [fp2.sqr, {}],
  [fp2.add, {}],
  [fp2.sub, {}],
  [fp2.mulXi, {}],
  [fp2.mulFp, {}],
  [fp2.neg, {}],
  [fp2.conj, {}],
  [fp2.inv, {}],
  [fp6.mul, {}],
  [fp6.sqr, {}],
  [fp6.add, {}],
  [fp6.sub, {}],
  [fp6.mulV, {}],
  [fp12.mul, {}],
  [fp12.sqr, {}],
  [fp12.cycSqr, {}],
  [fp12.mulLine, {}],
  [g2mod.stepDouble, {}],
  [g2mod.stepAdd, {}],
  [fp12.conj, {}],
  [fp12.frob, {}],
  [fp12.inv, {}],
  // Two rounds is enough to exercise every shape the loop has: a tangent, a
  // chord, the squaring that belongs to the bit rather than to the line, and
  // the accumulator surviving a round trip through both.
  // tools/pairing-prove.js runs the whole pairing.
  [pairingMod.miller(2), {}],
  [bytes.reverse, {}],
  [bytes.beToNum, {}],
  [rsa.verifier(rsa.fixtureKey()), {}],
  [u32.rotr, {}],
  [u32.shr, {}],
  [u32.xor, {}],
  [u32.add, {}],
  [u32.ch, {}],
  [u32.maj, {}],
  [u32.sigma0, {}],
  [u32.sigma1, {}],
  [u32.Sigma0, {}],
  [u32.Sigma1, {}],
  [sha256.block, {}],
  [hmac.sha256, {}],
  [hmac.sha1, {}],
  [totp.verify, {}],
  [totp.committed(Buffer.from('12345678901234567890')), {}],
  [ec.add, {}],
  [ec.double, {}],
  [ec.mul(8), {}],
  [ec.mul(32), {}],
  [ec.mulG(8), {}],
  [ec.mulG(32), {}],
  [ecdsa.verifier([ecdsa.signCase('22'.repeat(32), 'the price of gold is 4211 on 2026-09-05')]), {}],
  [merkle.verify(mtree.root, { depth: 3, leaves }), {}],
  [vault, {}],
  [txmod.locktime, {}],
  [recipes.timelockedTotp(Buffer.from('12345678901234567890'), { digits: 6, step: 30, at: 1600000020 }), {}],
  [txmod.hashOutputs, {}],
  [txmod.requireOutputs([recipes.instructedOutput(payee, 42)]), {}],
  [recipes.authorityPays(rsaFixture, { cases: recipes.authorityPaysCases(payee, 700, elsewhereAddr) }), {}],
  [schnorr.liftX, {}],
  [schnorr.verifier([], { cases: schnorr.bip340Cases() }), {}],
  [txmod.transition({ stateWidth: 8, fee: 200 }), {}],
  [stateMod.counter({ stateWidth: 8 }), {}],
  [recipes.counterCoin({ from: 41n }), {}],
  [txmod.transitionPaying({ stateWidth: 8, fee: 300 }), {}],
  [stateMod.limit({ stateWidth: 8 }), {}],
  [recipes.budgetCoin({ allowance: 1000n }), {}]
])

process.exit(failures.length ? 1 : 0)
