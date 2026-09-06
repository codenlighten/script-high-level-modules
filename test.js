'use strict'

const bsv = require('@smartledger/bsv')

const { proveAll } = require('./src/testkit')
const int = require('./src/modules/int')
const fp2 = require('./src/modules/fp2')
const fp6 = require('./src/modules/fp6')
const fp12 = require('./src/modules/fp12')
const g2mod = require('./src/modules/g2')
const pointsMod = require('./src/modules/points')
const pairingMod = require('./src/modules/pairing')
const groth16 = require('./src/modules/groth16')
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

const { failures, reports } = proveAll([
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
  [pointsMod.onCurveG1, {}],
  [pointsMod.onCurveG2, {}],
  [g2mod.stepDouble, {}],
  [g2mod.stepAdd, {}],
  [fp12.conj, {}],
  [fp12.frob, {}],
  [fp12.inv, {}],
  [fp12.powX, {}],
  [fp12.powXc, {}],
  // Two rounds is enough to exercise every shape the loop has: a tangent, a
  // chord, the squaring that belongs to the bit rather than to the line, and
  // the accumulator surviving a round trip through both.
  // tools/pairing-prove.js runs the whole pairing.
  [pairingMod.miller(2), {}],
  // Two pairings sharing one accumulator. The structural risk a multi-pairing
  // adds is the squaring: it belongs to the BIT, so k pairs pay for 63 between
  // them and not 63 each, and getting that wrong is a wrong answer rather than
  // a slow one. tools/groth16.js runs three at full depth.
  [pairingMod.miller(2, { pairs: 2 }), {}],
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
  [txmod.commitData(588), {}],
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

// ── the README's own numbers ────────────────────────────────────────────────
//
// The cost tables are generated because a transcribed number drifts. So do
// these: the README says how many modules, cases and forgery attempts this
// suite runs, and that sentence has been wrong before. It is cheaper to check
// it here than to notice it in a year.
{
  const fs = require('fs')
  const cases = reports.reduce((s, r) => s + r.cases.length, 0)
  const attacks = reports.reduce((s, r) => s + r.attacks.length, 0)
  const want = `${reports.length} modules, ${cases.toLocaleString()} cases, ${attacks.toLocaleString()} forgery attempts`
  const readme = fs.readFileSync(require('path').join(__dirname, 'README.md'), 'utf8')
  if (!readme.includes(want)) {
    console.log(`\n  README.md does not say "${want}" — update it, or say why the suite shrank`)
    process.exit(1)
  }
  console.log(`\n  README.md agrees: ${want}`)
}

// ── the one Groth16 property that must never regress ────────────────────────
//
// tools/groth16.js emits the whole verifier and runs it, and takes fifty
// seconds to do it. This is the part of that which is worth checking on every
// single run, because it is not a performance property or an arithmetic one —
// it is the difference between a verifier and a hole.
//
// A Groth16 verifier is sound only if the SPENDER CANNOT CHOOSE γ, δ or L. A
// spender who could choose γ could choose one that makes the equation hold for
// a proof of nothing. So the verifier's inputs must be exactly the proof and
// the witnesses, and never a verifying-key point. pairing.verify(3, …) takes
// all three pairs as inputs and is therefore a check of the equation rather
// than a verifier; the two are one wrapper apart and the wrapper is the point.
{
  const fx = groth16.fixture([3n, 5n])
  const v = groth16.verifier(fx.vk, fx.publicInputs, {
    cases: [{ name: 'a valid proof', inputs: fx.proof, params: { n: require('./src/bls12381').P, nn: require('./src/bls12381').P } }]
  })
  const open = v.inputs.filter((i) => !i.witness).map((i) => i.name).sort()
  const expected = ['Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy'].sort()
  const same = open.length === expected.length && open.every((k, i) => k === expected[i])
  if (!same) {
    console.log(`\n  groth16.verify: the spender can choose ${open.join(', ')}`)
    console.log(`  it must be only the proof: ${expected.join(', ')}`)
    process.exit(1)
  }
  // and the verifying key must actually appear in the script, as constants
  const { Asm } = require('./src/asm')
  const F = require('./src/facts')
  const bls = require('./src/bls12381')
  const asm = new Asm()
  asm.given([{ name: '_s', kind: 'bytes', width: 1 },
    ...v.inputs.map((i) => ({ name: i.name, kind: 'num', facts: F.range(0n, bls.P) }))])
  v.emit(asm, { n: bls.P, nn: bls.P })
  // Script numbers are little-endian and minimally encoded, so the constant is
  // looked for the way the interpreter would see it, not as big-endian hex.
  const { fromNum } = require('./src/num')
  const live = new Set(asm.script().chunks
    .filter((c) => c.buf)
    .map((c) => fromNum(c.buf).toString()))
  const buried = { 'γ.x0': fx.vk.gamma.x[0], 'δ.x0': fx.vk.delta.x[0], 'L.x': groth16.combine(fx.vk.IC, fx.publicInputs).x }
  for (const [what, value] of Object.entries(buried)) {
    if (!live.has(value.toString())) {
      console.log(`\n  groth16.verify: ${what} is not a constant in the locking script`)
      process.exit(1)
    }
  }
  console.log('\n  groth16.verify: the spender chooses only A, B, C — γ and δ are in the script')
}

process.exit(failures.length ? 1 : 0)
