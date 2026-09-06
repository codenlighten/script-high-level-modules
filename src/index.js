'use strict'

// The library, and a catalogue of what is in it.
//
// A module is only reusable if it can be found, so every module is registered
// here with the metadata a consumer needs to decide: what it takes, what it
// returns, which of its inputs the spender supplies, and what it costs. The
// entries that need a key or a width are functions, because a module without
// cases is not a module and those cases need one.

const int = require('./modules/int')
const bytes = require('./modules/bytes')
const u32 = require('./modules/u32')
const sha256 = require('./modules/sha256')
const rsa = require('./modules/rsa')
const hmac = require('./modules/hmac')
const totp = require('./modules/totp')
const ec = require('./modules/ec')
const ecdsa = require('./modules/ecdsa')
const schnorrMod = require('./modules/schnorr')
const merkle = require('./modules/merkle')
const txmod = require('./modules/tx')
const stateMod = require('./modules/state')
const fp2 = require('./modules/fp2')
const fp6 = require('./modules/fp6')
const fp12 = require('./modules/fp12')
const g2mod = require('./modules/g2')
const pairingMod = require('./modules/pairing')
const groth16 = require('./modules/groth16')

const { defineModule, apply, instantiate } = require('./module')
const { Asm } = require('./asm')
const { predicate } = require('./predicate')
const compose = require('./compose')
const recipes = require('./recipes')
const { evaluate, evaluateSpend, policyFlags } = require('./run')
const { proveModule, proveAll, moduleSize, build } = require('./testkit')
const num = require('./num')
const bigint = require('./bigint')
const ecMath = require('./ec')
const schnorrMath = require('./schnorr')
const rsaMath = require('./rsa')

/** Every module that is ready to use, by name. */
const modules = {
  'int.modadd': int.modadd,
  'int.modsub': int.modsub,
  'int.modmul': int.modmul,
  'int.modexp': int.modexp,
  'int.modinv': int.modinv,
  'bytes.reverse': bytes.reverse,
  'bytes.beToNum': bytes.beToNum,
  'u32.rotr': u32.rotr,
  'u32.shr': u32.shr,
  'u32.xor': u32.xor,
  'u32.add': u32.add,
  'u32.ch': u32.ch,
  'u32.maj': u32.maj,
  'sha256.sigma0': u32.sigma0,
  'sha256.sigma1': u32.sigma1,
  'sha256.Sigma0': u32.Sigma0,
  'sha256.Sigma1': u32.Sigma1,
  'sha256.block': sha256.block,
  'hmac.sha256': hmac.sha256,
  'hmac.sha1': hmac.sha1,
  'totp.verify': totp.verify,
  'ec.add': ec.add,
  'ec.double': ec.double,
  'tx.locktime': txmod.locktime,
  'tx.hashOutputs': txmod.hashOutputs,
  'schnorr.liftX': schnorrMod.liftX,
  // The pairing tower. Every one of these takes its prime as a parameter, so
  // they are not BLS12-381 modules — they are Fp2, Fp6 and Fp12 over any prime
  // with p ≡ 3 (mod 4), which is what makes u² + 1 irreducible. BLS12-381 is
  // where they are measured, in docs/pairing.md.
  'fp2.mul': fp2.mul,
  'fp2.sqr': fp2.sqr,
  'fp2.add': fp2.add,
  'fp2.sub': fp2.sub,
  'fp2.neg': fp2.neg,
  'fp2.conj': fp2.conj,
  'fp2.mulXi': fp2.mulXi,
  'fp2.mulFp': fp2.mulFp,
  'fp2.inv': fp2.inv,
  'fp6.mul': fp6.mul,
  'fp6.sqr': fp6.sqr,
  'fp6.add': fp6.add,
  'fp6.sub': fp6.sub,
  'fp6.mulV': fp6.mulV,
  'fp12.mul': fp12.mul,
  'fp12.sqr': fp12.sqr,
  'fp12.cycSqr': fp12.cycSqr,
  'fp12.mulLine': fp12.mulLine,
  'fp12.conj': fp12.conj,
  'fp12.frob': fp12.frob,
  'fp12.inv': fp12.inv,
  'fp12.powX': fp12.powX,
  'fp12.powXc': fp12.powXc,
  // The Miller loop's step function on the twist. These ARE BLS12-381 specific
  // in their test vectors but not in their arithmetic: the curve equation never
  // appears, only the slope through two points and the line it determines.
  'g2.stepDouble': g2mod.stepDouble,
  'g2.stepAdd': g2mod.stepAdd,
  // The whole final exponentiation, 592 KB of it, as one module.
  'pairing.finalExp': pairingMod.finalExp
}

/** The ones that are built for a particular key, width or scalar set. */
const factories = {
  'rsa.verify': rsa.verifier,
  'ec.mul': ec.mul,
  'ec.mulG': ec.mulG,
  'ecdsa.verify': ecdsa.verifier,
  'schnorr.verify': schnorrMod.verifier,
  'merkle.verify': merkle.verify,
  'tx.requireOutputs': txmod.requireOutputs,
  'recipes.authorityPays': recipes.authorityPays,
  'recipes.timelockedTotp': recipes.timelockedTotp,
  'recipes.counterCoin': recipes.counterCoin,
  'tx.transition': txmod.transition,
  'tx.transitionPaying': txmod.transitionPaying,
  'state.counter': stateMod.counter,
  'state.limit': stateMod.limit,
  'recipes.budgetCoin': recipes.budgetCoin,
  'pairing.miller': pairingMod.miller,
  'pairing.e': pairingMod.full,
  'pairing.product': pairingMod.product,
  'pairing.verify': pairingMod.verify,
  'groth16.verify': groth16.verifier
}

/** What a consumer needs to decide whether a module fits. */
function describe (m) {
  return {
    name: m.name,
    doc: m.doc,
    inputs: m.inputs.map((i) => ({ name: i.name, kind: i.kind, witness: !!i.witness })),
    outputs: m.outputs.map((o) => ({ name: o.name, kind: o.kind })),
    witnessed: m.witnessed.map((w) => w.name),
    isPredicate: m.outputs.length === 0,
    contextual: !!m.contextual,
    cases: m.cases.length,
    notes: m.notes
  }
}

function catalog () {
  return [
    ...Object.values(modules).map(describe),
    ...Object.entries(factories).map(([name, f]) => ({ name, factory: true, doc: `${name}(...) — built for a specific key, width or scalar set` }))
  ]
}

module.exports = {
  int, bytes, u32, sha256, rsa, hmac, totp, ec, ecdsa, schnorr: schnorrMod, merkle, tx: txmod, state: stateMod,
  fp2, fp6, fp12, g2: g2mod, pairing: pairingMod, groth16, bls12381: require('./bls12381'),
  modules, factories, catalog, describe,
  defineModule, apply, instantiate, predicate, compose, recipes, Asm,
  evaluate, evaluateSpend, policyFlags,
  proveModule, proveAll, moduleSize, build,
  num, bigint, math: { ec: ecMath, rsa: rsaMath, schnorr: schnorrMath }
}
