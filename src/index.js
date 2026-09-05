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
const merkle = require('./modules/merkle')

const { defineModule, apply, instantiate } = require('./module')
const { Asm } = require('./asm')
const { predicate } = require('./predicate')
const { evaluate, evaluateSpend, policyFlags } = require('./run')
const { proveModule, proveAll, moduleSize, build } = require('./testkit')
const num = require('./num')
const bigint = require('./bigint')
const ecMath = require('./ec')
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
  'ec.double': ec.double
}

/** The ones that are built for a particular key, width or scalar set. */
const factories = {
  'rsa.verify': rsa.verifier,
  'ec.mul': ec.mul,
  'ec.mulG': ec.mulG,
  'ecdsa.verify': ecdsa.verifier,
  'merkle.verify': merkle.verify
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
  int, bytes, u32, sha256, rsa, hmac, totp, ec, ecdsa, merkle,
  modules, factories, catalog, describe,
  defineModule, apply, instantiate, predicate, Asm,
  evaluate, evaluateSpend, policyFlags,
  proveModule, proveAll, moduleSize, build,
  num, bigint, math: { ec: ecMath, rsa: rsaMath }
}
