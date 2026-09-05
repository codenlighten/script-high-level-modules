'use strict'

const { proveAll } = require('./src/testkit')
const int = require('./src/modules/int')
const bytes = require('./src/modules/bytes')
const rsa = require('./src/modules/rsa')
const u32 = require('./src/modules/u32')
const sha256 = require('./src/modules/sha256')

const { failures } = proveAll([
  [int.modadd, {}],
  [int.modsub, {}],
  [int.modmul, {}],
  [int.modexp, {}],
  [int.modinv, {}],
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
  [sha256.block, {}]
])

process.exit(failures.length ? 1 : 0)
