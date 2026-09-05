'use strict'

const { proveAll } = require('./src/testkit')
const int = require('./src/modules/int')
const bytes = require('./src/modules/bytes')
const rsa = require('./src/modules/rsa')
const u32 = require('./src/modules/u32')
const sha256 = require('./src/modules/sha256')
const hmac = require('./src/modules/hmac')
const totp = require('./src/modules/totp')
const ec = require('./src/modules/ec')
const ecdsa = require('./src/modules/ecdsa')

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
  [ecdsa.verifier([ecdsa.signCase('22'.repeat(32), 'the price of gold is 4211 on 2026-09-05')]), {}]
])

process.exit(failures.length ? 1 : 0)
