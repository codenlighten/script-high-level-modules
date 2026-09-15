'use strict'

// The SLH-DSA-SHA2-128s vectors, as the verifiers take them — and a signer for
// the same test key, for witnesses that have to sign a transaction that does not
// exist until the test builds it.

const v = require('./vectors.json')

let secret = null
function secretKey () {
  if (!secret) {
    const { slh_dsa_sha2_128s: noble } = require('@noble/post-quantum/slh-dsa.js')
    secret = noble.keygen(Buffer.from(v.seed, 'hex')).secretKey
  }
  return secret
}

module.exports = {
  parameterSet: v.parameterSet,
  publicKey: Buffer.from(v.publicKey, 'hex'),
  cases: v.cases.map((c) => ({ name: c.name, message: Buffer.from(c.message, 'hex'), signature: Buffer.from(c.signature, 'hex') })),
  /** Deterministic, so a spend built twice signs the same digest the same way. */
  sign (digest) {
    const { slh_dsa_sha2_128s: noble } = require('@noble/post-quantum/slh-dsa.js')
    return Buffer.from(noble.sign(Buffer.from(digest), secretKey(), { extraEntropy: false }))
  }
}
