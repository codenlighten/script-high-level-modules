'use strict'

// SLH-DSA-SHA2-128s test vectors, made by @noble/post-quantum.
//
//   node test/vectors/slhdsa-sha2-128s/build.js
//
// The key comes from a fixed seed and the signatures are deterministic
// (FIPS 205's hedged randomness turned off), so rebuilding reproduces this file
// byte for byte. THE SEED IS PUBLIC: this is a test key, and anything locked to
// it can be spent by anyone who reads this file.

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { slh_dsa_sha2_128s: noble } = require('@noble/post-quantum/slh-dsa.js')

const seed = crypto.createHash('sha512').update('script-modules/slhdsa-sha2-128s/test-key').digest().subarray(0, 48)
const { publicKey, secretKey } = noble.keygen(seed)

const messages = [
  ['a 32-byte digest, the shape of a sighash', crypto.createHash('sha256').update('script-modules: message 0').digest()],
  ['a sentence', Buffer.from('script-modules: a post-quantum signature, verified by Bitcoin Script')]
]

const cases = messages.map(([name, message]) => {
  const signature = Buffer.from(noble.sign(message, secretKey, { extraEntropy: false }))
  if (!noble.verify(signature, message, publicKey)) throw new Error('noble does not accept its own signature')
  return { name, message: message.toString('hex'), signature: signature.toString('hex') }
})

const out = {
  parameterSet: 'SLH-DSA-SHA2-128s',
  // the package's exports do not include package.json, so it is read as a file
  producedBy: '@noble/post-quantum ' + JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'node_modules', '@noble', 'post-quantum', 'package.json'), 'utf8')).version,
  note: 'test key from a public seed; deterministic signatures, empty context',
  seed: Buffer.from(seed).toString('hex'),
  publicKey: Buffer.from(publicKey).toString('hex'),
  cases
}
fs.writeFileSync(path.join(__dirname, 'vectors.json'), JSON.stringify(out, null, 2) + '\n')
console.log(`wrote ${cases.length} signatures under ${out.publicKey}`)
