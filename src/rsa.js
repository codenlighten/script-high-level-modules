'use strict'

const crypto = require('crypto')
const { fromBE, toBE } = require('./num')

// The JS side of RSA: reading a key, and producing the encoded message a
// PKCS#1 v1.5 signature is the e-th root of. Nothing here is novel — it is the
// standard, written out so the Script module can be checked against it, and so
// the test can use a signature made by OpenSSL rather than by this file.

// DigestInfo for SHA-256, from RFC 8017 — the ASN.1 header the standard fixes.
const SHA256_DIGESTINFO = Buffer.from('3031300d060960864801650304020105000420', 'hex')

/** EM = 0x00 ‖ 0x01 ‖ 0xFF… ‖ 0x00 ‖ DigestInfo ‖ H(m), emLen bytes, big-endian. */
function pkcs1v15 (msgHash, emLen) {
  const tail = Buffer.concat([SHA256_DIGESTINFO, msgHash])
  const psLen = emLen - tail.length - 3
  if (psLen < 8) throw new Error('pkcs1: modulus too small for a SHA-256 signature')
  return Buffer.concat([
    Buffer.from([0x00, 0x01]), Buffer.alloc(psLen, 0xff), Buffer.from([0x00]), tail
  ])
}

/** The constant half of EM — everything but the digest. This is what the Script
 *  module hard-codes, so the only thing it computes at spend time is the hash. */
function pkcs1Prefix (emLen) {
  return pkcs1v15(Buffer.alloc(32), emLen).subarray(0, emLen - 32)
}

/** Generate a key and return the pieces both sides need. Slow; use a fixture. */
function generate (modulusLength = 2048) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength, publicExponent: 65537
  })
  const jwk = publicKey.export({ format: 'jwk' })
  return {
    n: fromBE(Buffer.from(jwk.n, 'base64url')),
    e: fromBE(Buffer.from(jwk.e, 'base64url')),
    emLen: modulusLength / 8,
    privateKey, publicKey,
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' })
  }
}

/** A signature from OpenSSL itself — RSASSA-PKCS1-v1_5 over SHA-256. */
function sign (msg, privateKey) {
  return crypto.sign('sha256', msg, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING })
}

/** Verification in JS — the same predicate the Script module enforces. */
function verify (msg, sigBE, { n, e, emLen }) {
  const s = fromBE(sigBE)
  if (s < 0n || s >= n) return false
  let r = 1n; let b = s % n; let x = e
  while (x > 0n) { if (x & 1n) r = (r * b) % n; b = (b * b) % n; x >>= 1n }
  const h = crypto.createHash('sha256').update(msg).digest()
  return r === fromBE(pkcs1v15(h, emLen))
}

/** The signature as the SPENDER pushes it: a Script number, not a byte string.
 *  Reversing 256 bytes on chain costs about a kilobyte of Script; asking the
 *  spender to push the number in the encoding Script already reads costs nothing
 *  and changes no security property, because the module pins s to [0, n). */
function encodeSignature (sigBE) { return fromBE(sigBE) }

module.exports = { SHA256_DIGESTINFO, pkcs1v15, pkcs1Prefix, generate, sign, verify, encodeSignature, toBE, fromBE }
