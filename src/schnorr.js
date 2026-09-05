'use strict'

const crypto = require('crypto')
const ec = require('./ec')

// BIP-340 Schnorr, in plain BigInt — the reference the Script module is checked
// against, and itself checked against the BIP's own published vectors
// (tools/bip340-check.js). The library has no Schnorr to cross-check against, so
// the standard's vectors are the second implementation.
//
// Two things distinguish it from ECDSA, and both matter on chain.
//
// It is CANONICAL. ECDSA admits (r, n − s) alongside (r, s) and needs a low-S
// rule imposed on top to pick one; a Schnorr signature over a message under a
// key is unique. There is no malleability to legislate away.
//
// And the public key is X-ONLY: 32 bytes, with the even-Y point implied. That
// saves a byte on chain and costs a square root — which is the expensive
// direction to compute and the cheap one to check, so the spender supplies the
// y coordinate and the script verifies y² = x³ + 7 and that y is even.

const { P, N, G, mod, powmod, inv } = ec

const TAGS = {}
function taggedHash (tag, ...parts) {
  if (!TAGS[tag]) TAGS[tag] = crypto.createHash('sha256').update(tag).digest()
  const t = TAGS[tag]
  return crypto.createHash('sha256').update(Buffer.concat([t, t, ...parts])).digest()
}

const be32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex')
const toInt = (b) => BigInt('0x' + Buffer.from(b).toString('hex'))

/** The point with this x and an even y, or null if x is not on the curve. */
function liftX (x) {
  if (x <= 0n || x >= P) return null
  const c = mod(x * x % P * x + 7n, P)
  const y = powmod(c, (P + 1n) / 4n, P)
  if (mod(y * y, P) !== c) return null
  return { x, y: y % 2n === 0n ? y : P - y }
}

/** The x-only public key for a secret. */
function publicKey (secret) {
  const p = ec.mul(mod(secret, N), G)
  return be32(p.x)
}

function sign (secret, message, aux = Buffer.alloc(32)) {
  const d0 = mod(secret, N)
  if (d0 === 0n) throw new Error('schnorr: the secret is zero')
  const p = ec.mul(d0, G)
  const d = p.y % 2n === 0n ? d0 : N - d0
  const t = be32(d ^ toInt(taggedHash('BIP0340/aux', aux)))
  const rand = taggedHash('BIP0340/nonce', t, be32(p.x), message)
  const k0 = mod(toInt(rand), N)
  if (k0 === 0n) throw new Error('schnorr: the nonce is zero')
  const r = ec.mul(k0, G)
  const k = r.y % 2n === 0n ? k0 : N - k0
  const e = mod(toInt(taggedHash('BIP0340/challenge', be32(r.x), be32(p.x), message)), N)
  return Buffer.concat([be32(r.x), be32(mod(k + e * d, N))])
}

/** The predicate the Script module enforces, in JavaScript. */
function verify (pubkeyBytes, message, sig) {
  if (sig.length !== 64 || pubkeyBytes.length !== 32) return false
  const p = liftX(toInt(pubkeyBytes))
  if (!p) return false
  const r = toInt(sig.subarray(0, 32))
  const s = toInt(sig.subarray(32))
  if (r >= P || s >= N) return false
  const e = challenge(sig.subarray(0, 32), pubkeyBytes, message)
  const R = ec.add(ec.mul(s, G), ec.mul(mod(-e, N), p))
  if (R === ec.INFINITY) return false
  return R.y % 2n === 0n && R.x === r
}

/** e = int(tagged_hash("BIP0340/challenge", r ‖ pk ‖ m)) mod n */
function challenge (rBytes, pubkeyBytes, message) {
  return mod(toInt(taggedHash('BIP0340/challenge', rBytes, pubkeyBytes, message)), N)
}

/** The constant the Script module concatenates in front of r ‖ pk ‖ m. */
function challengeTagPrefix () {
  const t = crypto.createHash('sha256').update('BIP0340/challenge').digest()
  return Buffer.concat([t, t])
}

module.exports = { taggedHash, liftX, publicKey, sign, verify, challenge, challengeTagPrefix, be32, toInt, P, N, G, mod, inv }
