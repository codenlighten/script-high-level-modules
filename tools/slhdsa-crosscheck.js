'use strict'

// src/slhdsa.js AGAINST AN IMPLEMENTATION THAT SHARES NO CODE WITH IT.
//
// The Script verifier will be checked against src/slhdsa.js, so src/slhdsa.js
// has to be right first, and "right" is not something a reading of the standard
// can establish by itself. @noble/post-quantum signs; this verifies. Three
// things are required:
//
//   every signature noble makes verifies here
//   nothing noble would refuse verifies here — a flipped byte in each region of
//   the signature, a different message, a different key, a different context
//   the number of hash calls is what the structure says it must be
//
// The last is not decoration. It is the budget a Script verifier inherits, and
// the Groth16 spend that miners refused for its validation time is the reason it
// is measured before anything is emitted.

const assert = require('assert')
const crypto = require('crypto')
const slh = require('../src/slhdsa')

const NAME = 'SLH-DSA-SHA2-128s'

async function main () {
  const { slh_dsa_sha2_128s: noble } = await import('@noble/post-quantum/slh-dsa.js')
  const P = slh.derive(NAME)
  let checks = 0
  const ok = (cond, what) => { assert.ok(cond, what); checks++ }

  console.log(`\n  ${NAME}: n=${P.n} h=${P.h} d=${P.d} h'=${P.hp} a=${P.a} k=${P.k} w=${P.w} len=${P.len}`)
  console.log(`  public key ${P.pkBytes} bytes, signature ${P.sigBytes.toLocaleString()} bytes\n`)
  ok(P.sigBytes === noble.lengths.signature && P.pkBytes === noble.lengths.publicKey, 'the sizes agree with noble')

  // Deterministic keys, so a failure reproduces.
  const seedFor = (i) => crypto.createHash('sha512').update(`slhdsa-crosscheck/${i}`).digest().subarray(0, 48)
  const keys = [0, 1, 2].map((i) => noble.keygen(seedFor(i)))

  let accepted = 0
  for (const [i, { publicKey, secretKey }] of keys.entries()) {
    for (const msg of [Buffer.alloc(0), Buffer.from('script-modules: a post-quantum signature'), crypto.randomBytes(32)]) {
      const sig = Buffer.from(noble.sign(msg, secretKey))
      ok(noble.verify(sig, msg, publicKey), 'noble accepts its own signature')
      slh.resetCount()
      ok(slh.verify(NAME, msg, sig, Buffer.from(publicKey)), `key ${i}: a noble signature over ${msg.length} bytes verifies here`)
      accepted++
    }
  }
  console.log(`    · ${accepted} signatures from noble verify here`)

  // Every region of the signature, tampered.
  const { publicKey, secretKey } = keys[0]
  const msg = Buffer.from('script-modules: tamper with me')
  const sig = Buffer.from(noble.sign(msg, secretKey))
  const forsEnd = P.n + P.k * (1 + P.a) * P.n
  const xmss = (P.hp + P.len) * P.n
  const regions = [
    ['R, the randomizer', 0],
    ['a FORS secret', P.n],
    ['a FORS authentication node', P.n + P.n + 3],
    ['the last FORS tree', forsEnd - 1],
    ['a WOTS+ chain value, layer 0', forsEnd + 5],
    ['an XMSS authentication node, layer 0', forsEnd + P.len * P.n + 2],
    ['a WOTS+ chain value, the top layer', forsEnd + (P.d - 1) * xmss + 1],
    ['the last byte', P.sigBytes - 1]
  ]
  for (const [what, at] of regions) {
    const bad = Buffer.from(sig); bad[at] ^= 0x01
    ok(!noble.verify(bad, msg, publicKey) && !slh.verify(NAME, msg, bad, Buffer.from(publicKey)), `refused: ${what} changed`)
  }
  ok(!slh.verify(NAME, Buffer.from('script-modules: tamper with mE'), sig, Buffer.from(publicKey)), 'refused: a different message')
  ok(!slh.verify(NAME, msg, sig, Buffer.from(keys[1].publicKey)), 'refused: a different public key')
  ok(!slh.verify(NAME, msg, sig, Buffer.from(publicKey), Buffer.from('ctx')), 'refused: a different context')
  ok(!slh.verify(NAME, msg, sig.subarray(1), Buffer.from(publicKey)), 'refused: a signature one byte short')
  console.log(`    · ${regions.length + 4} forgeries refused, by noble and here alike`)

  // A context string, which the pure form prefixes and a Script verifier will too.
  const ctx = Buffer.from('bitcoin-script')
  const csig = Buffer.from(noble.sign(msg, secretKey, { context: ctx }))
  ok(noble.verify(csig, msg, publicKey, { context: ctx }), 'noble accepts a signature with a context')
  ok(slh.verify(NAME, msg, csig, Buffer.from(publicKey), ctx), 'a signature with a context verifies here')
  ok(!slh.verify(NAME, msg, csig, Buffer.from(publicKey)), 'and not without it')
  console.log('    · context strings agree')

  // The budget. Every call is determined by the structure except the WOTS+
  // chain lengths, which depend on the digest — so the worst case is computed
  // from the structure and the observed count must never exceed it.
  slh.resetCount()
  slh.verify(NAME, msg, sig, Buffer.from(publicKey))
  const c = { ...slh.count }
  const worst = {
    F: P.k + P.d * P.len * (P.w - 1),
    H: P.k * P.a + P.d * P.hp,
    T: 1 + P.d,
    Hmsg: 1
  }
  ok(c.H === worst.H && c.T === worst.T && c.Hmsg === 1, 'H, T and H_msg are fixed by the structure')
  ok(c.F >= P.k && c.F <= worst.F, 'F stays within the worst case')
  const total = c.F + c.H + c.T
  const worstTotal = worst.F + worst.H + worst.T
  console.log(`\n  hash calls for this signature   F ${c.F}  H ${c.H}  T ${c.T}  (+ H_msg)   ${total.toLocaleString()} in all`)
  console.log(`  worst case, unrolled for Script F ${worst.F}  H ${worst.H}  T ${worst.T}            ${worstTotal.toLocaleString()} in all`)
  console.log(`\n  ${checks} checks. SHA-256 compressions per verification: about ${(total * 2).toLocaleString()} (each tweakable hash is two blocks).\n`)
}

main().catch((e) => { console.error(`\n  ${e.message}\n`); process.exit(1) })
