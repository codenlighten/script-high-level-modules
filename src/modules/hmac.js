'use strict'

const crypto = require('crypto')
const { defineModule } = require('../module')

// HMAC — the first module that is a COMPOSITION of an opcode Bitcoin already
// has, rather than a rebuild of one it does not.
//
//     HMAC(K, m) = H( (K ⊕ opad) ‖ H( (K ⊕ ipad) ‖ m ) )
//
// Two hashes, two XORs, three concatenations. Against `sha256.block` — the same
// hash function rebuilt from primitives at 50,765 bytes — this is the whole
// argument for looking at what the interpreter already provides before lowering
// anything: the identical construction costs about a hundred bytes here.
//
// The key is padded to the 64-byte block at COMPILE time, from its declared
// length, so no runtime length handling is needed. A key longer than the block
// is hashed first, which is what the standard says and what `keyLen > 64`
// selects here.

const BLOCK = 64
const IPAD = Buffer.alloc(BLOCK, 0x36)
const OPAD = Buffer.alloc(BLOCK, 0x5c)

const ALGOS = {
  sha256: { width: 32, emit: (asm, out) => asm.sha256(out) },
  sha1: { width: 20, emit: (asm, out) => asm.sha1(out) }
}

/**
 * Emit HMAC over the values named `keyName` (consumed) and `msgName` (consumed),
 * leaving the MAC as `outName`.
 */
function emitHmac (asm, { algo = 'sha256', keyLen }, keyName, msgName, outName) {
  const A = ALGOS[algo]
  if (!A) throw new Error(`hmac: no algorithm '${algo}' — Script has OP_SHA256 and OP_SHA1`)
  if (keyLen === undefined) throw new Error('hmac: needs the key length at compile time')

  asm.roll(keyName)
  if (keyLen > BLOCK) { A.emit(asm, '_kh'); asm.data(Buffer.alloc(BLOCK - A.width), '_kz'); asm.cat('_kp') } else if (keyLen < BLOCK) { asm.data(Buffer.alloc(BLOCK - keyLen), '_kz'); asm.cat('_kp') } else { asm.rename('_kp', 'bytes', BLOCK) }

  asm.pick('_kp', '_kp1'); asm.data(IPAD, '_ipad'); asm.xor('_inKey')
  asm.roll(msgName); asm.cat('_inBlock'); A.emit(asm, '_inner')

  asm.roll('_kp'); asm.data(OPAD, '_opad'); asm.xor('_outKey')
  asm.roll('_inner'); asm.cat('_outBlock'); A.emit(asm, outName)
  return asm
}

/** The reference: Node's HMAC, not a second implementation of the same idea. */
function model ({ key, msg }, { algo = 'sha256' }) {
  return { mac: crypto.createHmac(algo, Buffer.from(key)).update(Buffer.from(msg)).digest() }
}

function macModule (algo) {
  const A = ALGOS[algo]
  const KEYS = {
    short: Buffer.from('key'),
    block: Buffer.alloc(BLOCK, 0xa5),
    long: Buffer.alloc(100, 0x0b),
    rfc: Buffer.from('12345678901234567890')
  }
  const MSGS = [Buffer.from('The quick brown fox jumps over the lazy dog'), Buffer.alloc(0), Buffer.from('a')]
  return defineModule({
    name: `hmac.${algo}`,
    doc: `HMAC-${algo.toUpperCase()} over a key of a compile-time length`,
    inputs: [{ name: 'key', kind: 'bytes' }, { name: 'msg', kind: 'bytes' }],
    outputs: [{ name: 'mac', kind: 'bytes', width: A.width }],
    model,
    emit: (asm, params) => emitHmac(asm, { ...params, algo }, 'key', 'msg', 'mac'),
    cases: Object.entries(KEYS).flatMap(([kn, key]) => MSGS.map((msg, i) => ({
      name: `${kn} key (${key.length} B) / message ${i}`,
      inputs: { key, msg },
      params: { algo, keyLen: key.length }
    }))),
    notes: [
      'the key length is a compile-time parameter — it decides the padding, not a runtime branch',
      'a key longer than 64 bytes is hashed first, as RFC 2104 requires'
    ]
  })
}

const sha256 = macModule('sha256')
const sha1 = macModule('sha1')

module.exports = { sha256, sha1, emitHmac, BLOCK, IPAD, OPAD, ALGOS }
