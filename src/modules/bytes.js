'use strict'

const { defineModule } = require('../module')

// BYTE-STRING MODULES — the layer between "a number Script can do arithmetic on"
// and "the byte order every cryptographic standard is written in".
//
// Script counts in LITTLE-ENDIAN. RSA, SHA-2, X9.62 and every standard document
// you will implement from count in BIG-ENDIAN. Somebody has to reverse the
// bytes, and doing it inline, differently, in each covenant is how the two
// conventions end up silently mixed. So it is a module, with cases.

/**
 * Reverse a byte string of a known width — the endianness bridge.
 *
 * Split the string into its bytes (each split leaves the remainder on top, so
 * the stack ends up holding them bottom-to-top in order), then swap-and-cat
 * pairs from the top down, which glues them back together in the reverse order.
 * 4(w−1) bytes of Script, no loop and no witness.
 */
function emitReverse (asm, width, inName, outName) {
  if (width < 1) throw new Error('reverse: width must be at least 1 byte')
  if (asm.top().name !== inName) asm.roll(inName)
  if (width === 1) return asm.rename(outName)
  for (let i = 0; i < width - 1; i++) asm.splitAt(1, `_b${i}`, `_rest${i}`)
  for (let i = 0; i < width - 1; i++) { asm.swap(); asm.cat(i === width - 2 ? outName : '_acc') }
  const t = asm.top(); t.kind = 'bytes'; t.width = width
  return asm
}

const reverse = defineModule({
  name: 'bytes.reverse',
  doc: 'big-endian ⇄ little-endian for a fixed width',
  inputs: [{ name: 'x', kind: 'bytes' }],
  outputs: [{ name: 'r', kind: 'bytes' }],
  model: ({ x }) => ({ r: Buffer.from(x).reverse() }),
  emit: (asm, { width }) => emitReverse(asm, width, 'x', 'r'),
  cases: [
    { name: '4 bytes', inputs: { x: Buffer.from('01020304', 'hex') }, params: { width: 4 } },
    { name: '1 byte', inputs: { x: Buffer.from('a1', 'hex') }, params: { width: 1 } },
    { name: '32 bytes (a digest)', inputs: { x: Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex') }, params: { width: 32 } },
    { name: '256 bytes (an RSA-2048 block)', inputs: { x: Buffer.alloc(256).map((_, i) => i & 0xff) }, params: { width: 256 } }
  ]
})

/**
 * A big-endian byte string as a Script number.
 *
 * Two conversions in one, and both are load-bearing: reverse to little-endian,
 * then append the 0x00 that stops the top bit being read as a sign. Omitting the
 * pad is the single most common way a covenant computes with a number that is
 * silently the negative of the one intended.
 */
const beToNum = defineModule({
  name: 'bytes.beToNum',
  doc: 'read a big-endian byte string as a non-negative Script number',
  inputs: [{ name: 'x', kind: 'bytes' }],
  outputs: ['r'],
  model: ({ x }) => {
    let v = 0n
    for (const byte of x) v = (v << 8n) | BigInt(byte)
    return { r: v }
  },
  emit: (asm, { width }) => {
    emitReverse(asm, width, 'x', '_le')
    asm.data(Buffer.from([0]), '_sign')
    asm.cat('_lep')
    asm.bin2num('r')
  },
  cases: [
    { name: '4 bytes', inputs: { x: Buffer.from('01020304', 'hex') }, params: { width: 4 } },
    { name: 'top bit set (the sign trap)', inputs: { x: Buffer.from('ff000000', 'hex') }, params: { width: 4 } },
    { name: '32 bytes', inputs: { x: Buffer.from('ff'.repeat(32), 'hex') }, params: { width: 32 } }
  ]
})

module.exports = { reverse, beToNum, emitReverse }
