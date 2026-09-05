'use strict'

const { defineModule } = require('../module')
const { emitReverse } = require('./bytes')

// 32-BIT WORD ARITHMETIC — the vocabulary SHA-2, HMAC, ChaCha, and every other
// ARX construction is written in.
//
// A word is four BIG-ENDIAN bytes, because that is how the standards define it,
// and because OP_LSHIFT and OP_RSHIFT already treat a byte string as a
// big-endian bit string of fixed width — measured, not assumed. So the shifts
// and the boolean operations are one opcode each.
//
// Addition is where it costs. Script adds NUMBERS, and a number is
// little-endian, so every add pays for two conversions and a reduction mod 2³².
// That asymmetry is the whole reason these modules report their sizes: it is
// what makes a hand-built SHA-256 expensive and OP_SHA256 (one byte) the right
// answer whenever the algorithm you need is the one Bitcoin already has.

const W = 4                                   // bytes per word
const word = (name) => ({ name, kind: 'bytes', width: W })
const beNum = (b) => b.readUInt32BE(0)
const beBuf = (v) => { const b = Buffer.alloc(W); b.writeUInt32BE(v >>> 0, 0); return b }

const WORDS = [
  Buffer.from('00000000', 'hex'), Buffer.from('ffffffff', 'hex'),
  Buffer.from('80000000', 'hex'), Buffer.from('00000001', 'hex'),
  Buffer.from('6a09e667', 'hex'), Buffer.from('12345678', 'hex')
]

/** rotr(x, k) = (x >>> k) | (x << (32−k)) — two shifts and an OR, no loop. */
function emitRotr (asm, k, inName, outName) {
  if (k < 1 || k > 31) throw new Error('u32.rotr: k must be 1..31')
  asm.pick(inName, '_hi'); asm.rshift(k, '_hi')
  asm.roll(inName); asm.lshift(32 - k, '_lo')
  return asm.or(outName)
}

const rotr = defineModule({
  name: 'u32.rotr',
  doc: 'rotate a 32-bit word right by a constant',
  inputs: [word('x')],
  outputs: [word('r')],
  model: ({ x }, { k }) => { const v = beNum(x); return { r: beBuf(((v >>> k) | (v << (32 - k))) >>> 0) } },
  emit: (asm, { k }) => emitRotr(asm, k, 'x', 'r'),
  cases: WORDS.flatMap((x) => [7, 17].map((k) => ({ name: `${x.toString('hex')} ⟳ ${k}`, inputs: { x }, params: { k } })))
})

const shr = defineModule({
  name: 'u32.shr',
  doc: 'shift a 32-bit word right by a constant, zero-filled',
  inputs: [word('x')],
  outputs: [word('r')],
  model: ({ x }, { k }) => ({ r: beBuf(beNum(x) >>> k) }),
  emit: (asm, { k }) => asm.rshift(k, 'r'),
  cases: WORDS.map((x) => ({ name: `${x.toString('hex')} ≫ 3`, inputs: { x }, params: { k: 3 } }))
})

const xor = defineModule({
  name: 'u32.xor',
  doc: 'x ⊕ y',
  inputs: [word('x'), word('y')],
  outputs: [word('r')],
  model: ({ x, y }) => ({ r: beBuf(beNum(x) ^ beNum(y)) }),
  emit: (asm) => asm.xor('r'),
  cases: [
    { name: 'ones ⊕ ones', inputs: { x: WORDS[1], y: WORDS[1] } },
    { name: 'const ⊕ zero', inputs: { x: WORDS[4], y: WORDS[0] } },
    { name: 'const ⊕ const', inputs: { x: WORDS[4], y: WORDS[5] } }
  ]
})

/**
 * (x + y) mod 2³² — the expensive one.
 *
 * Big-endian words in, big-endian word out, with the two little-endian
 * conversions and the reduction that Script's numeric model requires. Every
 * term is non-negative, so OP_MOD's truncation toward zero is harmless here —
 * which is worth stating, because it is not harmless one module over.
 */
const add = defineModule({
  name: 'u32.add',
  doc: '(x + y) mod 2³², big-endian words',
  inputs: [word('x'), word('y')],
  outputs: [word('r')],
  model: ({ x, y }) => ({ r: beBuf((beNum(x) + beNum(y)) >>> 0) }),
  emit: (asm) => {
    const zero = Buffer.from([0])
    emitReverse(asm, W, 'y', '_yle'); asm.data(zero, '_z1'); asm.cat('_yp'); asm.bin2num('_yn')
    emitReverse(asm, W, 'x', '_xle'); asm.data(zero, '_z2'); asm.cat('_xp'); asm.bin2num('_xn')
    asm.add('_sum')
    asm.num(1n << 32n, '_2p32'); asm.mod('_wrapped')
    // OP_NUM2BIN writes a SIGNED number, so a word with its top bit set does not
    // fit in four bytes — the interpreter refuses it as an impossible encoding.
    // Ask for five and split the sign byte off. (Every result below 2³¹ works
    // without this, which is exactly why the case list below now contains one
    // that is not.)
    asm.num2bin(W + 1, '_rle5')
    asm.splitAt(W, '_rle', '_sign')
    asm.drop()
    emitReverse(asm, W, '_rle', 'r')
  },
  cases: [
    { name: 'no carry', inputs: { x: WORDS[5], y: WORDS[3] } },
    { name: 'wraps', inputs: { x: WORDS[1], y: WORDS[3] } },
    { name: 'top bits set (the sign trap)', inputs: { x: WORDS[2], y: WORDS[2] } },
    { name: 'result ≥ 2³¹ (OP_NUM2BIN is signed)', inputs: { x: WORDS[2], y: WORDS[3] } },
    { name: 'result is 0xffffffff', inputs: { x: WORDS[1], y: WORDS[0] } },
    { name: 'zero', inputs: { x: WORDS[0], y: WORDS[0] } }
  ]
})

/** ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z) — SHA-2's "choose". */
const ch = defineModule({
  name: 'u32.ch',
  doc: 'ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)',
  inputs: [word('x'), word('y'), word('z')],
  outputs: [word('r')],
  model: ({ x, y, z }) => ({ r: beBuf((beNum(x) & beNum(y)) ^ (~beNum(x) & beNum(z))) }),
  emit: (asm) => {
    asm.pick('x', '_nx'); asm.invert('_nx')
    asm.roll('z'); asm.and('_nxz')
    asm.roll('x'); asm.roll('y'); asm.and('_xy')
    asm.xor('r')
  },
  cases: [
    { name: 'selects y', inputs: { x: WORDS[1], y: WORDS[4], z: WORDS[5] } },
    { name: 'selects z', inputs: { x: WORDS[0], y: WORDS[4], z: WORDS[5] } },
    { name: 'mixed', inputs: { x: WORDS[5], y: WORDS[4], z: WORDS[2] } }
  ]
})

/** maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z) — SHA-2's bitwise majority. */
const maj = defineModule({
  name: 'u32.maj',
  doc: 'maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)',
  inputs: [word('x'), word('y'), word('z')],
  outputs: [word('r')],
  model: ({ x, y, z }) => ({ r: beBuf((beNum(x) & beNum(y)) ^ (beNum(x) & beNum(z)) ^ (beNum(y) & beNum(z))) }),
  emit: (asm) => {
    asm.pick('x', '_x1'); asm.pick('y', '_y1'); asm.and('_xy')
    asm.pick('x', '_x2'); asm.pick('z', '_z1'); asm.and('_xz')
    asm.xor('_a')
    asm.roll('y'); asm.roll('z'); asm.and('_yz')
    asm.xor('_b')
    asm.roll('x'); asm.drop()                  // x is finished with
    asm.rename('r', 'bytes', W)
  },
  cases: [
    { name: 'all ones', inputs: { x: WORDS[1], y: WORDS[1], z: WORDS[1] } },
    { name: 'two of three', inputs: { x: WORDS[1], y: WORDS[1], z: WORDS[0] } },
    { name: 'mixed', inputs: { x: WORDS[4], y: WORDS[5], z: WORDS[2] } }
  ]
})

// ── SHA-256's four mixing functions, as compositions ────────────────────────
// Nothing new is introduced here: each is three of the modules above. This is
// what "a cryptographic library, not a new opcode" means in practice.

function sigma (name, doc, rots, shift) {
  return defineModule({
    name,
    doc,
    inputs: [word('x')],
    outputs: [word('r')],
    model: ({ x }) => {
      const v = beNum(x)
      const rot = (k) => ((v >>> k) | (v << (32 - k))) >>> 0
      const terms = rots.map(rot).concat(shift === undefined ? [] : [v >>> shift])
      return { r: beBuf(terms.reduce((a, b) => (a ^ b) >>> 0)) }
    },
    emit: (asm) => {
      asm.pick('x', '_t0'); emitRotr(asm, rots[0], '_t0', '_a')
      asm.pick('x', '_t1'); emitRotr(asm, rots[1], '_t1', '_b')
      asm.xor('_ab')
      if (shift === undefined) { asm.pick('x', '_t2'); emitRotr(asm, rots[2], '_t2', '_c') } else { asm.pick('x', '_t2'); asm.rshift(shift, '_c') }
      asm.xor('_abc')
      asm.roll('x'); asm.drop()
      asm.rename('r', 'bytes', W)
    },
    cases: WORDS.map((x) => ({ name: x.toString('hex'), inputs: { x } }))
  })
}

const sigma0 = sigma('sha256.sigma0', 'σ0(x) = rotr7 ⊕ rotr18 ⊕ shr3', [7, 18], 3)
const sigma1 = sigma('sha256.sigma1', 'σ1(x) = rotr17 ⊕ rotr19 ⊕ shr10', [17, 19], 10)
const Sigma0 = sigma('sha256.Sigma0', 'Σ0(x) = rotr2 ⊕ rotr13 ⊕ rotr22', [2, 13, 22])
const Sigma1 = sigma('sha256.Sigma1', 'Σ1(x) = rotr6 ⊕ rotr11 ⊕ rotr25', [6, 11, 25])

module.exports = { rotr, shr, xor, add, ch, maj, sigma0, sigma1, Sigma0, Sigma1, emitRotr, word, beNum, beBuf }
