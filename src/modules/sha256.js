'use strict'

const crypto = require('crypto')
const { defineModule, apply } = require('../module')
const u32 = require('./u32')

// SHA-256, REBUILT — from OP_AND, OP_XOR, OP_LSHIFT, OP_RSHIFT, OP_ADD, OP_MOD,
// OP_CAT and OP_SPLIT, with OP_SHA256 nowhere in it.
//
// Bitcoin already has OP_SHA256, and it costs one byte. This module is not a
// replacement for it; it is the CONTROL EXPERIMENT for the whole idea. If a
// compiler claims it can lower an algorithm that Script has no opcode for, the
// way to find out is to lower one whose right answer is independently known —
// then check the Script's output against OpenSSL's, byte for byte, and read off
// the price.
//
// The price is the point. Every module here reports its size, so the
// arithmetic of the claim is visible: what is cheap (bitwise work, shifts,
// anything Script does natively at any width) and what is not (32-bit modular
// addition, which pays for two endianness conversions every time).
//
// The register rotation a←b←c… costs nothing at all: the assembler tracks
// values by name, so a shuffle is a relabel, not an opcode.

const K = [
  '428a2f98', '71374491', 'b5c0fbcf', 'e9b5dba5', '3956c25b', '59f111f1', '923f82a4', 'ab1c5ed5',
  'd807aa98', '12835b01', '243185be', '550c7dc3', '72be5d74', '80deb1fe', '9bdc06a7', 'c19bf174',
  'e49b69c1', 'efbe4786', '0fc19dc6', '240ca1cc', '2de92c6f', '4a7484aa', '5cb0a9dc', '76f988da',
  '983e5152', 'a831c66d', 'b00327c8', 'bf597fc7', 'c6e00bf3', 'd5a79147', '06ca6351', '14292967',
  '27b70a85', '2e1b2138', '4d2c6dfc', '53380d13', '650a7354', '766a0abb', '81c2c92e', '92722c85',
  'a2bfe8a1', 'a81a664b', 'c24b8b70', 'c76c51a3', 'd192e819', 'd6990624', 'f40e3585', '106aa070',
  '19a4c116', '1e376c08', '2748774c', '34b0bcb5', '391c0cb3', '4ed8aa4a', '5b9cca4f', '682e6ff3',
  '748f82ee', '78a5636f', '84c87814', '8cc70208', '90befffa', 'a4506ceb', 'bef9a3f7', 'c67178f2'
].map((h) => Buffer.from(h, 'hex'))

const IV = ['6a09e667', 'bb67ae85', '3c6ef372', 'a54ff53a', '510e527f', '9b05688c', '1f83d9ab', '5be0cd19']
  .map((h) => Buffer.from(h, 'hex'))

// ── the composition helpers: every module reads COPIES and names its result ──
const add = (asm, x, y, out) => { asm.pick(x, '_ax'); asm.pick(y, '_ay'); apply(asm, u32.add, {}, ['_ax', '_ay'], [out]) }
const addConst = (asm, x, k, out) => { asm.pick(x, '_ax'); asm.data(k, '_ak'); apply(asm, u32.add, {}, ['_ax', '_ak'], [out]) }
const un = (asm, mod, x, out) => { asm.pick(x, '_ux'); apply(asm, mod, {}, ['_ux'], [out]) }
const tri = (asm, mod, x, y, z, out) => { asm.pick(x, '_tx'); asm.pick(y, '_ty'); asm.pick(z, '_tz'); apply(asm, mod, {}, ['_tx', '_ty', '_tz'], [out]) }

/** The compression of ONE 64-byte block against the fixed initial state. */
function emitCompress (asm, { rounds = 64 } = {}) {
  // 1. the block as sixteen big-endian words
  for (let i = 0; i < 15; i++) asm.splitAt(4, `w${i}`, '_blk')
  asm.rename('w15', 'bytes', 4)

  // 2. the message schedule: w[t] = σ1(w[t−2]) + w[t−7] + σ0(w[t−15]) + w[t−16]
  for (let t = 16; t < rounds; t++) {
    un(asm, u32.sigma0, `w${t - 15}`, '_s0')
    un(asm, u32.sigma1, `w${t - 2}`, '_s1')
    add(asm, `w${t - 16}`, '_s0', '_p1')
    add(asm, '_p1', `w${t - 7}`, '_p2')
    add(asm, '_p2', '_s1', `w${t}`)
    for (const dead of ['_s0', '_s1', '_p1', '_p2']) asm.discard(dead)
  }

  // 3. the working registers
  const reg = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
  reg.forEach((r, i) => asm.data(IV[i], r))

  // 4. the rounds
  for (let t = 0; t < rounds; t++) {
    un(asm, u32.Sigma1, 'e', '_S1')
    tri(asm, u32.ch, 'e', 'f', 'g', '_ch')
    add(asm, 'h', '_S1', '_t1a')
    add(asm, '_t1a', '_ch', '_t1b')
    addConst(asm, '_t1b', K[t], '_t1c')
    add(asm, '_t1c', `w${t}`, '_T1')

    un(asm, u32.Sigma0, 'a', '_S0')
    tri(asm, u32.maj, 'a', 'b', 'c', '_maj')
    add(asm, '_S0', '_maj', '_T2')

    add(asm, 'd', '_T1', '_e')
    add(asm, '_T1', '_T2', '_a')

    for (const dead of ['_S1', '_ch', '_t1a', '_t1b', '_t1c', '_S0', '_maj', '_T1', '_T2', 'h', 'd']) asm.discard(dead)
    // the shuffle: names only, no opcodes
    asm.relabel('g', 'h'); asm.relabel('f', 'g'); asm.relabel('e', 'f'); asm.relabel('_e', 'e')
    asm.relabel('c', 'd'); asm.relabel('b', 'c'); asm.relabel('a', 'b'); asm.relabel('_a', 'a')
  }

  // 5. add the initial state back in, and concatenate the digest
  reg.forEach((r, i) => { addConst(asm, r, IV[i], `_o${r}`); asm.discard(r) })
  for (let t = 0; t < rounds; t++) asm.discard(`w${t}`)
  asm.roll('_oa')
  for (const r of reg.slice(1)) { asm.roll(`_o${r}`); asm.cat('_digest') }
  asm.rename('digest', 'bytes', 32)
  return asm
}

/** The 64-byte block a short message becomes — the padding, done off chain. */
function pad (msg) {
  if (msg.length > 55) throw new Error('sha256.block: this module compresses ONE block; messages up to 55 bytes')
  const b = Buffer.alloc(64)
  msg.copy(b, 0)
  b[msg.length] = 0x80
  b.writeUInt32BE(msg.length * 8, 60)
  return b
}

const block = defineModule({
  name: 'sha256.block',
  doc: 'SHA-256 of one padded 64-byte block, built from primitives — no OP_SHA256',
  inputs: [{ name: 'blk', kind: 'bytes', width: 64 }],
  outputs: [{ name: 'digest', kind: 'bytes', width: 32 }],
  // The specification is OpenSSL's answer, not a reimplementation of the same
  // idea in JavaScript: a shared misreading of the standard would agree with
  // itself. The case supplies the block; the model hashes the message it padded.
  model: ({ blk }, { msg }) => ({ digest: crypto.createHash('sha256').update(msg).digest() }),
  emit: (asm, params) => emitCompress(asm, params),
  // A random message of a length one block holds, padded — the block itself
  // cannot be random, because the padding is what makes it a message.
  fuzz: (rnd) => {
    const msg = Buffer.from(Array.from({ length: Math.floor(rnd() * 56) }, () => Math.floor(rnd() * 256)))
    return { inputs: { blk: pad(msg) }, params: { msg } }
  },
  cases: [
    { name: 'the empty string', inputs: { blk: pad(Buffer.alloc(0)) }, params: { msg: Buffer.alloc(0) } },
    { name: '“abc”', inputs: { blk: pad(Buffer.from('abc')) }, params: { msg: Buffer.from('abc') } }
  ]
})

module.exports = { block, emitCompress, pad, K, IV }
