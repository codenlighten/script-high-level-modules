'use strict'

const bsv = require('@smartledger/bsv')
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { defineModule } = require('../module')
const { emitReverse } = require('./bytes')
const txmod = require('./tx')
const slh = require('../slhdsa')

// A POST-QUANTUM SIGNATURE, VERIFIED BY BITCOIN SCRIPT.
//
// SLH-DSA (FIPS 205), the stateless hash-based signature NIST standardised from
// SPHINCS+, at its smallest parameter set, SLH-DSA-SHA2-128s. Its security rests
// on SHA-256 alone, and Script has OP_SHA256 — so where a pairing had to be
// built out of 381-bit multiplications, this is built out of the opcode the
// scheme was designed around, a few thousand times.
//
//   public key   32 bytes, compiled into the locking script
//   signature    7,856 bytes, one push in the unlocking script
//   work         3,928 tweakable hashes in the worst case, unrolled
//
// THE SHAPE OF A VERIFICATION, FIPS 205 §9.
//
//     H_msg(R, PK.seed, PK.root, M)  →  a FORS message, a tree index, a leaf index
//     FORS: 14 trees of height 12    →  a FORS public key
//     7 XMSS layers, each a WOTS+ public key and a Merkle path of 9
//                                    →  a root, compared with PK.root
//
// Every hash is SHA-256(PK.seed ‖ 0⁴⁸ ‖ ADRSc ‖ input) truncated to 16 bytes. The
// 64-byte prefix is a constant of the public key, pushed once and picked; the
// 22-byte compressed address is assembled from pieces that are constant per
// layer, per chain or per tree, so what changes per hash is a byte or two.
//
// THE WORST CASE IS WHAT THE SCRIPT PAYS FOR. A WOTS+ chain runs from its digit
// to 15, and the digit comes from the message, so each chain is unrolled as 15
// guarded steps — `if digit ≤ j: hash with hash address j` — at fourteen bytes
// a step. That is most of the script. Tree hashes are fixed in number; only
// their left-right order depends on the index, and that is one OP_SWAP under an
// OP_IF.
//
// WHAT THE SPENDER CHOOSES is the signature, and nothing else. The public key,
// the parameter set and the context (empty) are fixed by the script. The
// signature's length is checked before anything reads it, so no byte of the
// push goes unread.
//
// Checked against src/slhdsa.js, which is checked against @noble/post-quantum.

const NAME = 'SLH-DSA-SHA2-128s'
const P = slh.derive(NAME)
const N = P.n
const XMSS_BYTES = (P.hp + P.len) * N
const FORS_BYTES = P.k * (P.a + 1) * N
const MD_BYTES = Math.ceil((P.k * P.a) / 8)
const TREE_BYTES = Math.ceil((P.h - P.h / P.d) / 8)
const LEAF_BYTES = Math.ceil(P.h / P.d / 8)
const TREE_BITS = P.h - P.h / P.d
const LEAF_BITS = P.h / P.d
if (P.m > 32) throw new Error('slhdsa: H_msg needs more than one MGF1 block for this parameter set')

const be4 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b }
let uid = 0
const fresh = (s) => `_q${s}${uid++}`

// ── small pieces ────────────────────────────────────────────────────────────

/** A copy of a number, as `w` big-endian bytes. The number must be below 2^(8w−1). */
function toBE (asm, num, w, out) {
  asm.pick(num, fresh('b'))
  asm.num2bin(w, fresh('le'))
  emitReverse(asm, w, asm.top().name, out)
}

/** A big-endian byte string, consumed, as a non-negative number. */
function bytesToNum (asm, name, width, out) {
  asm.roll(name)
  emitReverse(asm, width, name, fresh('r'))
  asm.data(Buffer.from([0]), fresh('z')); asm.cat(fresh('c'))
  asm.bin2num(out)
}

/** The first `width` bytes of a tape, named `out`; the rest keeps the tape's name. */
function take (asm, tape, width, out) {
  asm.roll(tape)
  asm.splitAt(width, out, fresh('rest'))
  asm.rename(tape)
}

/** Trunc_n(SHA-256(top of stack)). */
function tweak (asm, out) {
  asm.sha256(fresh('h'))
  txmod.left(asm, N, out)
}

/** Rename the top values — for the two arms of a branch that leave them swapped. */
function nameTop (asm, names) {
  names.forEach((nm, i) => { asm.stack[asm.stack.length - names.length + i].name = nm })
}

/** Require the byte string `name` to be exactly `width` bytes, leaving it. */
function exactSize (asm, name, width) {
  asm.pick(name, fresh('s'))
  asm.op('OP_SIZE', 0, [{ name: fresh('sz'), kind: 'num' }])
  asm.nip()
  asm.num(width, fresh('w'))
  asm.numEqualVerify()
}

// ── WOTS+ digits, FIPS 205 Algorithm 8 lines 1–9 ────────────────────────────
//
// Two digits per byte of M, most significant nibble first, then the checksum
// Σ(w − 1 − digit), shifted left so it fills whole bytes, as len₂ more digits.
// Leaves `${tag}d0` … `${tag}d${len−1}` on the stack and consumes M.
function emitDigits (asm, M, tag) {
  asm.num(0, `${tag}sum`)
  for (let b = 0; b < N; b++) {
    if (b < N - 1) take(asm, M, 1, `${tag}byte`)
    else { asm.roll(M); asm.rename(`${tag}byte`) }
    asm.roll(`${tag}byte`)
    asm.data(Buffer.from([0]), fresh('z')); asm.cat(fresh('c')); asm.bin2num(`${tag}bv`)
    asm.pick(`${tag}bv`, fresh('v')); asm.num(P.w, fresh('w')); asm.div(`${tag}d${2 * b}`)
    asm.roll(`${tag}bv`); asm.num(P.w, fresh('w')); asm.mod(`${tag}d${2 * b + 1}`)
    asm.pick(`${tag}d${2 * b}`, fresh('p')); asm.pick(`${tag}d${2 * b + 1}`, fresh('q')); asm.add(fresh('pq'))
    asm.roll(`${tag}sum`); asm.add(`${tag}sum`)
  }
  asm.num(P.len1 * (P.w - 1), fresh('max')); asm.roll(`${tag}sum`); asm.sub(`${tag}c`)
  const shift = (8 - ((P.len2 * P.lgw) % 8)) % 8
  const bits = 8 * Math.ceil((P.len2 * P.lgw) / 8)
  for (let i = 0; i < P.len2; i++) {
    const right = bits - P.lgw * (i + 1) - shift
    if (right < 0) throw new Error('slhdsa: a checksum digit wants a left shift, which this parameter set was not written for')
    asm.pick(`${tag}c`, fresh('c'))
    if (right > 0) { asm.num(1n << BigInt(right), fresh('sh')); asm.div(fresh('cs')) }
    asm.num(P.w, fresh('w')); asm.mod(`${tag}d${P.len1 + i}`)
  }
  asm.discard(`${tag}c`)
}

// ── a Merkle path, shared by XMSS and FORS: FIPS 205 Algorithms 11 and 17 ────
//
// `header` is the address up to and including its first word; each level
// appends the tree height and the index one level up. The index is a number on
// the stack, halved per level, and its parity before halving decides whether the
// node is the left child or the right.
function emitClimb (asm, { header, node, index, tape, height, tag }) {
  for (let k = 0; k < height; k++) {
    asm.pick(index, fresh('i')); asm.num(2, fresh('2')); asm.mod(`${tag}par`)
    asm.roll(index); asm.num(2, fresh('2')); asm.div(index)
    asm.pick(header, fresh('hd')); asm.data(be4(k + 1), fresh('ht')); asm.cat(fresh('h1'))
    toBE(asm, index, 4, fresh('ib')); asm.cat(`${tag}in`)
    take(asm, tape, N, `${tag}au`)
    asm.roll(node); asm.roll(`${tag}au`); asm.roll(`${tag}par`)
    asm.beginIf()
    asm.swap(); nameTop(asm, [`${tag}l`, `${tag}r`])           // odd: AUTH ‖ node
    asm.elseBranch()
    nameTop(asm, [`${tag}l`, `${tag}r`])                        // even: node ‖ AUTH
    asm.endIf()
    asm.cat(fresh('lr'))
    asm.roll(`${tag}in`); asm.swap(); asm.cat(fresh('full'))
    tweak(asm, node)
  }
}

// ── one XMSS layer: FIPS 205 Algorithm 11, with Algorithm 8 inside ──────────
//
// Consumes M and leaf, reads XMSS_BYTES off the tape, leaves tree and the tape.
function emitXmss (asm, { pre, M, sig, leaf, tree, layer, out }) {
  const t = `_L${layer}x${uid++}_`
  // PK.seed ‖ 0⁴⁸ ‖ layer ‖ tree address: the first 73 bytes of every hash here
  asm.pick(pre, fresh('p')); asm.data(Buffer.from([layer]), fresh('ly')); asm.cat(fresh('p1'))
  toBE(asm, tree, 8, fresh('tb')); asm.cat(`${t}lh`)
  toBE(asm, leaf, 4, `${t}kp`)
  // WOTS_HASH, keypair
  asm.pick(`${t}lh`, fresh('a')); asm.data(Buffer.from([slh.TYPE.WOTS_HASH]), fresh('ty')); asm.cat(fresh('a1'))
  asm.pick(`${t}kp`, fresh('k')); asm.cat(`${t}wh`)
  // WOTS_PK, keypair, zeros: the header T_len hashes the chain ends under
  asm.pick(`${t}lh`, fresh('a')); asm.data(Buffer.from([slh.TYPE.WOTS_PK]), fresh('ty')); asm.cat(fresh('a1'))
  asm.roll(`${t}kp`); asm.cat(fresh('a2')); asm.data(Buffer.alloc(8), fresh('z8')); asm.cat(`${t}acc`)

  emitDigits(asm, M, t)

  for (let i = 0; i < P.len; i++) {
    take(asm, sig, N, `${t}x`)
    // chain address i, and the three zero bytes of the hash address
    asm.pick(`${t}wh`, fresh('w')); asm.data(Buffer.concat([be4(i), Buffer.alloc(3)]), fresh('ca')); asm.cat(`${t}pc`)
    asm.roll(`${t}d${i}`)
    asm.roll(`${t}x`)
    // [chain prefix, digit, value]: hash address j runs from the digit to w − 2
    for (let j = 0; j < P.w - 1; j++) {
      asm.pick(`${t}d${i}`, fresh('dd'))
      asm.num(j, fresh('j'))
      asm.op('OP_LESSTHANOREQUAL', 2, [{ name: fresh('go'), kind: 'num' }])
      asm.beginIf()
      asm.pick(`${t}pc`, fresh('pc'))
      asm.data(Buffer.from([j]), fresh('ha')); asm.cat(fresh('ad'))
      asm.swap(); asm.cat(fresh('in'))
      tweak(asm, `${t}x`)
      asm.endIf()
    }
    asm.roll(`${t}acc`); asm.swap(); asm.cat(`${t}acc`)
    asm.discard(`${t}pc`); asm.discard(`${t}d${i}`)
  }
  asm.discard(`${t}wh`)
  asm.roll(`${t}acc`); tweak(asm, `${t}node`)

  // TREE, zero padding, then height and index per level
  asm.roll(`${t}lh`); asm.data(Buffer.from([slh.TYPE.TREE, 0, 0, 0, 0]), fresh('tt')); asm.cat(`${t}th`)
  asm.roll(leaf); asm.rename(`${t}ti`)
  emitClimb(asm, { header: `${t}th`, node: `${t}node`, index: `${t}ti`, tape: sig, height: P.hp, tag: t })
  asm.discard(`${t}th`); asm.discard(`${t}ti`)
  asm.roll(`${t}node`); asm.rename(out)
}

// ── FORS: FIPS 205 Algorithm 17 ─────────────────────────────────────────────
//
// Consumes md, reads FORS_BYTES off the tape, leaves leaf, tree and the tape.
function emitFors (asm, { pre, md, sig, leaf, tree, out }) {
  const t = `_F${uid++}_`
  bytesToNum(asm, md, MD_BYTES, `${t}N`)
  asm.pick(pre, fresh('p')); asm.data(Buffer.from([0]), fresh('ly')); asm.cat(fresh('p1'))
  toBE(asm, tree, 8, fresh('tb')); asm.cat(`${t}fb`)
  toBE(asm, leaf, 4, `${t}kp`)
  asm.pick(`${t}fb`, fresh('a')); asm.data(Buffer.from([slh.TYPE.FORS_TREE]), fresh('ty')); asm.cat(fresh('a1'))
  asm.pick(`${t}kp`, fresh('k')); asm.cat(`${t}fh`)
  asm.roll(`${t}fb`); asm.data(Buffer.from([slh.TYPE.FORS_ROOTS]), fresh('ty')); asm.cat(fresh('a1'))
  asm.roll(`${t}kp`); asm.cat(fresh('a2')); asm.data(Buffer.alloc(8), fresh('z8')); asm.cat(`${t}acc`)

  for (let i = 0; i < P.k; i++) {
    // indices = base_2b(md, a, k): the i-th a-bit field, most significant first
    const right = P.k * P.a - P.a * (i + 1)
    asm.pick(`${t}N`, fresh('n'))
    if (right > 0) { asm.num(1n << BigInt(right), fresh('sh')); asm.div(fresh('q')) }
    asm.num(1n << BigInt(P.a), fresh('m')); asm.mod(fresh('ix'))
    if (i > 0) { asm.num(BigInt(i) << BigInt(P.a), fresh('o')); asm.add(`${t}ti`) } else asm.rename(`${t}ti`)
    // the leaf: F under height 0 and index i·2^a + indices[i]
    take(asm, sig, N, `${t}sk`)
    asm.pick(`${t}fh`, fresh('h')); asm.data(Buffer.alloc(4), fresh('h0')); asm.cat(fresh('h1'))
    toBE(asm, `${t}ti`, 4, fresh('ib')); asm.cat(fresh('ad'))
    asm.roll(`${t}sk`); asm.cat(fresh('in'))
    tweak(asm, `${t}node`)
    emitClimb(asm, { header: `${t}fh`, node: `${t}node`, index: `${t}ti`, tape: sig, height: P.a, tag: t })
    asm.discard(`${t}ti`)
    asm.roll(`${t}acc`); asm.roll(`${t}node`); asm.cat(`${t}acc`)
  }
  asm.discard(`${t}N`); asm.discard(`${t}fh`)
  asm.roll(`${t}acc`); tweak(asm, out)
}

// ── the whole verification: FIPS 205 Algorithms 20 and 24 ───────────────────
//
// Consumes `msg` and `sig`, leaves nothing, and fails unless the signature is
// an SLH-DSA-SHA2-128s signature of msg under pk with the empty context.
function emitVerify (asm, pk, { msg = 'msg', sig = 'sig' } = {}) {
  pk = Buffer.from(pk)
  if (pk.length !== P.pkBytes) throw new Error(`slhdsa: a ${NAME} public key is ${P.pkBytes} bytes, given ${pk.length}`)
  const seed = pk.subarray(0, N)
  const root = pk.subarray(N)
  const t = `_V${uid++}_`

  exactSize(asm, sig, P.sigBytes)
  asm.data(Buffer.concat([seed, Buffer.alloc(64 - N)]), `${t}pre`)
  take(asm, sig, N, `${t}R`)

  // H_msg = MGF1-SHA-256(R ‖ PK.seed ‖ SHA-256(R ‖ PK.seed ‖ PK.root ‖ M′), m),
  // M′ = 0x00 ‖ |ctx| ‖ ctx ‖ M with the context empty
  asm.pick(`${t}R`, fresh('r')); asm.data(Buffer.concat([pk, Buffer.from([0, 0])]), fresh('pk')); asm.cat(fresh('rp'))
  asm.roll(msg); asm.cat(fresh('rpm')); asm.sha256(`${t}inner`)
  asm.roll(`${t}R`); asm.data(seed, fresh('sd')); asm.cat(fresh('rs'))
  asm.roll(`${t}inner`); asm.cat(fresh('rsi')); asm.data(Buffer.alloc(4), fresh('ctr')); asm.cat(fresh('mg'))
  asm.sha256(fresh('dg')); txmod.left(asm, P.m, `${t}dg`)

  take(asm, `${t}dg`, MD_BYTES, `${t}md`)
  take(asm, `${t}dg`, TREE_BYTES, `${t}tb`)
  bytesToNum(asm, `${t}tb`, TREE_BYTES, fresh('tn')); asm.num(1n << BigInt(TREE_BITS), fresh('tm')); asm.mod(`${t}tree`)
  bytesToNum(asm, `${t}dg`, LEAF_BYTES, fresh('ln')); asm.num(1n << BigInt(LEAF_BITS), fresh('lm')); asm.mod(`${t}leaf`)

  take(asm, sig, FORS_BYTES, `${t}sf`)
  emitFors(asm, { pre: `${t}pre`, md: `${t}md`, sig: `${t}sf`, leaf: `${t}leaf`, tree: `${t}tree`, out: `${t}M` })
  asm.discard(`${t}sf`)

  for (let j = 0; j < P.d; j++) {
    if (j > 0) {
      asm.pick(`${t}tree`, fresh('t')); asm.num(1n << BigInt(P.hp), fresh('hm')); asm.mod(`${t}leaf`)
      asm.roll(`${t}tree`); asm.num(1n << BigInt(P.hp), fresh('hd')); asm.div(`${t}tree`)
    }
    if (j < P.d - 1) take(asm, sig, XMSS_BYTES, `${t}sx`)
    else { asm.roll(sig); asm.rename(`${t}sx`) }
    emitXmss(asm, { pre: `${t}pre`, M: `${t}M`, sig: `${t}sx`, leaf: `${t}leaf`, tree: `${t}tree`, layer: j, out: `${t}M` })
    asm.discard(`${t}sx`)
  }

  asm.roll(`${t}M`); asm.data(root, fresh('root')); asm.equalVerify()
  asm.discard(`${t}tree`); asm.discard(`${t}pre`)
}

// ── forgeries ───────────────────────────────────────────────────────────────
/** A byte flipped in each region of a signature, and the wrong length both ways. */
function sigAttacks (honest, params, name) {
  const v = Buffer.from(honest[name])
  if (name !== 'sig') {
    const b = Buffer.from(v); b[0] ^= 0x01
    return [{ label: `${name}: a byte changed`, value: b }]
  }
  const forsEnd = N + FORS_BYTES
  const at = (label, i) => { const b = Buffer.from(v); b[i] ^= 0x01; return { label, value: b } }
  return [
    at('R changed', 0),
    at('a FORS secret changed', N),
    at('a FORS authentication node changed', N + N + 1),
    at('a WOTS+ chain value changed, layer 0', forsEnd + 3),
    at('an XMSS authentication node changed, layer 0', forsEnd + P.len * N + 1),
    at('a WOTS+ chain value changed, the top layer', forsEnd + (P.d - 1) * XMSS_BYTES + 2),
    at('the last byte changed', v.length - 1),
    { label: 'one byte short', value: v.subarray(0, v.length - 1) },
    { label: 'one byte long', value: Buffer.concat([v, Buffer.from([0])]) }
  ]
}

// ── modules ─────────────────────────────────────────────────────────────────
const preFor = (pk) => Buffer.concat([Buffer.from(pk).subarray(0, N), Buffer.alloc(64 - N)])

/** One XMSS layer, as a module — for proving the piece before the whole. */
function xmss (pk, { layer = 0, cases } = {}) {
  const seed = Buffer.from(pk).subarray(0, N)
  return defineModule({
    name: 'slhdsa.xmss',
    doc: `one ${NAME} hypertree layer: a WOTS+ public key from its signature, and the Merkle path to the layer's root`,
    inputs: [{ name: 'M', kind: 'bytes', width: N }, { name: 'sigX', kind: 'bytes', width: XMSS_BYTES }, 'leaf', 'tree'],
    outputs: [{ name: 'root', kind: 'bytes', width: N }],
    model: ({ M, sigX, leaf, tree }) => {
      const adrs = new slh.ADRS()
      adrs.setLayerAddress(layer)
      adrs.setTreeAddress(tree)
      return { root: slh.xmssPkFromSig(P, Number(leaf), Buffer.from(sigX), Buffer.from(M), seed, adrs) }
    },
    emit: (asm) => {
      exactSize(asm, 'sigX', XMSS_BYTES)
      asm.data(preFor(pk), '_pre')
      emitXmss(asm, { pre: '_pre', M: 'M', sig: 'sigX', leaf: 'leaf', tree: 'tree', layer, out: 'root' })
      asm.discard('sigX'); asm.discard('tree'); asm.discard('_pre')
      asm.roll('root')
    },
    cases: cases || []
  })
}

/** FORS, as a module. */
function fors (pk, { cases } = {}) {
  const seed = Buffer.from(pk).subarray(0, N)
  return defineModule({
    name: 'slhdsa.fors',
    doc: `the ${NAME} few-time signature: ${P.k} trees of height ${P.a}, compressed to a public key`,
    inputs: [{ name: 'md', kind: 'bytes', width: MD_BYTES }, { name: 'sigF', kind: 'bytes', width: FORS_BYTES }, 'leaf', 'tree'],
    outputs: [{ name: 'pkF', kind: 'bytes', width: N }],
    model: ({ md, sigF, leaf, tree }) => {
      const adrs = new slh.ADRS()
      adrs.setTreeAddress(tree)
      adrs.setTypeAndClear(slh.TYPE.FORS_TREE)
      adrs.setKeyPairAddress(Number(leaf))
      return { pkF: slh.forsPkFromSig(P, Buffer.from(sigF), Buffer.from(md), seed, adrs) }
    },
    emit: (asm) => {
      exactSize(asm, 'sigF', FORS_BYTES)
      asm.data(preFor(pk), '_pre')
      emitFors(asm, { pre: '_pre', md: 'md', sig: 'sigF', leaf: 'leaf', tree: 'tree', out: 'pkF' })
      asm.discard('sigF'); asm.discard('leaf'); asm.discard('tree'); asm.discard('_pre')
      asm.roll('pkF')
    },
    cases: cases || []
  })
}

/**
 * slhdsa.verify(pk): a signature over a message, against a key in the script.
 *
 * A predicate on a MESSAGE. Like every signature check here that is not bound
 * to a transaction, a coin locked to it alone is spendable by anyone who copies
 * the witness out of the first spend — use slhdsa.spend for a coin.
 */
function verifier (pk, { cases, maxWitnessAttacks = 9 } = {}) {
  return defineModule({
    name: 'slhdsa.verify',
    doc: `an ${NAME} signature (FIPS 205, empty context) over a message, under a public key fixed in the script`,
    inputs: [{ name: 'msg', kind: 'bytes' }, { name: 'sig', kind: 'bytes', witness: true }],
    outputs: [],
    maxWitnessAttacks,
    hint: () => ({}),
    model: () => ({}),
    attacks: sigAttacks,
    emit: (asm) => emitVerify(asm, pk),
    notes: [
      'the spender supplies only the signature; the key, the parameter set and the empty context are in the script',
      'the signature length is checked before any byte of it is read',
      'authorises a MESSAGE — slhdsa.spend binds one to the spending transaction'
    ],
    cases: cases || []
  })
}

/**
 * slhdsa.spend(pk): a coin that only an SLH-DSA signature over its OWN SPEND
 * can move.
 *
 * OP_PUSH_TX proves the pushed preimage is this transaction's, under
 * SIGHASH_ALL|FORKID; its double SHA-256 is the digest OP_CHECKSIG would sign;
 * and the script requires an SLH-DSA signature of that digest. Nothing about
 * spending the coin rests on elliptic-curve discrete logarithms.
 *
 * OP_PUSH_TX itself runs an OP_CHECKSIG, with a private key everybody knows.
 * What it establishes does not depend on that key being secret: it holds
 * because the signature is DERIVED from the pushed preimage, and a signature
 * derived from bytes that are not this transaction's sighash preimage does not
 * verify against this transaction. That is arithmetic about a fixed key, not a
 * hardness assumption about an unknown one.
 *
 * @param sign  (digest) → a signature, for the witness generator
 */
function spender (pk, { sign, cases, maxWitnessAttacks = 3 } = {}) {
  if (typeof sign !== 'function') throw new Error('slhdsa.spend: needs sign(digest) to produce its own witness')
  return defineModule({
    name: 'slhdsa.spend',
    doc: `a coin spendable only by an ${NAME} signature over its own spending transaction`,
    inputs: [{ name: 'preimage', kind: 'bytes', witness: true }, { name: 'sig', kind: 'bytes', witness: true }],
    outputs: [],
    contextual: true,
    maxWitnessAttacks,
    witnessFor: ({ tx, lockingScript, satoshis, inputIndex = 0 }) => {
      const g = PushTx.grind(tx, inputIndex, lockingScript, satoshis, { field: 'sequence' })
      const preimage = Buffer.from(g.preimage)
      return { preimage, sig: Buffer.from(sign(bsv.crypto.Hash.sha256sha256(preimage))) }
    },
    hint: () => ({}),
    model: () => ({}),
    attacks: (honest, params, name) => (name === 'preimage' ? txmod.preimageAttacks(honest, params, name) : sigAttacks(honest, params, name)),
    emit: (asm) => {
      txmod.emitAuthenticate(asm)
      asm.roll('preimage'); asm.hash256('msg')
      emitVerify(asm, pk, { msg: 'msg', sig: 'sig' })
    },
    notes: [
      'the signed message is the BIP-143 sighash digest, SIGHASH_ALL|FORKID — every input, output and amount',
      'no elliptic-curve key is needed to spend; OP_PUSH_TX\'s key is public and its role does not depend on secrecy'
    ],
    cases: cases || [{ name: 'signed by the key', spend: {} }]
  })
}

module.exports = {
  NAME, P, XMSS_BYTES, FORS_BYTES, MD_BYTES,
  emitVerify, emitXmss, emitFors, emitDigits, emitClimb, sigAttacks,
  xmss, fors, verifier, spender
}
