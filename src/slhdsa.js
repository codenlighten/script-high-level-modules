'use strict'

// SLH-DSA (FIPS 205) VERIFICATION, in plain JavaScript, from the standard.
//
// The post-quantum signature NIST standardised from SPHINCS+. Its security rests
// on nothing but the hash function — no discrete logarithm, no lattice, nothing
// a quantum computer is known to break beyond Grover's square root — and that is
// what makes it the natural first post-quantum signature for Bitcoin Script,
// which already has OP_SHA256.
//
// This file is the SPECIFICATION the Script modules are checked against, written
// algorithm by algorithm from FIPS 205 and named after it. It is checked in turn
// against @noble/post-quantum, an implementation that shares no code with it:
// tools/slhdsa-crosscheck.js requires noble's signatures to verify here and
// tampered ones not to.
//
// Only verification, and only the SHA2 instantiations. A verifier needs no
// secrets, and the SHAKE instantiations would need Keccak, which Script does not
// have.
//
// Every hash call is counted, because the count is what a Script verifier will
// cost — and because, after a Groth16 spend was refused for its validation
// time, the count is also what decides whether a node will accept one.

const crypto = require('crypto')

// ── parameter sets, FIPS 205 Table 2 ────────────────────────────────────────
const PARAMS = {
  'SLH-DSA-SHA2-128s': { n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lgw: 4, m: 30 },
  'SLH-DSA-SHA2-128f': { n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, lgw: 4, m: 34 },
  'SLH-DSA-SHA2-192s': { n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17, lgw: 4, m: 39 },
  'SLH-DSA-SHA2-192f': { n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33, lgw: 4, m: 42 },
  'SLH-DSA-SHA2-256s': { n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, lgw: 4, m: 47 },
  'SLH-DSA-SHA2-256f': { n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, lgw: 4, m: 49 }
}

/** The derived WOTS+ lengths, FIPS 205 §5 (equations 5.1–5.4). */
function derive (name) {
  const p = PARAMS[name]
  if (!p) throw new Error(`slhdsa: no parameter set ${name}`)
  const w = 1 << p.lgw
  const len1 = Math.ceil((8 * p.n) / p.lgw)
  const len2 = Math.floor(Math.log2(len1 * (w - 1)) / p.lgw) + 1
  const len = len1 + len2
  const sigBytes = p.n * (1 + p.k * (1 + p.a) + p.h + p.d * len)
  return { name, ...p, w, len1, len2, len, sigBytes, pkBytes: 2 * p.n }
}

// ── the counter ─────────────────────────────────────────────────────────────
const count = { F: 0, H: 0, T: 0, Hmsg: 0 }
const resetCount = () => { for (const k of Object.keys(count)) count[k] = 0 }

// ── byte helpers, FIPS 205 §4.4 ─────────────────────────────────────────────
/** toInt(X, n): big-endian. */
function toInt (X) { let t = 0n; for (const b of X) t = (t << 8n) | BigInt(b); return t }
/** toByte(x, n): big-endian, n bytes. */
function toByte (x, n) {
  const out = Buffer.alloc(n)
  let t = BigInt(x)
  for (let i = n - 1; i >= 0; i--) { out[i] = Number(t & 0xffn); t >>= 8n }
  return out
}
/** base_2b(X, b, out_len): Algorithm 4. */
function base2b (X, b, outLen) {
  let inIdx = 0; let bits = 0; let total = 0n
  const out = []
  const mask = (1n << BigInt(b)) - 1n
  for (let o = 0; o < outLen; o++) {
    while (bits < b) { total = (total << 8n) + BigInt(X[inIdx]); inIdx++; bits += 8 }
    bits -= b
    out.push(Number((total >> BigInt(bits)) & mask))
  }
  return out
}

// ── ADRS, FIPS 205 §4.2 and the compressed form of §11.2 ────────────────────
const TYPE = { WOTS_HASH: 0, WOTS_PK: 1, TREE: 2, FORS_TREE: 3, FORS_ROOTS: 4, WOTS_PRF: 5, FORS_PRF: 6 }

class ADRS {
  constructor (bytes) { this.b = bytes ? Buffer.from(bytes) : Buffer.alloc(32) }
  copy () { return new ADRS(this.b) }
  setLayerAddress (l) { this.b.writeUInt32BE(l, 0) }
  setTreeAddress (t) { toByte(t, 12).copy(this.b, 4) }
  setTypeAndClear (y) { this.b.writeUInt32BE(y, 16); this.b.fill(0, 20) }
  setKeyPairAddress (i) { this.b.writeUInt32BE(i, 20) }
  getKeyPairAddress () { return this.b.readUInt32BE(20) }
  setChainAddress (i) { this.b.writeUInt32BE(i, 24) }
  setTreeHeight (z) { this.b.writeUInt32BE(z, 24) }
  setHashAddress (i) { this.b.writeUInt32BE(i, 28) }
  setTreeIndex (i) { this.b.writeUInt32BE(i, 28) }
  getTreeIndex () { return this.b.readUInt32BE(28) }
  /** ADRSc: the 22 bytes the SHA2 instantiations hash (§11.2). */
  compressed () {
    return Buffer.concat([this.b.subarray(3, 4), this.b.subarray(8, 16), this.b.subarray(19, 20), this.b.subarray(20, 32)])
  }
}

// ── the hash functions, SHA2 instantiations, FIPS 205 §11.2 ─────────────────
//
// Security category 1 (n = 16) uses SHA-256 throughout. Categories 3 and 5
// use SHA-512 for H_msg, H and T_l; those are listed so the parameter table is
// complete, and refused by the functions below until a Script verifier exists
// for them — Script has OP_SHA256 and no SHA-512.
const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest()

function mgf1sha256 (seed, len) {
  const out = []
  for (let c = 0; out.length * 32 < len; c++) out.push(sha256(seed, toByte(c, 4)))
  return Buffer.concat(out).subarray(0, len)
}

function hashes (P) {
  if (P.n !== 16) throw new Error(`slhdsa: ${P.name} uses SHA-512 for H_msg, H and T_l; only category 1 (n = 16) is implemented`)
  const pad = Buffer.alloc(64 - P.n)
  const tweak = (seed, adrs, M) => sha256(seed, pad, adrs.compressed(), M).subarray(0, P.n)
  return {
    Hmsg: (R, seed, root, M) => { count.Hmsg++; return mgf1sha256(Buffer.concat([R, seed, sha256(R, seed, root, M)]), P.m) },
    F: (seed, adrs, M) => { count.F++; return tweak(seed, adrs, M) },
    H: (seed, adrs, M) => { count.H++; return tweak(seed, adrs, M) },
    T: (seed, adrs, M) => { count.T++; return tweak(seed, adrs, M) }
  }
}

// ── WOTS+, FIPS 205 §5 ──────────────────────────────────────────────────────
/** chain(X, i, s, PK.seed, ADRS): Algorithm 5. */
function chain (P, X, i, s, seed, adrs) {
  let tmp = X
  for (let j = i; j < i + s; j++) { adrs.setHashAddress(j); tmp = hashes(P).F(seed, adrs, tmp) }
  return tmp
}

/** The base-w digits a WOTS+ signature is checked against: message then checksum. */
function wotsDigits (P, M) {
  const msg = base2b(M, P.lgw, P.len1)
  let csum = 0
  for (const d of msg) csum += P.w - 1 - d
  csum = csum << ((8 - ((P.len2 * P.lgw) % 8)) % 8)
  return [...msg, ...base2b(toByte(csum, Math.ceil((P.len2 * P.lgw) / 8)), P.lgw, P.len2)]
}

/** wots_pkFromSig(sig, M, PK.seed, ADRS): Algorithm 8. */
function wotsPkFromSig (P, sig, M, seed, adrs) {
  const digits = wotsDigits(P, M)
  const tmp = []
  for (let i = 0; i < P.len; i++) {
    adrs.setChainAddress(i)
    tmp.push(chain(P, sig.subarray(i * P.n, (i + 1) * P.n), digits[i], P.w - 1 - digits[i], seed, adrs))
  }
  const pkAdrs = adrs.copy()
  pkAdrs.setTypeAndClear(TYPE.WOTS_PK)
  pkAdrs.setKeyPairAddress(adrs.getKeyPairAddress())
  return hashes(P).T(seed, pkAdrs, Buffer.concat(tmp))
}

// ── XMSS, FIPS 205 §6 ───────────────────────────────────────────────────────
/** A Merkle path from a leaf to a root, shared by XMSS and FORS. */
function climb (P, node, idx, auth, seed, adrs, height) {
  for (let k = 0; k < height; k++) {
    adrs.setTreeHeight(k + 1)
    const sibling = auth.subarray(k * P.n, (k + 1) * P.n)
    if (Math.floor(idx / 2 ** k) % 2 === 0) {
      adrs.setTreeIndex(adrs.getTreeIndex() / 2)
      node = hashes(P).H(seed, adrs, Buffer.concat([node, sibling]))
    } else {
      adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2)
      node = hashes(P).H(seed, adrs, Buffer.concat([sibling, node]))
    }
  }
  return node
}

/** xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS): Algorithm 11. */
function xmssPkFromSig (P, idx, sigXmss, M, seed, adrs) {
  adrs.setTypeAndClear(TYPE.WOTS_HASH)
  adrs.setKeyPairAddress(idx)
  const node = wotsPkFromSig(P, sigXmss.subarray(0, P.len * P.n), M, seed, adrs)
  adrs.setTypeAndClear(TYPE.TREE)
  adrs.setTreeIndex(idx)
  return climb(P, node, idx, sigXmss.subarray(P.len * P.n), seed, adrs, P.hp)
}

// ── the hypertree, FIPS 205 §7 ──────────────────────────────────────────────
/** ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root): Algorithm 13. */
function htVerify (P, M, sigHt, seed, idxTree, idxLeaf, root) {
  const xmssBytes = (P.hp + P.len) * P.n
  const adrs = new ADRS()
  adrs.setTreeAddress(idxTree)
  let node = xmssPkFromSig(P, idxLeaf, sigHt.subarray(0, xmssBytes), M, seed, adrs)
  let tree = idxTree
  for (let j = 1; j < P.d; j++) {
    const leaf = Number(tree % (1n << BigInt(P.hp)))
    tree >>= BigInt(P.hp)
    adrs.setLayerAddress(j)
    adrs.setTreeAddress(tree)
    node = xmssPkFromSig(P, leaf, sigHt.subarray(j * xmssBytes, (j + 1) * xmssBytes), node, seed, adrs)
  }
  return node.equals(root)
}

// ── FORS, FIPS 205 §8 ───────────────────────────────────────────────────────
/** fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS): Algorithm 17. */
function forsPkFromSig (P, sigFors, md, seed, adrs) {
  const indices = base2b(md, P.a, P.k)
  const roots = []
  for (let i = 0; i < P.k; i++) {
    const base = i * (P.a + 1) * P.n
    const sk = sigFors.subarray(base, base + P.n)
    adrs.setTreeHeight(0)
    adrs.setTreeIndex(i * 2 ** P.a + indices[i])
    const leaf = hashes(P).F(seed, adrs, sk)
    roots.push(climb(P, leaf, indices[i], sigFors.subarray(base + P.n, base + (P.a + 1) * P.n), seed, adrs, P.a))
  }
  const pkAdrs = adrs.copy()
  pkAdrs.setTypeAndClear(TYPE.FORS_ROOTS)
  pkAdrs.setKeyPairAddress(adrs.getKeyPairAddress())
  return hashes(P).T(seed, pkAdrs, Buffer.concat(roots))
}

// ── SLH-DSA verification, FIPS 205 §9 and §10 ───────────────────────────────
/** Split a digest into the FORS message and the two hypertree indices. */
function splitDigest (P, digest) {
  const mdLen = Math.ceil((P.k * P.a) / 8)
  const treeLen = Math.ceil((P.h - P.h / P.d) / 8)
  const leafLen = Math.ceil(P.h / P.d / 8)
  const md = digest.subarray(0, mdLen)
  const idxTree = toInt(digest.subarray(mdLen, mdLen + treeLen)) % (1n << BigInt(P.h - P.h / P.d))
  const idxLeaf = Number(toInt(digest.subarray(mdLen + treeLen, mdLen + treeLen + leafLen)) % (1n << BigInt(P.h / P.d)))
  return { md, idxTree, idxLeaf }
}

/** slh_verify_internal(M, SIG, PK): Algorithm 20. */
function verifyInternal (P, M, sig, pk) {
  if (sig.length !== P.sigBytes || pk.length !== P.pkBytes) return false
  const seed = pk.subarray(0, P.n)
  const root = pk.subarray(P.n)
  const R = sig.subarray(0, P.n)
  const forsEnd = P.n + P.k * (1 + P.a) * P.n
  const digest = hashes(P).Hmsg(R, seed, root, M)
  const { md, idxTree, idxLeaf } = splitDigest(P, digest)
  const adrs = new ADRS()
  adrs.setTreeAddress(idxTree)
  adrs.setTypeAndClear(TYPE.FORS_TREE)
  adrs.setKeyPairAddress(idxLeaf)
  const pkFors = forsPkFromSig(P, sig.subarray(P.n, forsEnd), md, seed, adrs)
  return htVerify(P, pkFors, sig.subarray(forsEnd), seed, idxTree, idxLeaf, root)
}

/** slh_verify(M, SIG, ctx, PK): Algorithm 24, the pure (non-prehash) form. */
function verify (name, M, sig, pk, ctx = Buffer.alloc(0)) {
  const P = derive(name)
  if (ctx.length > 255) return false
  const Mp = Buffer.concat([Buffer.from([0, ctx.length]), ctx, M])
  return verifyInternal(P, Mp, Buffer.from(sig), Buffer.from(pk))
}

/**
 * Every intermediate value of one verification, in the order a verifier meets
 * them — for building test cases for the pieces of a Script verifier, and for
 * finding which piece disagrees when the whole one does.
 */
function trace (name, M, sig, pk, ctx = Buffer.alloc(0)) {
  const P = derive(name)
  sig = Buffer.from(sig); pk = Buffer.from(pk)
  const Mp = Buffer.concat([Buffer.from([0, ctx.length]), ctx, Buffer.from(M)])
  const seed = pk.subarray(0, P.n)
  const root = pk.subarray(P.n)
  const R = sig.subarray(0, P.n)
  const forsEnd = P.n + P.k * (1 + P.a) * P.n
  const digest = hashes(P).Hmsg(R, seed, root, Mp)
  const { md, idxTree, idxLeaf } = splitDigest(P, digest)
  const adrs = new ADRS()
  adrs.setTreeAddress(idxTree)
  adrs.setTypeAndClear(TYPE.FORS_TREE)
  adrs.setKeyPairAddress(idxLeaf)
  const sigFors = sig.subarray(P.n, forsEnd)
  const pkFors = forsPkFromSig(P, sigFors, md, seed, adrs)
  const xmssBytes = (P.hp + P.len) * P.n
  const layers = []
  let node = pkFors
  let tree = idxTree
  let leaf = idxLeaf
  for (let j = 0; j < P.d; j++) {
    if (j > 0) { leaf = Number(tree % (1n << BigInt(P.hp))); tree >>= BigInt(P.hp) }
    const sigX = sig.subarray(forsEnd + j * xmssBytes, forsEnd + (j + 1) * xmssBytes)
    const a = new ADRS()
    a.setLayerAddress(j)
    a.setTreeAddress(tree)
    const out = xmssPkFromSig(P, leaf, sigX, node, seed, a)
    layers.push({ layer: j, M: node, sigX, leaf, tree, root: out })
    node = out
  }
  return { P, Mp, R, digest, md, idxTree, idxLeaf, sigFors, pkFors, layers, ok: node.equals(root) }
}

module.exports = {
  PARAMS, derive, verify, verifyInternal, count, resetCount, trace,
  toInt, toByte, base2b, ADRS, TYPE, hashes, mgf1sha256, sha256,
  chain, wotsDigits, wotsPkFromSig, climb, xmssPkFromSig, htVerify, forsPkFromSig, splitDigest
}
