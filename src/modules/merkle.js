'use strict'

const bsv = require('@smartledger/bsv')
const { defineModule } = require('../module')

// MERKLE PROOF VERIFICATION — the cheapest useful thing in this repository, and
// the one that shows what "already an opcode" is worth.
//
// A membership proof is a fold: hash the leaf with its sibling, hash that with
// the next sibling, and keep going until you have the root. Every step is one
// OP_CAT and one OP_HASH256, both of which Bitcoin does natively, so a proof of
// depth 32 — a tree of four billion leaves — is about a kilobyte.
//
// Compare `sha256.block`, which pays 49,181 bytes to compute one hash the
// interpreter would have done in a single byte. Same repository, same
// technique, opposite conclusion. Reach for what is already there.
//
// THE DIRECTION BYTE IS A WITNESS, AND IT NEEDS PINNING. OP_IF treats every
// non-zero value as true, so a direction byte of 2 branches exactly as 1 does.
// Without the b² = b constraint one proof has many valid unlocking scripts,
// each with a different txid. Six bytes a level.

const LEAF = 32

const HASHES = {
  hash256: { fn: (b) => bsv.crypto.Hash.sha256sha256(b), emit: (asm, out) => asm.hash256(out) },
  sha256: { fn: (b) => bsv.crypto.Hash.sha256(b), emit: (asm, out) => asm.sha256(out) }
}

/** Fold a leaf up its path. `dirs[i]` is 1 when the sibling is on the LEFT. */
function fold (leaf, path, dirs, algo = 'hash256') {
  const H = HASHES[algo].fn
  let node = Buffer.from(leaf)
  for (let i = 0; i < dirs.length; i++) {
    const sib = path.subarray(i * LEAF, (i + 1) * LEAF)
    node = H(dirs[i] ? Buffer.concat([sib, node]) : Buffer.concat([node, sib]))
  }
  return node
}

/** Build a tree over `leaves` and return the root and one leaf's proof. */
function tree (leaves, algo = 'hash256') {
  const H = HASHES[algo].fn
  let level = leaves.map((l) => Buffer.from(l))
  const levels = [level]
  while (level.length > 1) {
    const next = []
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i]; const b = level[i + 1] || level[i]      // odd node pairs with itself
      next.push(H(Buffer.concat([a, b])))
    }
    levels.push(next)
    level = next
  }
  return {
    root: level[0],
    levels,
    proof (index) {
      const path = []; const dirs = []
      let idx = index
      for (let d = 0; d < levels.length - 1; d++) {
        const sibIdx = idx ^ 1
        const sib = levels[d][sibIdx] || levels[d][idx]
        path.push(sib)
        dirs.push(idx & 1)                                        // 1 ⇒ sibling on the left
        idx >>= 1
      }
      return { path: Buffer.concat(path), dirs: Buffer.from(dirs) }
    }
  }
}

/**
 * Assert that `leaf` is in the tree with the given root.
 *
 * The root is a compile-time parameter — it is the commitment the coin is
 * locked to. The path and the directions arrive as two packed strings and are
 * required to be exactly used up, so no unread bytes ride along in the
 * unlocking script.
 */
function verify (root, { depth, algo = 'hash256', leaves } = {}) {
  const A = HASHES[algo]
  if (!A) throw new Error(`merkle: no hash '${algo}'`)
  const t = leaves ? tree(leaves, algo) : null

  return defineModule({
    name: 'merkle.verify',
    doc: `membership in a depth-${depth} tree, folded with ${algo === 'hash256' ? 'OP_HASH256' : 'OP_SHA256'}`,
    inputs: [
      { name: 'leaf', kind: 'bytes', width: LEAF, witness: true },
      { name: 'path', kind: 'bytes', witness: true },
      { name: 'dirs', kind: 'bytes', witness: true }
    ],
    outputs: [],
    hint: () => ({}),
    model: () => ({}),
    emit: (asm, params) => {
      const d = params.depth ?? depth
      asm.roll('leaf'); asm.rename('_node')
      for (let i = 0; i < d; i++) {
        // one sibling off the path, one byte off the directions
        asm.roll('path'); asm.splitAt(LEAF, '_sib', '_prest'); asm.rename('path')
        asm.roll('dirs'); asm.splitAt(1, '_db', '_drest'); asm.rename('dirs')
        asm.roll('_db'); asm.bin2num('_d')
        // a byte is not a bit until it is one: OP_IF would take 2 for true
        asm.pick('_d', '_dv'); asm.op('OP_DUP', 0, ['_dv2']); asm.mul('_dsq')
        asm.pick('_d', '_dc'); asm.numEqualVerify()

        asm.roll('_node'); asm.roll('_sib'); asm.roll('_d')
        asm.beginIf()
        asm.swap(); asm.cat('_node')                    // sibling on the left
        asm.elseBranch()
        asm.cat('_node')                                // sibling on the right
        asm.endIf()
        A.emit(asm, '_node')
      }
      asm.roll('path'); asm.num(0, '_e1'); asm.equalVerify()
      asm.roll('dirs'); asm.num(0, '_e2'); asm.equalVerify()
      asm.roll('_node'); asm.data(params.root ?? root, '_root'); asm.equalVerify()
    },
    attacks: (honest, params, name) => {
      const v = Buffer.from(honest[name])
      if (!v.length) return null
      const flipped = Buffer.from(v); flipped[0] ^= 0x01
      const out = [
        { label: `${name}: first byte changed`, value: flipped },
        { label: `${name}: truncated`, value: v.subarray(0, v.length - 1) },
        { label: `${name}: a byte appended`, value: Buffer.concat([v, Buffer.from([0])]) }
      ]
      if (name === 'dirs') {
        const two = Buffer.from(v); two[0] = 2                     // OP_IF would take this for 1
        out.push({ label: 'dirs: a direction byte of 2', value: two })
      }
      return out
    },
    // A tree of a random size and a random leaf in it — which is how the
    // odd-count rule, the one every independent implementation gets wrong, gets
    // exercised without anybody choosing to exercise it.
    fuzz: (rnd) => {
      const n = 1 + Math.floor(rnd() * 12)
      const ls = Array.from({ length: n }, (_, i) => require('crypto').createHash('sha256').update('fuzz' + i + rnd()).digest())
      const tt = tree(ls, algo)
      const i = Math.floor(rnd() * n)
      const { path, dirs } = tt.proof(i)
      return { inputs: { leaf: ls[i], path, dirs }, params: { root: tt.root, depth: dirs.length } }
    },
    cases: t
      ? leaves.map((leaf, i) => {
        const { path, dirs } = t.proof(i)
        return { name: `leaf ${i} of ${leaves.length}`, inputs: { leaf, path, dirs }, params: { root: t.root, depth: dirs.length } }
      }).concat([
        // the sibling of leaf 0 is not leaf 0
        (() => {
          const { path, dirs } = t.proof(0)
          return { name: 'a leaf that is not in the tree', refuse: 'the fold does not reach the root', inputs: { leaf: Buffer.alloc(LEAF, 0xcd), path, dirs }, params: { root: t.root, depth: dirs.length } }
        })(),
        // the right proof for the wrong position
        (() => {
          const { path } = t.proof(0)
          const { dirs } = t.proof(1)
          return { name: 'the right path with the wrong directions', refuse: 'a swapped concatenation hashes differently', inputs: { leaf: leaves[0], path, dirs }, params: { root: t.root, depth: dirs.length } }
        })()
      ])
      : [],
    notes: [
      'the root is the coin’s commitment: a compile-time parameter, not an input',
      'direction bytes are pinned to 0 or 1, or one proof would have many valid spends'
    ]
  })
}

module.exports = { verify, fold, tree, HASHES, LEAF }
