'use strict'

// src/modules/merkle.js against the library's own block merkle tree — the code
// that decides whether a real block's merkle root is valid.
//
// The case that matters is an ODD number of leaves. Bitcoin pairs the last node
// with itself, and every independent implementation of that rule that has ever
// disagreed has disagreed here. So it is checked at every count from 1 to 17,
// not at a convenient power of two.

const bsv = require('@smartledger/bsv')
const crypto = require('crypto')
const merkle = require('../src/modules/merkle')

const leafFor = (i) => crypto.createHash('sha256').update('leaf' + i).digest()

let bad = 0
for (let n = 1; n <= 17; n++) {
  const leaves = Array.from({ length: n }, (_, i) => leafFor(i))
  const mine = merkle.tree(leaves).root
  // Drive the library's implementation with the leaves as the transaction hashes.
  const theirs = bsv.Block.prototype.getMerkleTree.call({
    transactions: leaves,
    getTransactionHashes: () => leaves.slice()
  })
  const root = theirs[theirs.length - 1]
  const ok = mine.equals(root)
  if (!ok) bad++
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${String(n).padStart(2)} leaves  ${mine.toString('hex').slice(0, 24)}…`)
}

// And the fold the Script module performs must reach the same root as the tree
// it came from — the two halves of the module agreeing with each other.
for (const n of [1, 2, 5, 8, 13]) {
  const leaves = Array.from({ length: n }, (_, i) => leafFor(i))
  const t = merkle.tree(leaves)
  for (let i = 0; i < n; i++) {
    const { path, dirs } = t.proof(i)
    const ok = merkle.fold(leaves[i], path, dirs).equals(t.root)
    if (!ok) { bad++; console.log(`FAIL  fold of leaf ${i} of ${n}`) }
  }
}
console.log(`\n${bad ? bad + ' FAILED' : 'the tree agrees with the library at every leaf count, and every proof folds to its root'}`)
process.exit(bad ? 1 : 0)
