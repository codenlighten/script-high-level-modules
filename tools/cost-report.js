'use strict'

// What every module costs, measured by emitting it. `--check` fails if the
// table in docs/cost.md no longer matches the code, so the documented numbers
// are derived rather than transcribed.

const fs = require('fs')
const path = require('path')
const { moduleSize } = require('../src/testkit')
const int = require('../src/modules/int')
const fp2 = require('../src/modules/fp2')
const fp6 = require('../src/modules/fp6')
const fp12 = require('../src/modules/fp12')
const g2mod = require('../src/modules/g2')
const BLS = require('../src/bls12381').P
const bytes = require('../src/modules/bytes')
const u32 = require('../src/modules/u32')
const sha256 = require('../src/modules/sha256')
const rsaMod = require('../src/modules/rsa')
const hmac = require('../src/modules/hmac')
const totp = require('../src/modules/totp')
const ec = require('../src/modules/ec')
const ecdsa = require('../src/modules/ecdsa')
const schnorrMod = require('../src/modules/schnorr')
const merkle = require('../src/modules/merkle')
const txmod = require('../src/modules/tx')
const stateMod = require('../src/modules/state')
const recipesMod = require('../src/recipes')
const crypto = require('crypto')
const mleaves = Array.from({ length: 8 }, (_, i) => crypto.createHash('sha256').update('leaf' + i).digest())
const mtree = merkle.tree(mleaves)

const key = rsaMod.fixtureKey()
const P256 = (1n << 256n) - 189n
const P2048 = (1n << 2048n) - 1557n

const ROWS = [
  ['int.modadd', int.modadd, { n: P2048 }, '2048-bit modulus'],
  ['int.modsub', int.modsub, { n: P2048 }, '2048-bit modulus'],
  ['int.modmul', int.modmul, { n: P2048 }, '2048-bit modulus'],
  ['int.modmul', int.modmul, { n: P256 }, '256-bit modulus'],
  ['int.modinv', int.modinv, { n: P256 }, '256-bit, witnessed'],
  ['fp2.mul', fp2.mul, { n: BLS }, 'BLS12-381, Karatsuba'],
  ['fp2.sqr', fp2.sqr, { n: BLS }, 'BLS12-381'],
  ['fp2.inv', fp2.inv, { n: BLS }, 'BLS12-381, witnessed'],
  ['fp6.mul', fp6.mul, { n: BLS }, 'BLS12-381'],
  ['fp12.mul', fp12.mul, { n: BLS }, 'BLS12-381'],
  ['fp12.sqr', fp12.sqr, { n: BLS }, 'BLS12-381'],
  ['fp12.cycSqr', fp12.cycSqr, { n: BLS }, 'BLS12-381, cyclotomic subgroup'],
  ['fp12.mulLine', fp12.mulLine, { n: BLS }, 'BLS12-381, a Miller-loop line'],
  ['g2.stepDouble', g2mod.stepDouble, { n: BLS }, 'a tangent and the point it moves to'],
  ['g2.stepAdd', g2mod.stepAdd, { n: BLS }, 'a chord and the point it moves to'],
  ['fp12.conj', fp12.conj, { n: BLS }, 'BLS12-381, the p⁶ Frobenius'],
  ['fp12.frob', fp12.frob, { n: BLS }, 'BLS12-381, f ↦ f^p'],
  ['fp12.inv', fp12.inv, { n: BLS }, 'BLS12-381, witnessed'],
  ['fp12.powX', fp12.powX, { n: BLS }, 'f^|x|, the final exponentiation ladder'],
  ['int.modexp', int.modexp, { n: P2048, e: 65537n }, 'e = 65537, 2048-bit'],
  ['int.modexp', int.modexp, { n: P2048, e: 3n }, 'e = 3, 2048-bit'],
  ['bytes.reverse', bytes.reverse, { width: 32 }, 'a 32-byte digest'],
  ['bytes.beToNum', bytes.beToNum, { width: 32 }, 'a 32-byte digest'],
  ['u32.rotr', u32.rotr, { k: 7 }, 'one rotation'],
  ['u32.xor', u32.xor, {}, 'one XOR'],
  ['u32.add', u32.add, {}, 'one addition mod 2³²'],
  ['u32.ch', u32.ch, {}, 'SHA-2 choose'],
  ['u32.maj', u32.maj, {}, 'SHA-2 majority'],
  ['sha256.Sigma1', u32.Sigma1, {}, 'one mixing function'],
  ['rsa.verify', rsaMod.verifier(key), { n: key.n, e: key.e, emLen: key.emLen }, 'RSA-2048, PKCS#1 v1.5'],
  ['hmac.sha256', hmac.sha256, { keyLen: 32 }, 'a 32-byte key'],
  ['hmac.sha1', hmac.sha1, { keyLen: 20 }, 'a 20-byte key'],
  ['totp.verify', totp.verify, { keyLen: 20, digits: 6 }, 'RFC 6238, 6 digits'],
  ['merkle.verify', merkle.verify(mtree.root, { depth: 3, leaves: mleaves }), { depth: 3, root: mtree.root }, 'depth 3 (8 leaves)'],
  ['merkle.verify', merkle.verify(mtree.root, { depth: 32, leaves: mleaves }), { depth: 32, root: mtree.root }, 'depth 32 (4 billion leaves)'],
  ['tx.locktime', txmod.locktime, {}, 'OP_PUSH_TX + nLockTime'],
  ['tx.hashOutputs', txmod.hashOutputs, {}, 'OP_PUSH_TX + the output commitment'],
  ['tx.transition', txmod.transition({ stateWidth: 8, fee: 200 }), { state: Buffer.alloc(8) }, 'a coin that recreates itself'],
  ['state.counter', stateMod.counter({ stateWidth: 8 }), {}, 'the successor is one higher'],
  ['tx.transitionPaying', txmod.transitionPaying({ stateWidth: 8, fee: 300 }), { state: Buffer.alloc(8) }, 'recreate itself and pay one output'],
  ['state.limit', stateMod.limit({ stateWidth: 8 }), {}, 'the allowance falls by what was paid'],
  ['ec.add', ec.add, {}, 'secp256k1, witnessed inverse'],
  ['ec.double', ec.double, {}, 'secp256k1, witnessed inverse'],
  ['ec.mulG', ec.mulG(256, [1n]), {}, 'k·G, 256-bit, base fixed'],
  ['ec.mul', ec.mul(256, [1n]), {}, 'k·P, 256-bit, both runtime'],
  ['ecdsa.verify', ecdsa.verifier([ecdsa.signCase('22'.repeat(32), 'x')]), {}, 'arbitrary message, secp256k1'],
  ['schnorr.liftX', schnorrMod.liftX, {}, 'x-only key to a point'],
  ['schnorr.verify', schnorrMod.verifier(['x']), {}, 'BIP-340, x-only key'],
  ['sha256.block', sha256.block, {}, 'one block, no OP_SHA256']
]

const measured = ROWS.map(([name, m, params, note]) => {
  const { bytes: b, ops } = moduleSize(m, params)
  return { name, note, bytes: b, ops }
})

const table = [
  '| module | configuration | Script bytes | opcodes |',
  '| --- | --- | ---: | ---: |',
  ...measured.map((r) => `| \`${r.name}\` | ${r.note} | ${r.bytes.toLocaleString()} | ${r.ops.toLocaleString()} |`)
].join('\n')

const NATIVE = 1                                   // OP_SHA256
const at = (n) => measured.find((r) => r.name === n).bytes
const rebuilt = at('sha256.block')
const rsaCost = at('rsa.verify')
const ecdsaCost = at('ecdsa.verify')
const FEE_SAT_PER_KB = 100                         // what this wallet pays; the reader can change it

const body = `<!-- generated by tools/cost-report.js — do not edit by hand -->
${table}

## What to read out of this

**\`rsa.verify\` is ${rsaCost.toLocaleString()} bytes.** A signature scheme Bitcoin has no
opcode for, at a size nobody needs to think about — because every operation RSA
needs is one Script opcode at any width.

**\`sha256.block\` is ${rebuilt.toLocaleString()} bytes** for one block: **${Math.round(rebuilt / NATIVE).toLocaleString()}×** what
\`OP_SHA256\` costs for the same answer. Same technique, four orders of magnitude
apart. The difference is only whether the primitive you need is already an
opcode — and 32-bit modular addition is not, so every one of them pays for two
endianness conversions.

**\`ecdsa.verify\` is ${ecdsaCost.toLocaleString()} bytes**, the most expensive thing here
by an order of magnitude, and the one worth justifying before use. It buys
something nothing else here does: an oracle signs with the secp256k1 key it
already has, over any message at all. Rabin verification is a few hundred bytes
and buys the same authenticity — with a key the oracle must hold specifically
for this purpose. That is the trade, and it is an engineering choice rather than
a technical limit.

At ${FEE_SAT_PER_KB} sat/KB, that most expensive module is about
${Math.ceil(ecdsaCost / 1000 * FEE_SAT_PER_KB)} satoshis of fee. Size stopped being the
question at Genesis; what it costs, and whether a cheaper construction buys the
same thing, is the question that replaced it.
`

// The README quotes a handful of these figures. It quoted them by hand until one
// of them went stale — sha256.block shrank when u32.add was fixed, and the
// README kept the old number through several commits. A number that is
// transcribed is a number that will eventually be wrong, so the README's table
// is generated between markers and checked with the rest.
const HEADLINE = [
  ['int.modmul', '2048-bit modulus'],
  ['int.modexp', 'e = 65537, 2048-bit'],
  ['rsa.verify', 'RSA-2048, PKCS#1 v1.5'],
  ['hmac.sha256', 'a 32-byte key'],
  ['totp.verify', 'RFC 6238, 6 digits'],
  ['tx.locktime', 'OP_PUSH_TX + nLockTime'],
  ['merkle.verify', 'depth 32 (4 billion leaves)'],
  ['ec.add', 'secp256k1, witnessed inverse'],
  ['fp2.mul', 'BLS12-381, Karatsuba'],
  ['fp12.mul', 'BLS12-381'],
  ['u32.add', 'one addition mod 2³²'],
  ['sha256.block', 'one block, no OP_SHA256'],
  ['ec.mul', 'k·P, 256-bit, both runtime'],
  ['ecdsa.verify', 'arbitrary message, secp256k1']
]

function readmeTable () {
  const rows = HEADLINE.map(([name, note]) => {
    const r = measured.find((x) => x.name === name && x.note === note)
    if (!r) throw new Error(`cost-report: the README wants ${name} / ${note}, which is not measured here`)
    return `| \`${r.name}\` | ${r.note.replace('OP_SHA256', '`OP_SHA256`')} | ${r.bytes.toLocaleString()} |`
  })
  return ['<!-- cost:table -->', '| module | configuration | Script bytes |', '| --- | --- | ---: |', ...rows, '<!-- /cost:table -->'].join('\n')
}

function syncReadme (check) {
  const file = path.join(__dirname, '..', 'README.md')
  const text = fs.readFileSync(file, 'utf8')
  const block = /<!-- cost:table -->[\s\S]*?<!-- \/cost:table -->/
  if (!block.test(text)) throw new Error('cost-report: the README has no <!-- cost:table --> markers')
  const next = text.replace(block, readmeTable())
  if (check) return next === text
  fs.writeFileSync(file, next)
  return true
}

// docs/index.md quotes three of these numbers in a sentence, and quoted them
// wrongly for a while — 955 where the table said 969, 59,141 where it said
// 59,191 — because a number written into prose is a number that will drift.
// The sentence is generated now, for the same reason the README's table is.
// docs/optimization.md's summary table had the same drift: it claimed ec.add was
// 139 bytes long after the missing-bound audit had made it 167. The BEFORE
// column is history and lives here as a constant; the AFTER column is measured,
// so the table cannot describe a version of the code that no longer exists.
const OPTIMIZED = [
  ['ec.add', 'secp256k1, witnessed inverse', 191],
  ['ec.double', 'secp256k1, witnessed inverse', 191],
  ['ec.mul', 'k·P, 256-bit, both runtime', 116127],
  ['ec.mulG', 'k·G, 256-bit, base fixed', 80216],
  ['ecdsa.verify', 'arbitrary message, secp256k1', 196778]
]

function optimizationTable () {
  const rows = OPTIMIZED.map(([name, note, before]) => {
    const r = measured.find((x) => x.name === name && x.note === note)
    if (!r) throw new Error(`cost-report: docs/optimization.md wants ${name} / ${note}, which is not measured here`)
    const pct = Math.round(((r.bytes - before) / before) * 100)
    return `| \`${name}\` | ${before.toLocaleString()} | ${r.bytes.toLocaleString()} | ${pct}% |`
  })
  return ['<!-- cost:optimized -->', '| | before | now | |', '| --- | ---: | ---: | ---: |',
    ...rows, '<!-- /cost:optimized -->'].join('\n')
}

function syncOptimization (check) {
  const file = path.join(__dirname, '..', 'docs', 'optimization.md')
  const text = fs.readFileSync(file, 'utf8')
  const block = /<!-- cost:optimized -->[\s\S]*?<!-- \/cost:optimized -->/
  if (!block.test(text)) throw new Error('cost-report: docs/optimization.md has no <!-- cost:optimized --> markers')
  const next = text.replace(block, optimizationTable())
  if (check) return next === text
  fs.writeFileSync(file, next)
  return true
}

function indexLine () {
  const of = (name) => {
    const r = measured.find((x) => x.name === name)
    if (!r) throw new Error(`cost-report: docs/index.md wants ${name}, which is not measured here`)
    return r.bytes.toLocaleString()
  }
  return ['<!-- cost:line -->',
    `RSA verification is ${of('rsa.verify')} bytes; SHA-256 rebuilt from primitives is ` +
    `${of('sha256.block')}; ECDSA over an arbitrary message is ${of('ecdsa.verify')}. Reading ` +
    'those three against each other is most of what there is to know about lowering an ' +
    'algorithm into Script.',
    '<!-- /cost:line -->'].join('\n')
}

function syncIndex (check) {
  const file = path.join(__dirname, '..', 'docs', 'index.md')
  const text = fs.readFileSync(file, 'utf8')
  const block = /<!-- cost:line -->[\s\S]*?<!-- \/cost:line -->/
  if (!block.test(text)) throw new Error('cost-report: docs/index.md has no <!-- cost:line --> markers')
  const next = text.replace(block, indexLine())
  if (check) return next === text
  fs.writeFileSync(file, next)
  return true
}

const out = path.join(__dirname, '..', 'docs', 'cost.md')
const check = process.argv.includes('--check')
const existing = fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : ''
const doc = `# What the modules cost\n\n${body}`

if (check) {
  if (existing !== doc) {
    console.log('cost-report: docs/cost.md is out of date — run `npm run cost`')
    process.exit(1)
  }
  if (!syncReadme(true)) {
    console.log('cost-report: the README table is out of date — run `npm run cost`')
    process.exit(1)
  }
  if (!syncIndex(true)) {
    console.log('cost-report: the docs/index.md cost line is out of date — run `npm run cost`')
    process.exit(1)
  }
  if (!syncOptimization(true)) {
    console.log('cost-report: the docs/optimization.md table is out of date — run `npm run cost`')
    process.exit(1)
  }
  console.log(`cost-report: docs/cost.md and the README match the code (${measured.length} modules)`)
} else {
  fs.writeFileSync(out, doc)
  syncReadme(false)
  syncIndex(false)
  syncOptimization(false)
  console.log(doc)
}
