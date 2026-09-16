'use strict'

// WHERE THE BYTES ACTUALLY GO.
//
//   node tools/script-anatomy.js
//
// Every size in this repository is measured, and none of them says what the
// bytes are FOR. A pairing is 817,031 bytes — of what? The only datum was
// fp6.mul, where composition cost ×1.47 of the arithmetic it composed, and a
// factor measured on a 721-byte module is not evidence about a 333,000-byte one.
// The four modules that carry the pairing are measured whole precisely because
// that extrapolation was not trusted.
//
// So this attributes every emitted byte to the thing that emitted it:
//
//   arithmetic      OP_ADD, OP_SUB, OP_MUL, OP_MOD, OP_DIV
//   stack           OP_PICK, OP_ROLL, OP_SWAP, OP_DUP, OP_DROP and their indices
//   serialisation   OP_CAT, OP_SPLIT, OP_BIN2NUM, OP_NUM2BIN, OP_SIZE
//   hashing         the SHA/HASH/RIPEMD family
//   control         OP_VERIFY, OP_EQUALVERIFY, OP_IF, bounds
//   constants       pushed literals
//
// It changes nothing in src/. Asm.prototype is wrapped here, for the duration of
// the measurement, so what is measured is exactly what is deployed.
//
// TWO DETAILS THAT DECIDE WHETHER THE NUMBERS MEAN ANYTHING:
//
// 1. Attribution is to the INNERMOST emitter. asm.discard() calls roll() then
//    drop(); asm.bound() calls pick() and num(). Counting the outer call would
//    hide stack traffic inside "control". Inner wrappers finish first, so they
//    claim their chunks and outer ones take only what is left.
//
// 2. An index push is part of the stack cost. `4 OP_PICK` is two chunks and two
//    bytes, and OP_PICK alone is one — so counting opcodes rather than bytes
//    would understate deep access, which is exactly the thing worth finding.

const { Asm } = require('../src/asm')
const F = require('../src/facts')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')

const n = (x) => x.toLocaleString('en-US')
const P = bls.P

const CATEGORY = {
  num: 'constants',
  data: 'constants',
  pick: 'stack',
  roll: 'stack',
  swap: 'stack',
  nip: 'stack',
  drop: 'stack',
  discard: 'stack',
  toAlt: 'stack',
  fromAlt: 'stack',
  dropTo: 'stack',
  keep: 'stack',
  add: 'arithmetic',
  sub: 'arithmetic',
  mul: 'arithmetic',
  div: 'arithmetic',
  mod: 'arithmetic',
  min: 'arithmetic',
  max: 'arithmetic',
  cat: 'serialisation',
  splitAt: 'serialisation',
  split: 'serialisation',
  bin2num: 'serialisation',
  num2bin: 'serialisation',
  size: 'serialisation',
  sha1: 'hashing',
  sha256: 'hashing',
  hash256: 'hashing',
  hash160: 'hashing',
  ripemd160: 'hashing',
  equalVerify: 'control',
  equal: 'control',
  numEqualVerify: 'control',
  numEqual: 'control',
  verify: 'control',
  withinVerify: 'control',
  ltVerify: 'control',
  geVerify: 'control',
  bound: 'control',
  beginIf: 'control',
  elseBranch: 'control',
  endIf: 'control',
  xor: 'bitwise',
  and: 'bitwise',
  or: 'bitwise',
  invert: 'bitwise',
  lshift: 'bitwise',
  rshift: 'bitwise'
}

/** asm.op() takes the opcode by name, so it is categorised by what it names. */
const byName = (name) => {
  const s = String(name)
  if (/SWAP|ROT|DUP|OVER|PICK|ROLL|DROP|NIP|TUCK|TOALTSTACK|FROMALTSTACK/.test(s)) return 'stack'
  if (/ADD|SUB|MUL|DIV|MOD|NEGATE|ABS/.test(s)) return 'arithmetic'
  if (/CAT|SPLIT|BIN2NUM|NUM2BIN|SIZE/.test(s)) return 'serialisation'
  if (/SHA|HASH|RIPEMD/.test(s)) return 'hashing'
  return 'control'
}

/** The bytes a chunk encodes to: one for an opcode, prefix + payload for a push. */
function chunkBytes (c) {
  if (!c.buf) return 1
  const n = c.buf.length
  if (c.opcodenum < 76) return 1 + n // direct push
  if (c.opcodenum === 76) return 2 + n // PUSHDATA1
  if (c.opcodenum === 77) return 3 + n // PUSHDATA2
  return 5 + n // PUSHDATA4
}

/**
 * Wrap the emitter, run `fn`, and give back the script with every chunk tagged.
 *
 * The tags live outside the Asm instances, indexed by position in the chunk
 * list, so nothing about the emitted script changes — the same bytes come out
 * whether this is running or not.
 */
function measure (fn) {
  const tags = [] // chunk index → category
  const accesses = [] // one entry per OP_PICK/OP_ROLL: { depth, bytes }
  const saved = []

  const wrap = (method, category) => {
    const orig = Asm.prototype[method]
    if (typeof orig !== 'function') return
    saved.push([method, orig])
    Asm.prototype[method] = function (...args) {
      const start = this.s.chunks.length
      // The distance is read BEFORE the call, because roll() consumes the slot.
      let d
      if ((method === 'pick' || method === 'roll') && typeof args[0] === 'string') {
        try { d = this.has(args[0]) ? this.depth(args[0]) : undefined } catch (e) { d = undefined }
      }
      const out = orig.apply(this, args)
      const cat = category === '@op' ? byName(args[0]) : category
      let emitted = 0
      for (let i = start; i < this.s.chunks.length; i++) {
        emitted += chunkBytes(this.s.chunks[i])
        // Innermost wins: a nested call has already claimed its own chunks.
        if (tags[i] === undefined) tags[i] = cat
      }
      // ONE access per call, not one per chunk. `4 OP_PICK` is two chunks —
      // OP_4 carries no buffer, so counting opcode chunks counted it as an
      // access of its own and halved every shallow figure in the first version
      // of this report.
      if (d !== undefined) accesses.push({ how: method, depth: d, bytes: emitted })
      return out
    }
  }

  for (const [method, category] of Object.entries(CATEGORY)) wrap(method, category)
  wrap('op', '@op')

  let script
  try { script = fn() } finally {
    for (const [method, orig] of saved) Asm.prototype[method] = orig
  }

  const byCategory = {}
  let total = 0
  script.chunks.forEach((c, i) => {
    const b = chunkBytes(c)
    total += b
    const cat = tags[i] || 'unattributed'
    byCategory[cat] = (byCategory[cat] || 0) + b
  })
  return { script, total, byCategory, accesses }
}

/** A module emitted the way a composition emits it: the prime already on hand. */
function emitModule (m, params = {}) {
  const asm = new Asm()
  const reduced = F.range(0n, P)
  const slots = [{ name: '_s', kind: 'bytes', width: 1 },
    { name: 'p', kind: 'num', facts: F.range(P, P + 1n) }]
  slots.push(...m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width, facts: reduced })))
  asm.given(slots)
  m.emit(asm, { n: 'p', nn: P, ...params })
  return asm.script()
}

const BUCKETS = [[0, 1], [2, 3], [4, 16], [17, 63], [64, 255], [256, 1023], [1024, Infinity]]

function report (label, r) {
  console.log(`\n  ${label} — ${n(r.total)} bytes\n`)
  const rows = Object.entries(r.byCategory).sort((a, b) => b[1] - a[1])
  for (const [cat, bytes] of rows) {
    const pct = (bytes / r.total * 100)
    const bar = '█'.repeat(Math.max(0, Math.round(pct / 2)))
    console.log(`    ${cat.padEnd(15)} ${n(bytes).padStart(9)}  ${pct.toFixed(1).padStart(5)}%  ${bar}`)
  }

  const acc = r.accesses
  if (!acc.length) return
  const stackBytes = acc.reduce((s, a) => s + a.bytes, 0)

  // pick and roll are reported apart, because their cheap cases are different
  // and averaging them hides both. asm.pick() emits OP_DUP at depth 0 and
  // OP_OVER at 1; asm.roll() emits OP_SWAP at 1 and OP_ROT at 2 — one byte,
  // no index. Only an access that pushes an index can be made cheaper by
  // moving values closer, and mixing the two made the averages meaningless.
  console.log(`\n    stack access by distance — ${n(acc.length)} accesses, ${n(stackBytes)} bytes`)
  console.log(`      ${'how'.padEnd(6)} ${'distance'.padEnd(10)} ${'accesses'.padStart(10)} ${'bytes'.padStart(10)}   per access`)
  for (const how of ['pick', 'roll']) {
    for (const [lo, hi] of BUCKETS) {
      const inBucket = acc.filter((a) => a.how === how && a.depth >= lo && a.depth <= hi)
      if (!inBucket.length) continue
      const bytes = inBucket.reduce((s, a) => s + a.bytes, 0)
      const label = hi === Infinity ? `${lo}+` : `${lo}–${hi}`
      console.log(`      ${how.padEnd(6)} ${label.padEnd(10)} ${n(inBucket.length).padStart(10)} ${n(bytes).padStart(10)}   ${(bytes / inBucket.length).toFixed(2)} B`)
    }
  }
  console.log(`      deepest access: ${n(acc.reduce((m, a) => Math.max(m, a.depth), 0))}`)

  // THE CEILING FOR REARRANGEMENT ALONE, which is narrower than it first looks.
  //
  // An index below 17 pushes as OP_1..OP_16: one byte where a deeper one needs
  // two. So moving a value closer saves the index byte and nothing more — the
  // OP_PICK or OP_ROLL itself is paid either way, and it is 46% of the script.
  // An access already at two bytes cannot be improved by moving anything, and
  // one that emits OP_SWAP or OP_ROT is already free of index cost.
  const deep = acc.filter((a) => a.depth > 16)
  const saving = deep.reduce((s, a) => s + (a.bytes - 2), 0)
  console.log(`      ${n(deep.length)} accesses are deeper than 16, costing ${n(deep.reduce((s, a) => s + a.bytes, 0))} bytes`)
  console.log(`      bringing every one of them within 16 would save ${n(saving)} bytes — ${(saving / r.total * 100).toFixed(1)}% of the script`)
  console.log(`      the opcodes themselves are ${n(stackBytes - saving)} bytes and no rearrangement removes them`)
  console.log('      (an access can be made cheaper; it can only be removed by emitting differently)')
}

const targets = [
  ['the Miller loop, 63 rounds', () => emitModule(pairing.miller(pairing.FULL))],
  ['the final exponentiation', () => emitModule(pairing.finalExp)],
  ['a whole pairing', () => emitModule(pairing.full())]
]

console.log('\n  what the bytes are for')
for (const [label, build] of targets) report(label, measure(build))

console.log(`
  Attribution is to the innermost emitter, and an index push counts as part of
  the access that needed it. "unattributed" is anything a module wrote straight
  to the script rather than through a named Asm method; if it is large, this
  tool is measuring less than it claims to.
`)

// WHAT THE FIRST INVESTIGATION FOUND, so the next one starts further along.
//
// 82% of a pairing is stack traffic, and the single largest slot in it is the
// MODULUS: 27,008 of the Miller loop's 132,144 accesses are pick('p'), costing
// 88,716 bytes — 25.9% of the script. Its median depth is 98 and its maximum
// 182, so nearly every one of those pays a two- or three-byte index.
//
// The obvious remedy does not survive contact with the code:
//
//   · int.js already caches the modulus WITHIN a module — pushModulus() exists
//     for exactly that, and its comment says so. The two picks in modsub are
//     not redundant; each is consumed by the operation after it.
//
//   · Parking it on the alt-stack is not free. fp2, fp6 and fp12 already use
//     the alt-stack as their spill space, around almost every operation, so a
//     modulus left there sits underneath whatever the tower parked on top.
//
//   · A shallow copy WOULD survive: the stack height between consecutive p
//     accesses moves by a median of 1 slot, and not at all 38.8% of the time.
//     But only 12 of 27,008 accesses are within 16 today, because p sits at the
//     bottom of a ~100-slot working set that never shrinks. Keeping a copy near
//     the top means giving the tower a convention for where the modulus lives,
//     maintained across park/unpark — a change to fp2/fp6/fp12's calling
//     discipline, not a peephole.
//
// The measured ceiling for bringing every deep access within 16 is 42,322 bytes
// on the Miller loop, 12.4%, of which the modulus is 34,700. That is worth
// having and it is not worth risking byte-identity with 20 mainnet deployments
// to get in a hurry: the same 10% is available from one more transaction split,
// which costs nothing but a boundary.
//
// The larger number is the one to attack next: 132,144 accesses, of which the
// modulus is only a fifth. An access can be made cheaper by moving values; it
// can only be REMOVED by emitting differently.
