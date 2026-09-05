'use strict'

// What the interpreter ACTUALLY does — measured, not reasoned about. Every
// number in docs/limits.md comes from a run of this file.

const bsv = require('@smartledger/bsv')
const Op = bsv.Opcode
const { evaluate } = require('../src/run')
const { toNum, toLE, pushNum } = require('../src/num')

const results = []
function probe (name, build, expectOk = true) {
  const { unlock, lock, flags } = build()
  const r = evaluate(unlock, lock, flags === undefined ? {} : { flags })
  const pass = r.ok === expectOk
  results.push({ name, pass, ok: r.ok, error: r.error, lockSize: r.lockSize, opCount: r.opCount })
  console.log(`${pass ? 'ok  ' : 'FAIL'}  ${name.padEnd(52)} ${r.ok ? '' : '(' + String(r.error).slice(0, 60) + ')'}`)
  return r
}
const S = () => new bsv.Script()

// ── 1. big-number arithmetic ────────────────────────────────────────────────
// The whole premise: OP_MUL and OP_MOD on numbers wide enough for real crypto.
function modmul (bits) {
  const p = (1n << BigInt(bits)) - 1189n            // an arbitrary wide odd modulus
  const a = (1n << BigInt(bits - 3)) + 12345n
  const b = (1n << BigInt(bits - 5)) + 6789n
  const want = (a * b) % p
  return {
    unlock: S().add(pushNum(a)).add(pushNum(b)),
    lock: S().add(Op.OP_MUL).add(pushNum(p)).add(Op.OP_MOD).add(pushNum(want)).add(Op.OP_NUMEQUAL)
  }
}
for (const bits of [64, 256, 512, 1024, 2048, 4096]) probe(`OP_MUL/OP_MOD at ${bits} bits`, () => modmul(bits))

// ── 2. the sign bit, the classic wrong answer ───────────────────────────────
probe('a top-bit-set blob reads NEGATIVE without a 0x00 pad', () => ({
  unlock: S().add(Buffer.from('ff', 'hex')),
  lock: S().add(Op.OP_BIN2NUM).add(pushNum(-127n)).add(Op.OP_NUMEQUAL)
}))
probe('…and reads positive with one', () => ({
  unlock: S().add(Buffer.from('ff00', 'hex')),
  lock: S().add(Op.OP_BIN2NUM).add(pushNum(255n)).add(Op.OP_NUMEQUAL)
}))
probe('OP_BIN2NUM accepts a NON-minimal input under MINIMALDATA', () => ({
  unlock: S().add(Buffer.from('0100000000', 'hex')),
  lock: S().add(Op.OP_BIN2NUM).add(Op.OP_1).add(Op.OP_NUMEQUAL)
}))
probe('but a non-minimal PUSH read as a number is refused', () => ({
  unlock: S().add(Buffer.from('0100000000', 'hex')),
  lock: S().add(Op.OP_1).add(Op.OP_NUMEQUAL)
}), false)

// ── 3. fixed-width bytes ────────────────────────────────────────────────────
probe('OP_NUM2BIN pads to a chosen width', () => ({
  unlock: S().add(pushNum(1n)),
  lock: S().add(pushNum(32)).add(Op.OP_NUM2BIN).add(toLE(1n, 32)).add(Op.OP_EQUAL)
}))
probe('OP_NUM2BIN to 256 bytes (a 2048-bit register)', () => ({
  unlock: S().add(pushNum(1n)),
  lock: S().add(pushNum(256)).add(Op.OP_NUM2BIN).add(toLE(1n, 256)).add(Op.OP_EQUAL)
}))

// ── 4. bitwise ops, the hash-function primitives ────────────────────────────
probe('OP_XOR on equal-length strings', () => ({
  unlock: S().add(Buffer.from('f0f0f0f0', 'hex')).add(Buffer.from('ff00ff00', 'hex')),
  lock: S().add(Op.OP_XOR).add(Buffer.from('0ff00ff0', 'hex')).add(Op.OP_EQUAL)
}))
probe('OP_XOR on UNEQUAL lengths is refused', () => ({
  unlock: S().add(Buffer.from('f0f0f0f0', 'hex')).add(Buffer.from('ff00', 'hex')),
  lock: S().add(Op.OP_XOR).add(Op.OP_SIZE).add(Op.OP_NIP).add(pushNum(4)).add(Op.OP_NUMEQUAL)
}), false)
probe('OP_AND / OP_OR / OP_INVERT', () => ({
  unlock: S().add(Buffer.from('f0f0', 'hex')).add(Buffer.from('ff00', 'hex')),
  lock: S().add(Op.OP_AND).add(Buffer.from('f000', 'hex')).add(Op.OP_EQUAL)
}))
probe('OP_LSHIFT shifts the byte STRING, keeping its length', () => ({
  unlock: S().add(Buffer.from('01020304', 'hex')),
  lock: S().add(pushNum(8)).add(Op.OP_LSHIFT).add(Buffer.from('02030400', 'hex')).add(Op.OP_EQUAL)
}))
probe('OP_RSHIFT likewise', () => ({
  unlock: S().add(Buffer.from('01020304', 'hex')),
  lock: S().add(pushNum(8)).add(Op.OP_RSHIFT).add(Buffer.from('00010203', 'hex')).add(Op.OP_EQUAL)
}))
probe('OP_LSHIFT by a non-multiple of 8 (bit-level)', () => ({
  unlock: S().add(Buffer.from('0f0f', 'hex')),
  lock: S().add(pushNum(4)).add(Op.OP_LSHIFT).add(Buffer.from('f0f0', 'hex')).add(Op.OP_EQUAL)
}))

// ── 5. the stack cap is era-derived, and this repository is why ─────────────
// The pre-Genesis cap is 1000 elements across the main and alt stacks; Genesis
// removed it, replacing the element COUNT with a bound on the memory the two
// stacks occupy. This probe used to record the opposite, because the
// interpreter applied 1000 unconditionally and checked it once at the end of
// the script rather than after every opcode. Both were fixed in the library
// (see docs/limits.md); the probe now measures the corrected behaviour, and
// would go red again if it regressed.
function stackOf (n) {
  const unlock = S()
  for (let i = 0; i < n; i++) unlock.add(Op.OP_1)
  const lock = S()
  for (let i = 0; i < n - 1; i++) lock.add(Op.OP_DROP)
  return { unlock, lock }
}
const PRE_GENESIS = bsv.Script.Interpreter.SCRIPT_VERIFY_P2SH | bsv.Script.Interpreter.SCRIPT_VERIFY_STRICTENC

// The fix that makes the cap era-derived is newer than the published library, so
// the probe asks the interpreter what it is before asserting what it does. An
// older one is not a failure here — no module in this repository holds more than
// a few dozen stack elements — but the measurement genuinely differs, and
// reporting it as passing would be a lie either way it is written.
const ERA_DERIVED_STACK = typeof bsv.Script.Interpreter.prototype.maxStackSize === 'function'

probe('999 stack elements', () => stackOf(999))
if (ERA_DERIVED_STACK) {
  probe('1001 stack elements, post-Genesis', () => stackOf(1001))
  probe('5000 stack elements, post-Genesis', () => stackOf(5000))
  probe('…but 1001 is refused under pre-Genesis flags', () => {
    const unlock = S()
    for (let i = 0; i < 1001; i++) unlock.add(Op.OP_1)
    return { unlock, lock: S().add(Op.OP_1), flags: PRE_GENESIS }
  }, false)
} else {
  console.log('skip  post-Genesis stack cap — this @smartledger/bsv predates the era-derived')
  console.log('      limit (see docs/limits.md). Nothing here depends on it; the modules hold')
  console.log('      a few dozen stack elements, not a thousand.')
}
probe('one 100 KB element is fine', () => ({
  unlock: S().add(Buffer.alloc(100000, 7)),
  lock: S().add(Op.OP_SIZE).add(Op.OP_NIP).add(pushNum(100000)).add(Op.OP_NUMEQUAL)
}))

// ── 6. how far the op budget really goes ────────────────────────────────────
function chain (n) {
  const lock = S().add(Op.OP_1)
  for (let i = 0; i < n; i++) lock.add(Op.OP_1).add(Op.OP_ADD)
  return { unlock: S(), lock: lock.add(pushNum(n + 1)).add(Op.OP_NUMEQUAL) }
}
for (const n of [500, 5000, 50000]) {
  const r = probe(`${n} sequential opcodes`, () => chain(n))
  console.log(`        ${r.lockSize} bytes of Script, ${r.opCount} counted ops`)
}

const failed = results.filter((r) => !r.pass)
console.log(`\n${results.length - failed.length}/${results.length} probes behaved as documented`)
process.exit(failed.length ? 1 : 0)
