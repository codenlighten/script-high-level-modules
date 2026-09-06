'use strict'

const bsv = require('@smartledger/bsv')
const Op = bsv.Opcode
const { pushNum, pushData } = require('./num')

// A stack-tracking assembler, so a module reads as DATA FLOW rather than as
// stack juggling.
//
// Every live value has a name and a kind. `num` is a value the arithmetic
// opcodes may read; `bytes` is a byte string of a known width. Keeping the two
// apart in the model is not pedantry — a `bytes` value handed to OP_ADD is read
// through the sign-magnitude rule and silently means something else, which is
// the single most expensive mistake in Script arithmetic. Asking for a `num`
// where a `bytes` sits is a build-time error here instead.
//
// The assembler is not separately unit-tested and does not need to be: a wrong
// depth or a wrong stack effect produces a script the real consensus
// interpreter rejects, and every module carries suites that would go red.

class Asm {
  constructor () {
    this.s = new bsv.Script()
    this.stack = []            // [{ name, kind, width }] bottom -> top
    this.alt = []              // the altstack, modelled the same way
    this._frames = []

    // HOW DEEP IT GOT.
    //
    // The interpreter caps the stack at 1000 elements, and that cap decides the
    // shape of anything with a large witness (docs/limits.md) — so a module's
    // peak depth is part of its cost, not a curiosity. It is recorded here
    // because the model is already exact: every emitting method goes through
    // `s.add`, so sampling there sees the depth after each opcode's effect on
    // the model has been applied by the previous one. `script()` samples once
    // more, so a peak reached by the last push is not missed.
    this.maxStack = 0
    this.maxAlt = 0

    // WHERE A VALUE CAME FROM, and whether it was ever bounded.
    //
    // A witnessed value owes canonicity, and the test kit establishes that by
    // ATTACKING it — which is evidence, and which is sampled once a module has
    // 136 witnesses. Sampling cannot say "every witness is bounded"; only
    // structure can. So each slot carries the input name it descends from
    // through picks, rolls and renames, and `bound()` records that origin.
    // tools/audit-soundness.js then checks the whole library exhaustively
    // rather than a sample of it.
    this.boundedOrigins = new Set()
    const add = this.s.add.bind(this.s)
    this.s.add = (chunk) => { this._peak(); return add(chunk) }
  }

  _peak () {
    if (this.stack.length > this.maxStack) this.maxStack = this.stack.length
    if (this.alt.length > this.maxAlt) this.maxAlt = this.alt.length
    return this
  }

  // ── introducing values ────────────────────────────────────────────────────
  /** Declare what the unlocking script (or a caller) has already left, bottom→top. */
  given (slots) { for (const v of slots) { const x = norm(v); x.origin = x.name; this.stack.push(x) } return this }
  /** A literal's range is known exactly, so it is recorded. */
  num (value, name, facts) {
    this.s.add(pushNum(value))
    const v = typeof value === 'bigint' ? value : BigInt(value)
    this.stack.push({ name, kind: 'num', facts: facts || { range: { lo: v, hi: v + 1n } } })
    return this
  }
  data (buf, name, facts) { this.s.add(pushData(buf)); this.stack.push({ name, kind: 'bytes', width: buf.length, facts }); return this }

  // ── inspecting the model ──────────────────────────────────────────────────
  top () { return this.stack[this.stack.length - 1] }
  has (name) { return this.stack.some((v) => v.name === name) }
  slot (name) {
    for (let i = this.stack.length - 1; i >= 0; i--) if (this.stack[i].name === name) return this.stack[i]
    throw new Error(`asm: '${name}' is not live [${this.stack.map((v) => v.name).join(', ')}]`)
  }
  depth (name) {
    for (let i = this.stack.length - 1; i >= 0; i--) if (this.stack[i].name === name) return this.stack.length - 1 - i
    throw new Error(`asm: '${name}' is not live [${this.stack.map((v) => v.name).join(', ')}]`)
  }
  /** Assert a value is of the kind an opcode is about to read it as. */
  wantNum (name) {
    const v = this.slot(name)
    if (v.kind !== 'num') throw new Error(`asm: '${name}' is ${v.kind}, but this reads it as a number — convert with bin2num() and mind the sign bit`)
    return v
  }

  // ── copying / moving ──────────────────────────────────────────────────────
  /** Copy `name` to the top under a new name. */
  pick (name, as) {
    const d = this.depth(name)
    if (d === 0) this.s.add(Op.OP_DUP)
    else if (d === 1) this.s.add(Op.OP_OVER)
    else this.s.add(pushNum(d)).add(Op.OP_PICK)
    const v = this.slot(name)
    this.stack.push({ ...v, name: as || name + "'" })
    return this
  }
  /** Move `name` to the top, consuming it from where it was. */
  roll (name) {
    const d = this.depth(name)
    if (d === 1) this.s.add(Op.OP_SWAP)
    else if (d === 2) this.s.add(Op.OP_ROT)
    else if (d > 2) this.s.add(pushNum(d)).add(Op.OP_ROLL)
    if (d !== 0) {
      for (let i = this.stack.length - 1; i >= 0; i--) {
        if (this.stack[i].name === name) { this.stack.push(this.stack.splice(i, 1)[0]); break }
      }
    }
    return this
  }
  /**
   * Record what is known about a live value, and say why.
   *
   * The framework derives what it can; this is for what it cannot. The reason
   * is required because an asserted fact is a claim nothing checks, and a claim
   * nothing checks should at least be one somebody wrote down.
   */
  assert (name, facts, why) {
    if (!why) throw new Error(`asm: assert('${name}') needs a reason — an unchecked claim with no argument for it is how the bounds went missing in the first place`)
    const slot = this.slot(name)
    slot.facts = require('./facts').meet(slot.facts, facts)
    slot.claimed = [...(slot.claimed || []), why]
    return this
  }

  /** What is known about a live value. */
  factsOf (name) { return this.slot(name).facts || {} }

  rename (name, kind, width) {
    const t = this.top()
    t.name = name
    if (kind) t.kind = kind
    if (width !== undefined) t.width = width
    return this
  }
  drop () { this.s.add(Op.OP_DROP); this.stack.pop(); return this }
  /** Move a value to the top and drop it — the explicit death of a temporary. */
  discard (name) { this.roll(name); return this.drop() }

  // ── the altstack ──────────────────────────────────────────────────────────
  // Not a second workspace so much as a place to put things that are in the
  // way. Its one useful property here is that a value parked there is not
  // counted in any OP_PICK depth on the main stack.
  toAlt () { this.s.add(Op.OP_TOALTSTACK); this.alt.push(this.stack.pop()); return this }
  fromAlt () { this.s.add(Op.OP_FROMALTSTACK); this.stack.push(this.alt.pop()); return this }

  /**
   * The floor of the region this module owns.
   *
   * `below` is how many of the values already on the stack belong to it — its
   * declared inputs. Everything from there up is the module's own business and
   * may be dropped; everything below belongs to the caller and must not be
   * touched.
   */
  mark (below = 0) { return this.stack.length - below }

  /**
   * Clear everything the module owns except `keep`, which is left on top in the
   * order given.
   *
   * The obvious way — roll each dead value to the top and drop it — costs three
   * bytes each: a depth push, OP_ROLL, OP_DROP. Parking the survivors on the
   * altstack instead lets the rest go with OP_2DROP, which takes two at a time
   * and needs no depth at all:
   *
   *   13 temporaries, 2 survivors:  39 bytes rolling,  11 bytes this way
   *
   * At 512 point operations in an elliptic-curve ladder that is 14 KB.
   */
  dropTo (floor, keep = []) {
    for (const n of keep) this.roll(n)
    const dead = this.stack.length - keep.length - floor
    if (dead < 0) throw new Error(`asm: dropTo would cut below the caller's values (${dead})`)
    if (dead === 0) return this
    for (let i = 0; i < keep.length; i++) this.toAlt()
    let d = dead
    while (d >= 2) { this.s.add(Op.OP_2DROP); this.stack.pop(); this.stack.pop(); d -= 2 }
    if (d === 1) this.drop()
    for (let i = 0; i < keep.length; i++) this.fromAlt()
    return this
  }
  /** Rename a live value IN PLACE. Emits nothing: a register shuffle that only
   *  moves names, like SHA-256's a..h rotation, costs no opcodes at all. */
  relabel (from, to) { this.slot(from).name = to; return this }
  nip () { this.s.add(Op.OP_NIP); const t = this.stack.pop(); this.stack[this.stack.length - 1] = t; return this }
  swap () {
    this.s.add(Op.OP_SWAP)
    const i = this.stack.length - 1
    ;[this.stack[i], this.stack[i - 1]] = [this.stack[i - 1], this.stack[i]]
    return this
  }
  /** Drop everything except the named values, which are left in the order given. */
  keep (names) {
    for (const n of names) this.roll(n)
    const keepSet = new Set(names)
    // after the rolls the kept values are the top |names|; drop what is beneath
    const below = this.stack.length - names.length
    for (let i = 0; i < below; i++) { this.roll(this.stack[this.stack.length - 1 - names.length].name); this.drop() }
    for (const v of this.stack) if (!keepSet.has(v.name)) throw new Error(`asm: keep() left '${v.name}' behind`)
    return this
  }

  // ── arithmetic (all consume their operands) ───────────────────────────────
  _bin (opcode, out, kind = 'num', derive) {
    const b = this.stack[this.stack.length - 1]
    const a = this.stack[this.stack.length - 2]
    this.s.add(opcode)
    this.stack.pop()
    this.stack[this.stack.length - 1] = { name: out, kind, facts: derive ? derive(a.facts, b.facts) : undefined }
    return this
  }

  // ── deriving what is known, rather than being told ────────────────────────
  //
  // A range on a value is only useful if it survives arithmetic. These are the
  // interval rules for the four operations the modules actually reason about,
  // and they are deliberately conservative: where a bound cannot be derived
  // soundly the result carries NO fact, and a module that needs one has to
  // assert it with a reason. Silence is the safe direction.
  //
  // `hi` is exclusive throughout, which is why the arithmetic below is off by
  // one in the places it is.
  add (out) { this._checkTop2Num(); return this._bin(Op.OP_ADD, out, 'num', ivAdd) }
  sub (out) { this._checkTop2Num(); return this._bin(Op.OP_SUB, out, 'num', ivSub) }
  mul (out) { this._checkTop2Num(); return this._bin(Op.OP_MUL, out, 'num', ivMul) }
  div (out) { this._checkTop2Num(); return this._bin(Op.OP_DIV, out) }
  mod (out) { this._checkTop2Num(); return this._bin(Op.OP_MOD, out, 'num', ivMod) }
  min (out) { return this._bin(Op.OP_MIN, out) }
  max (out) { return this._bin(Op.OP_MAX, out) }
  _checkTop2Num () {
    const a = this.stack[this.stack.length - 2]; const b = this.stack[this.stack.length - 1]
    for (const v of [a, b]) {
      if (v.kind !== 'num') throw new Error(`asm: '${v.name}' is ${v.kind}, but an arithmetic opcode is about to read it as a number`)
    }
  }

  // ── bytes ─────────────────────────────────────────────────────────────────
  cat (out) {
    const b = this.stack.pop(); const a = this.stack[this.stack.length - 1]
    const width = (a.width !== undefined && b.width !== undefined) ? a.width + b.width : undefined
    this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width }
    this.s.add(Op.OP_CAT)
    return this
  }
  /** Split the top item at a constant offset, leaving [lo, hi]. */
  splitAt (at, lo, hi) {
    const v = this.stack.pop()
    this.s.add(pushNum(at)).add(Op.OP_SPLIT)
    this.stack.push({ name: lo, kind: 'bytes', width: at })
    this.stack.push({ name: hi, kind: 'bytes', width: v.width === undefined ? undefined : v.width - at })
    return this
  }
  /** Split the top item at an index taken FROM THE STACK — a runtime offset,
   *  which is what dynamic truncation (RFC 4226) needs and a constant cannot do. */
  split (lo, hi) {
    this.stack.pop()                              // the index
    const v = this.stack.pop()                    // the buffer
    this.s.add(Op.OP_SPLIT)
    this.stack.push({ name: lo, kind: 'bytes' })
    this.stack.push({ name: hi, kind: 'bytes', width: v.width })   // width unknown until split
    this.stack[this.stack.length - 1].width = undefined
    return this
  }
  bin2num (out) {
    this.s.add(Op.OP_BIN2NUM)
    this.stack[this.stack.length - 1] = { name: out, kind: 'num' }
    return this
  }
  num2bin (width, out) {
    // The width is pushed as a literal and consumed by the opcode, so it never
    // enters the model: one value in, one value out.
    this.s.add(pushNum(width)).add(Op.OP_NUM2BIN)
    this.stack.pop()
    this.stack.push({ name: out, kind: 'bytes', width })
    return this
  }
  xor (out) { return this._bitwise(Op.OP_XOR, out) }
  and (out) { return this._bitwise(Op.OP_AND, out) }
  or (out) { return this._bitwise(Op.OP_OR, out) }
  invert (out) { const t = this.top(); this.s.add(Op.OP_INVERT); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: t.width }; return this }
  _bitwise (opcode, out) {
    const b = this.stack.pop(); const a = this.stack[this.stack.length - 1]
    if (a.width !== undefined && b.width !== undefined && a.width !== b.width) {
      throw new Error(`asm: bitwise op on '${a.name}' (${a.width}B) and '${b.name}' (${b.width}B) — the interpreter refuses unequal lengths`)
    }
    this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: a.width }
    this.s.add(opcode)
    return this
  }
  /** Bit-shift the byte STRING left/right by a constant, keeping its width. */
  lshift (bits, out) { const t = this.top(); this.s.add(pushNum(bits)).add(Op.OP_LSHIFT); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: t.width }; return this }
  rshift (bits, out) { const t = this.top(); this.s.add(pushNum(bits)).add(Op.OP_RSHIFT); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: t.width }; return this }
  size (out) { this.s.add(Op.OP_SIZE); this.stack.push({ name: out, kind: 'num' }); return this }
  sha1 (out) { this.s.add(Op.OP_SHA1); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: 20 }; return this }
  sha256 (out) { this.s.add(Op.OP_SHA256); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: 32 }; return this }
  hash256 (out) { this.s.add(Op.OP_HASH256); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: 32 }; return this }
  hash160 (out) { this.s.add(Op.OP_HASH160); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: 20 }; return this }
  ripemd160 (out) { this.s.add(Op.OP_RIPEMD160); this.stack[this.stack.length - 1] = { name: out, kind: 'bytes', width: 20 }; return this }

  // ── assertions (consume) ──────────────────────────────────────────────────
  equalVerify () { this.s.add(Op.OP_EQUALVERIFY); this.stack.pop(); this.stack.pop(); return this }
  // A comparison yields 0 or 1, always. That is the framework's own knowledge,
  // not a module's claim, and it is what lets a selector built from bits be
  // reduced without a bound check at every step.
  equal (out) { this.s.add(Op.OP_EQUAL); this.stack.pop(); this.stack[this.stack.length - 1] = { name: out || 'eq', kind: 'num', facts: BOOL }; return this }
  numEqualVerify () { this.s.add(Op.OP_NUMEQUALVERIFY); this.stack.pop(); this.stack.pop(); return this }
  numEqual (out) { this.s.add(Op.OP_NUMEQUAL); this.stack.pop(); this.stack[this.stack.length - 1] = { name: out || 'eq', kind: 'num' }; return this }
  verify () { this.s.add(Op.OP_VERIFY); this.stack.pop(); return this }
  /**
   * OP_WITHIN: assert min ≤ x < max, consuming all three.
   *
   * One opcode for the pair of comparisons every witnessed inverse needs. The
   * two-comparison form is eleven bytes; this is seven, and there are 512 of
   * them in an elliptic-curve ladder.
   */
  withinVerify () { this.s.add(Op.OP_WITHIN).add(Op.OP_VERIFY); this.stack.pop(); this.stack.pop(); this.stack.pop(); return this }
  /**
   * Assert min ≤ name < max IN SCRIPT, and record it as known.
   *
   * The difference between this and `assert()` is the whole point: this one
   * emits the check, so the fact it records is established rather than claimed.
   */
  bound (name, lo, hi, temp = '_b') {
    const F = require('./facts')
    this.pick(name, temp + 'v')
    F.pushBound(this, BigInt(lo), temp + 'lo')
    F.pushBound(this, BigInt(hi), temp + 'hi')
    this.withinVerify()
    const v = this.slot(name)
    v.facts = F.meet(v.facts, F.range(lo, hi))
    if (v.origin) this.boundedOrigins.add(v.origin)
    return this
  }

  /** 2nd < top, consuming both. */
  ltVerify () { this.s.add(Op.OP_LESSTHAN).add(Op.OP_VERIFY); this.stack.pop(); this.stack.pop(); return this }
  geVerify () { this.s.add(Op.OP_GREATERTHANOREQUAL).add(Op.OP_VERIFY); this.stack.pop(); this.stack.pop(); return this }

  // ── branches ──────────────────────────────────────────────────────────────
  beginIf () {
    this.s.add(Op.OP_IF); this.stack.pop()
    this._frames.push({ snap: this.stack.map((v) => ({ ...v })), altSnap: this.alt.map((v) => ({ ...v })), ifEnd: null })
    return this
  }
  elseBranch () {
    this.s.add(Op.OP_ELSE)
    const f = this._frames[this._frames.length - 1]
    f.ifEnd = this.stack.map((v) => ({ ...v }))
    f.altEnd = this.alt.map((v) => ({ ...v }))
    this.stack = f.snap.map((v) => ({ ...v }))
    this.alt = f.altSnap.map((v) => ({ ...v }))
    return this
  }
  endIf () {
    this.s.add(Op.OP_ENDIF)
    const f = this._frames.pop()
    const other = f.ifEnd || f.snap
    if (other.length !== this.stack.length) {
      throw new Error(`asm: IF/ELSE branches leave different depths (${other.length} vs ${this.stack.length})`)
    }
    // Equal depth is not enough. If the two branches leave the same values in
    // different NAMES, the model after the branch describes only one of them,
    // and every depth computed from it afterwards is wrong on the other path.
    // Both branches must agree on what is where.
    const otherAlt = f.ifEnd ? f.altEnd : f.altSnap
    if (otherAlt.length !== this.alt.length) {
      throw new Error(`asm: IF/ELSE branches leave different ALTSTACK depths (${otherAlt.length} vs ${this.alt.length})`)
    }
    for (let i = 0; i < other.length; i++) {
      if (other[i].name !== this.stack[i].name) {
        throw new Error(`asm: IF/ELSE branches disagree at depth ${this.stack.length - 1 - i}: ` +
          `'${other[i].name}' vs '${this.stack[i].name}' — relabel both to the same name before OP_ENDIF`)
      }
    }
    return this
  }

  /**
   * Run a helper that appends to the raw bsv.Script, with a declared stack
   * effect. The escape hatch for code that is not written against this
   * assembler — the library's OP_PUSH_TX core, for instance.
   */
  clause (fn, pop = 0, push = []) {
    fn(this.s)
    for (let i = 0; i < pop; i++) this.stack.pop()
    for (const v of push) this.stack.push(norm(v))
    return this
  }

  /** Any opcode in the release, with an explicit stack effect. The escape hatch. */
  op (name, pop = 0, push = []) {
    this.s.add(require('./opcodes').opcode(name))
    for (let i = 0; i < pop; i++) this.stack.pop()
    for (const v of push) this.stack.push(norm(v))
    return this
  }

  script () { this._peak(); return this.s }
  size_ () { return this.s.toBuffer().length }
  toString () {
    const show = (xs) => xs.map((v) => `${v.name}:${v.kind}${v.width !== undefined ? '[' + v.width + ']' : ''}`).join(' ')
    return show(this.stack) + (this.alt.length ? ` | alt: ${show(this.alt)}` : '')
  }
}

// Interval rules. Each returns undefined — "nothing is known" — rather than a
// bound it cannot justify.
const iv = (f) => (f && f.range) || null
const BOOL = { range: { lo: 0n, hi: 2n } }

function ivAdd (a, b) {
  const x = iv(a); const y = iv(b)
  if (!x || !y) return undefined
  return { range: { lo: x.lo + y.lo, hi: x.hi + y.hi - 1n } }
}
function ivSub (a, b) {
  const x = iv(a); const y = iv(b)
  if (!x || !y) return undefined
  return { range: { lo: x.lo - (y.hi - 1n), hi: x.hi - y.lo } }
}
function ivMul (a, b) {
  const x = iv(a); const y = iv(b)
  if (!x || !y) return undefined
  if (x.lo < 0n || y.lo < 0n) return undefined            // sign flips, so the corners are not the extremes
  return { range: { lo: x.lo * y.lo, hi: (x.hi - 1n) * (y.hi - 1n) + 1n } }
}
/**
 * OP_MOD is TRUNCATED, so it keeps the sign of the dividend. A non-negative
 * dividend and a positive, exactly-known divisor give [0, divisor) — which is
 * the one case worth deriving, and the one every canonical reduction in this
 * repository is.
 */
function ivMod (a, b) {
  const x = iv(a); const y = iv(b)
  if (!y) return undefined
  if (y.hi - y.lo !== 1n) return undefined               // the divisor must be exactly known
  if (y.lo <= 0n) return undefined
  // Truncation bounds the MAGNITUDE whatever the sign, which is what makes the
  // two-step reduction ((v mod p) + p) mod p derivable rather than asserted: the
  // first step lands in (−p, p), the addition makes it positive, and the second
  // step is then the non-negative case.
  if (!x || x.lo < 0n) return { range: { lo: -(y.lo - 1n), hi: y.lo } }
  return { range: { lo: 0n, hi: y.lo } }
}

function norm (v) {
  if (typeof v === 'string') return { name: v, kind: 'num' }
  return { kind: 'num', ...v }
}

module.exports = { Asm }
