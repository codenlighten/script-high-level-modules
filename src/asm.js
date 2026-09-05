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
    this._frames = []
  }

  // ── introducing values ────────────────────────────────────────────────────
  /** Declare what the unlocking script (or a caller) has already left, bottom→top. */
  given (slots) { for (const v of slots) this.stack.push(norm(v)); return this }
  num (value, name) { this.s.add(pushNum(value)); this.stack.push({ name, kind: 'num' }); return this }
  data (buf, name) { this.s.add(pushData(buf)); this.stack.push({ name, kind: 'bytes', width: buf.length }); return this }

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
  _bin (opcode, out, kind = 'num') {
    this.s.add(opcode)
    this.stack.pop()
    this.stack[this.stack.length - 1] = { name: out, kind }
    return this
  }
  add (out) { this._checkTop2Num(); return this._bin(Op.OP_ADD, out) }
  sub (out) { this._checkTop2Num(); return this._bin(Op.OP_SUB, out) }
  mul (out) { this._checkTop2Num(); return this._bin(Op.OP_MUL, out) }
  div (out) { this._checkTop2Num(); return this._bin(Op.OP_DIV, out) }
  mod (out) { this._checkTop2Num(); return this._bin(Op.OP_MOD, out) }
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
  equal (out) { this.s.add(Op.OP_EQUAL); this.stack.pop(); this.stack[this.stack.length - 1] = { name: out || 'eq', kind: 'num' }; return this }
  numEqualVerify () { this.s.add(Op.OP_NUMEQUALVERIFY); this.stack.pop(); this.stack.pop(); return this }
  numEqual (out) { this.s.add(Op.OP_NUMEQUAL); this.stack.pop(); this.stack[this.stack.length - 1] = { name: out || 'eq', kind: 'num' }; return this }
  verify () { this.s.add(Op.OP_VERIFY); this.stack.pop(); return this }
  /** 2nd < top, consuming both. */
  ltVerify () { this.s.add(Op.OP_LESSTHAN).add(Op.OP_VERIFY); this.stack.pop(); this.stack.pop(); return this }
  geVerify () { this.s.add(Op.OP_GREATERTHANOREQUAL).add(Op.OP_VERIFY); this.stack.pop(); this.stack.pop(); return this }

  // ── branches ──────────────────────────────────────────────────────────────
  beginIf () {
    this.s.add(Op.OP_IF); this.stack.pop()
    this._frames.push({ snap: this.stack.map((v) => ({ ...v })), ifEnd: null })
    return this
  }
  elseBranch () {
    this.s.add(Op.OP_ELSE)
    const f = this._frames[this._frames.length - 1]
    f.ifEnd = this.stack.map((v) => ({ ...v }))
    this.stack = f.snap.map((v) => ({ ...v }))
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
    for (let i = 0; i < other.length; i++) {
      if (other[i].name !== this.stack[i].name) {
        throw new Error(`asm: IF/ELSE branches disagree at depth ${this.stack.length - 1 - i}: ` +
          `'${other[i].name}' vs '${this.stack[i].name}' — relabel both to the same name before OP_ENDIF`)
      }
    }
    return this
  }

  /** Any opcode in the release, with an explicit stack effect. The escape hatch. */
  op (name, pop = 0, push = []) {
    this.s.add(require('./opcodes').opcode(name))
    for (let i = 0; i < pop; i++) this.stack.pop()
    for (const v of push) this.stack.push(norm(v))
    return this
  }

  script () { return this.s }
  size_ () { return this.s.toBuffer().length }
  toString () { return this.stack.map((v) => `${v.name}:${v.kind}${v.width !== undefined ? '[' + v.width + ']' : ''}`).join(' ') }
}

function norm (v) {
  if (typeof v === 'string') return { name: v, kind: 'num' }
  return { kind: 'num', ...v }
}

module.exports = { Asm }
