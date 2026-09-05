'use strict'

// Script numbers, honestly.
//
// Script reads a byte string as a number in LITTLE-ENDIAN, SIGN-MAGNITUDE form:
// the top bit of the last byte is the sign. Every mistake in this file class is
// the same mistake — a positive value whose top bit happens to be set is read as
// a negative one — so the encoder always appends the 0x00 that keeps it positive,
// and `minimal` states the rule the interpreter enforces rather than assuming it.

/** BigInt -> the minimal script-number encoding the interpreter accepts. */
function toNum (x) {
  if (typeof x === 'number') x = BigInt(x)
  const neg = x < 0n
  let v = neg ? -x : x
  const bytes = []
  while (v > 0n) { bytes.push(Number(v & 0xffn)); v >>= 8n }
  if (bytes.length === 0) return Buffer.alloc(0)                 // zero is the empty string
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00)           // keep the sign bit clear
  if (neg) bytes[bytes.length - 1] |= 0x80
  return Buffer.from(bytes)
}

/** The interpreter's reading of a byte string as a number. */
function fromNum (buf) {
  if (buf.length === 0) return 0n
  const b = Buffer.from(buf)
  const neg = (b[b.length - 1] & 0x80) !== 0
  if (neg) b[b.length - 1] &= 0x7f
  let x = 0n
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i])
  return neg ? -x : x
}

/** Fixed-width little-endian bytes — the form OP_NUM2BIN produces and OP_CAT wants. */
function toLE (x, width) {
  if (typeof x === 'number') x = BigInt(x)
  const b = Buffer.alloc(width)
  for (let i = 0; i < width; i++) { b[i] = Number(x & 0xffn); x >>= 8n }
  if (x !== 0n) throw new Error(`toLE: value does not fit in ${width} bytes`)
  return b
}

function fromLE (buf) {
  let x = 0n
  for (let i = buf.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(buf[i])
  return x
}

/** Fixed-width BIG-endian — the form every crypto standard (RSA, SHA, X9.62) uses. */
function toBE (x, width) { return Buffer.from(toLE(x, width)).reverse() }
function fromBE (buf) { return fromLE(Buffer.from(buf).reverse()) }

/** Is this the encoding the interpreter would itself produce? (MINIMALDATA) */
function isMinimal (buf) {
  if (buf.length === 0) return true
  const last = buf[buf.length - 1]
  if ((last & 0x7f) !== 0) return true
  return buf.length > 1 && (buf[buf.length - 2] & 0x80) !== 0
}

/** What `Script.add()` wants for a numeric literal: the dedicated opcode for
 *  0..16 and -1, a minimal push otherwise. Anything else trips MINIMALDATA. */
function pushNum (x) {
  const v = typeof x === 'bigint' ? x : BigInt(x)
  if (v === 0n) return 0x00                      // OP_0
  if (v === -1n) return 0x4f                     // OP_1NEGATE
  if (v >= 1n && v <= 16n) return 0x50 + Number(v)
  return toNum(v)
}

/** What `Script.add()` wants for a byte string. MINIMALDATA insists a one-byte
 *  push of 0..16 (or 0x81) uses the dedicated opcode, so a module's own bytes
 *  are subject to the same rule as its numbers. */
function pushData (buf) {
  if (buf.length === 0) return 0x00                            // OP_0
  if (buf.length === 1) {
    if (buf[0] === 0x81) return 0x4f                           // OP_1NEGATE
    if (buf[0] >= 1 && buf[0] <= 16) return 0x50 + buf[0]
  }
  return buf
}

module.exports = { pushNum, pushData, toNum, fromNum, toLE, fromLE, toBE, fromBE, isMinimal }
