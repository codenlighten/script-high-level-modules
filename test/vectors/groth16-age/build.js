// "I am at least 21, as of 2026, and I am not telling you my birth year."
//
// The smallest circuit that is a claim a person would recognise. Public: the
// year, and the age required. Private: the birth year, and the bits that prove
// the difference is non-negative.
//
//   for each of 7 bits:   bᵢ · bᵢ = bᵢ                 (bᵢ is 0 or 1)
//   and:                  year − born − minAge = Σ bᵢ2ⁱ
//
// The bit width is the range proof. Σbᵢ2ⁱ lies in [0, 127], so the constraint
// says year − born − minAge ≥ 0: the holder is old enough. It says nothing else
// — not the birth year, not the exact age.
const fs = require('fs')
const path = require('path')
const D = __dirname
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n
const N8 = 32
const BITS = 7

const raw = (v, n = N8) => { const b = Buffer.alloc(n); let x = v; for (let i = 0; i < n; i++) { b[i] = Number(x & 0xffn); x >>= 8n } return b }
const le = (v, n = N8) => raw(((v % R) + R) % R, n)
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b }
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b }
const sections = (magic, version, list) => Buffer.concat([
  Buffer.from(magic, 'ascii'), u32(version), u32(list.length),
  ...list.flatMap(([t, d]) => [u32(t), u64(d.length), d])
])
const lc = (terms) => Buffer.concat([u32(terms.length), ...terms.map(([w, v]) => Buffer.concat([u32(w), le(v)]))])

// wires: 0 = 1, 1 = year, 2 = minAge (public), 3..9 = bits, 10 = born (private)
const YEAR = 1; const MIN = 2; const BIT0 = 3; const BORN = 10
const nWires = 11
const header = Buffer.concat([u32(N8), raw(R), u32(nWires), u32(0), u32(2), u32(BITS + 1), u64(nWires), u32(BITS + 1)])

const rows = []
for (let i = 0; i < BITS; i++) rows.push(lc([[BIT0 + i, 1n]]), lc([[BIT0 + i, 1n]]), lc([[BIT0 + i, 1n]]))
rows.push(
  lc([[YEAR, 1n], [BORN, -1n], [MIN, -1n]]),
  lc([[0, 1n]]),
  lc(Array.from({ length: BITS }, (_, i) => [BIT0 + i, 1n << BigInt(i)]))
)
fs.writeFileSync(path.join(D, 'age.r1cs'), sections('r1cs', 1, [
  [1, header], [2, Buffer.concat(rows)], [3, Buffer.concat(Array.from({ length: nWires }, (_, i) => u64(i)))]
]))

/** A witness — honest or not. An underage prover can still WRITE one. */
function witness (year, minAge, born, name) {
  const d = year - minAge - born
  const bits = Array.from({ length: BITS }, (_, i) => (d >= 0n ? (d >> BigInt(i)) & 1n : 0n))
  const values = [1n, year, minAge, ...bits, born]
  fs.writeFileSync(path.join(D, name), sections('wtns', 2, [
    [1, Buffer.concat([u32(N8), raw(R), u32(nWires)])],
    [2, Buffer.concat(values.map((v) => le(v)))]
  ]))
  return d
}
console.log('honest  born 1990:  year − born − minAge =', witness(2026n, 21n, 1990n, 'age.wtns'))
console.log('underage born 2010: year − born − minAge =', witness(2026n, 21n, 2010n, 'age-underage.wtns'), '  — no 7-bit decomposition exists')
