// A real Groth16 proof, from snarkjs, over BLS12-381.
// The circuit: c = a * b, with c public and a, b private.
const fs = require('fs')
const path = require('path')
const D = __dirname
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n
const N8 = 32

const raw = (v, n = N8) => { const b = Buffer.alloc(n); let x = v; for (let i = 0; i < n; i++) { b[i] = Number(x & 0xffn); x >>= 8n } return b }
// field elements are reduced; the PRIME itself must not be, and writing it
// through the reducing encoder produced a prime of zero and 'Division by zero'
const le = (v, n = N8) => { const b = Buffer.alloc(n); let x = ((v % R) + R) % R; for (let i = 0; i < n; i++) { b[i] = Number(x & 0xffn); x >>= 8n } return b }
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b }
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b }

function sections (magic, version, list) {
  const parts = [Buffer.from(magic, 'ascii'), u32(version), u32(list.length)]
  for (const [type, data] of list) parts.push(u32(type), u64(data.length), data)
  return Buffer.concat(parts)
}
/** one linear combination: nTerms, then (wireId, coefficient) */
const lc = (terms) => Buffer.concat([u32(terms.length), ...terms.map(([w, v]) => Buffer.concat([u32(w), le(v)]))])

// wires: 0 = the constant 1, 1 = c (public output), 2 = a, 3 = b
const nWires = 4
const header = Buffer.concat([
  u32(N8), raw(R), u32(nWires), u32(1), u32(0), u32(2), u64(nWires), u32(1)
])
// a * b = c
const constraints = Buffer.concat([lc([[2, 1n]]), lc([[3, 1n]]), lc([[1, 1n]])])
const wire2label = Buffer.concat(Array.from({ length: nWires }, (_, i) => u64(i)))
fs.writeFileSync(path.join(D, 'mul.r1cs'), sections('r1cs', 1, [[1, header], [2, constraints], [3, wire2label]]))

// the witness: [1, c, a, b] with a = 3, b = 11
const a = 3n; const b = 11n; const c = a * b
const wtnsHeader = Buffer.concat([u32(N8), raw(R), u32(nWires)])
const wtnsData = Buffer.concat([le(1n), le(c), le(a), le(b)])
fs.writeFileSync(path.join(D, 'mul.wtns'), sections('wtns', 2, [[1, wtnsHeader], [2, wtnsData]]))
console.log('wrote mul.r1cs and mul.wtns   (a =', a, ', b =', b, ', c =', c, ')')
