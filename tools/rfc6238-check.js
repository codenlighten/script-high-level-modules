'use strict'

// The JS reference is pinned to the published standard, and the Script is pinned
// to the JS reference by the test kit. Two links, both explicit — otherwise a
// module can agree perfectly with a reference implementation that is wrong.
//
// Vectors: RFC 6238 Appendix B, SHA-1, secret "12345678901234567890", 8 digits.

const { totpCode } = require('../src/modules/totp')

const SECRET = Buffer.from('12345678901234567890')
const VECTORS = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130']
]

let bad = 0
for (const [time, expected] of VECTORS) {
  const got = totpCode(SECRET, time, { digits: 8 }).toString().padStart(8, '0')
  const ok = got === expected
  if (!ok) bad++
  console.log(`${ok ? 'ok  ' : 'FAIL'}  t=${String(time).padStart(11)}  expected ${expected}  got ${got}`)
}
console.log(`\n${VECTORS.length - bad}/${VECTORS.length} RFC 6238 vectors reproduced`)
process.exit(bad ? 1 : 0)
