'use strict'

// A check you have not seen fail is not a check.
//
// The test kit claims four things: it catches a module that computes the wrong
// value, one that leaves rubbish on the stack, one that reads bytes as a number,
// and — the one that matters — a witnessed module whose check is a congruence
// rather than an equality, so the spender may choose between several accepted
// witnesses. Here each of those bugs is written deliberately, and the kit is
// required to catch it. If any of them slips through, this file goes red.

const { defineModule } = require('../src/module')
const { proveModule } = require('../src/testkit')
const { mod, invmod } = require('../src/bigint')

const N = 11n

const offByOne = defineModule({
  name: 'broken.offbyone',
  doc: 'claims (a+b) mod n, computes (a+b+1) mod n',
  inputs: ['a', 'b'],
  outputs: ['r'],
  model: ({ a, b }) => ({ r: mod(a + b, N) }),
  emit: (asm) => { asm.add('s'); asm.num(1, '_one'); asm.add('s2'); asm.num(N, '_n'); asm.mod('r') },
  cases: [{ name: 'any', inputs: { a: 3n, b: 4n } }]
})

const leaky = defineModule({
  name: 'broken.leaky',
  doc: 'leaves a scratch value behind, so the next module reads the wrong depth',
  inputs: ['a', 'b'],
  outputs: ['r'],
  model: ({ a, b }) => ({ r: mod(a + b, N) }),
  emit: (asm) => { asm.pick('a', '_junk'); asm.roll('a'); asm.roll('b'); asm.add('s'); asm.num(N, '_n'); asm.mod('r') },
  cases: [{ name: 'any', inputs: { a: 3n, b: 4n } }]
})

const confused = defineModule({
  name: 'broken.typeconfusion',
  doc: 'hands a byte string to OP_ADD, where the top bit silently becomes a sign',
  inputs: [{ name: 'blob', kind: 'bytes', width: 4 }, 'b'],
  outputs: ['r'],
  model: () => ({ r: 0n }),
  emit: (asm) => { asm.add('r') },
  cases: [{ name: 'any', inputs: { blob: Buffer.from('ffffffff', 'hex'), b: 1n } }]
})

// The interesting one. a·inv ≡ 1 (mod n) is TRUE of inv, of inv+n, of inv+2n…
// The module computes the right answer for the honest witness and is still
// broken, because its output is whatever the spender picked.
const congruent = defineModule({
  name: 'broken.congruent',
  doc: 'checks the inverse congruence but not the range, so many witnesses pass',
  inputs: ['a', { name: 'inv', witness: true }],
  outputs: ['r'],
  hint: ({ a }, { n }) => ({ inv: invmod(a, n) }),
  model: ({ a }, { n }) => ({ r: invmod(a, n) }),
  emit: (asm, { n }) => {
    asm.pick('a', '_a'); asm.pick('inv', '_i'); asm.mul('_p')
    asm.num(n, '_n'); asm.mod('_res'); asm.num(1, '_one'); asm.numEqualVerify()
    asm.roll('inv'); asm.rename('r'); asm.nip()
  },
  cases: [{ name: 'any', inputs: { a: 3n }, params: { n: N } }]
})

// And the module the kit must refuse to bless at all: a witness it has no way to
// forge, so nothing was proven about it either way.
const unattackable = defineModule({
  name: 'broken.unprovenwitness',
  doc: 'a witnessed module the kit cannot attack, so its canonicity is unproven',
  inputs: ['a', { name: 'w', witness: true, kind: 'bytes', width: 4 }],
  outputs: ['r'],
  hint: () => ({ w: Buffer.from('00000000', 'hex') }),
  model: ({ a }) => ({ r: a }),
  emit: (asm) => { asm.drop(); asm.rename('r') },
  cases: [{ name: 'any', inputs: { a: 3n } }]
})

const expected = [
  [offByOne, 'a wrong value'],
  [leaky, 'a leaked stack slot'],
  [confused, 'bytes read as a number'],
  [congruent, 'a non-canonical witness'],
  [unattackable, 'a witness it cannot attack']
]

let missed = 0
for (const [m, what] of expected) {
  const r = proveModule(m, { quiet: true })
  const caught = r.failures.length > 0
  console.log(`${caught ? 'ok  ' : 'MISSED'}  the kit catches ${what.padEnd(26)} ${caught ? '— ' + r.failures[0].slice(0, 92) : ''}`)
  if (!caught) missed++
}

console.log(`\n${expected.length - missed}/${expected.length} deliberate bugs were caught`)
process.exit(missed ? 1 : 0)
