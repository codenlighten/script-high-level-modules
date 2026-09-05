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
const PushTx = require('@smartledger/bsv/lib/covenant/pushtx')
const { right, left } = require('../src/modules/tx')
const { apply } = require('../src/module')
const bytesMod = require('../src/modules/bytes')
const schnorrJs = require('../src/schnorr')

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

// The contextual one. A module that reads its own spending transaction has a
// circularity to break — the script contains the value being asserted, the
// transaction commits to the script, and the witness comes from the
// transaction. The kit breaks it by building twice, and the second build is
// what catches a module whose answer moves when its own bytes do.
//
// Here the spend pins the SEQUENCE, so the preimage grind has nothing to vary
// but nLockTime — and nLockTime is what the module reports. Its output is
// therefore a function of its own length, which no amount of testing could pin.
const selfDependent = defineModule({
  name: 'broken.selfdependent',
  doc: 'reports a field that its own script length moves',
  inputs: [{ name: 'preimage', kind: 'bytes', witness: true }],
  outputs: [{ name: 'locktime', kind: 'num' }],
  contextual: true,
  witnessFor: ({ tx, lockingScript, satoshis }) => ({
    preimage: PushTx.grind(tx, 0, lockingScript, satoshis, { field: 'nLockTime' }).preimage
  }),
  hint: () => ({}),
  model: ({ preimage }) => ({ locktime: BigInt(preimage.readUInt32LE(preimage.length - 8)) }),
  emit: (asm) => {
    asm.pick('preimage', '_pi')
    asm.clause((sc) => PushTx.pushTxCore(sc), 1, [{ name: '_ok', kind: 'num' }])
    asm.verify()
    asm.roll('preimage'); right(asm, 8, '_t8'); left(asm, 4, '_lt')
    asm.data(Buffer.from([0]), '_sign'); asm.cat('_ltp'); asm.bin2num('locktime')
  },
  attacks: () => [{ label: 'a byte changed', value: Buffer.alloc(4) }],
  cases: [{ name: 'sequence pinned, so the grind moves the locktime', spend: { sequence: 0xfffffffe } }]
})

// The seventh, and the one that came out of auditing rather than out of writing:
// BIP-340's lift takes the x BELOW the field size, and 32 bytes can encode more
// than the field holds. x = 1 is on secp256k1, so 1 + p fits in 32 bytes and is
// congruent to a real point — two encodings, one key. The standard's own vector
// 14 does not catch it, because the value it uses has no y at all.
//
// Here is the same module with the bound removed. It must accept what the
// standard refuses.
const unbounded = defineModule({
  name: 'broken.unboundedx',
  doc: 'lifts an x-only key without checking that x is below the field size',
  inputs: [
    { name: 'pubkey', kind: 'bytes', width: 32, witness: true },
    { name: 'py', witness: true }
  ],
  outputs: ['qx', 'qy'],
  hint: ({ pubkey }) => { const p = schnorrJs.liftX(schnorrJs.toInt(pubkey)); return p ? { py: p.y } : {} },
  model: ({ pubkey }) => { const p = schnorrJs.liftX(schnorrJs.toInt(pubkey)); return { qx: p.x, qy: p.y } },
  emit: (asm) => {
    const P = schnorrJs.P
    asm.num(P, '_P')
    apply(asm, bytesMod.beToNum, { width: 32 }, ['pubkey'], ['qx'])
    asm.pick('py', '_y0'); asm.num(0, '_z1'); asm.pick('_P', '_p1'); asm.withinVerify()
    asm.pick('py', '_y1'); asm.num(2, '_two'); asm.mod('_par')
    asm.num(0, '_z2'); asm.numEqualVerify()
    asm.pick('py', '_y2'); asm.pick('py', '_y3'); asm.mul('_yy')
    asm.pick('_P', '_p2'); asm.mod('_lhs')
    asm.pick('qx', '_x1'); asm.pick('qx', '_x2'); asm.mul('_xx')
    asm.pick('qx', '_x3'); asm.mul('_xxx')
    asm.num(7, '_b'); asm.add('_rhs0')
    asm.pick('_P', '_p3'); asm.mod('_rhs')
    asm.numEqualVerify()
    asm.discard('_P')
    asm.roll('py'); asm.rename('qy')
    asm.roll('qx'); asm.roll('qy')
  },
  attacks: () => [{ label: 'a different y', value: 1n }],
  cases: (() => {
    const one = schnorrJs.liftX(1n)
    return [{
      name: 'x = 1 + p',
      refuse: 'an encoding above the field size names no key',
      inputs: { pubkey: schnorrJs.be32(1n + schnorrJs.P), py: one.y }
    }]
  })()
})

const expected = [
  [offByOne, 'a wrong value'],
  [leaky, 'a leaked stack slot'],
  [confused, 'bytes read as a number'],
  [congruent, 'a non-canonical witness'],
  [unattackable, 'a witness it cannot attack'],
  [selfDependent, 'an answer its own script moves'],
  [unbounded, 'an x above the field size']
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
