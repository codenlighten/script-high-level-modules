'use strict'

const { defineModule, apply } = require('../module')
const ecJs = require('../ec')

// ELLIPTIC-CURVE POINT ARITHMETIC over a prime field, in affine coordinates.
//
// Affine coordinates are affordable here for one reason: the division in the
// slope is the expensive operation to COMPUTE in Script and a cheap one to
// CHECK. The spender supplies the inverse; the module verifies it with one
// multiplication and one OP_WITHIN. Every point operation therefore takes a
// witness, and every witness carries the same two obligations — soundness and
// canonicity — that the test kit attacks.
//
// The rest of what makes these small is in docs/optimization.md: reductions
// deferred to where a value must be canonical, the modulus hoisted out of the
// loop and referenced by name, and every value rolled at its last use so
// nothing is left to clean up.
//
// PRECONDITIONS, ENFORCED RATHER THAN DOCUMENTED. `add` covers two points with
// DIFFERENT x. Feed it two points with the same x and dx is zero, no inverse of
// zero exists, and the module refuses the spend — it cannot silently return the
// wrong point. `double` covers a point with y ≠ 0 for the same reason. The
// point at infinity has no affine coordinates and is not representable here;
// a caller that needs it must branch around it.

const P = ecJs.P

/**
 * Where the modulus lives for one point operation.
 *
 * `p` is either a BigInt, pushed as a literal, or the NAME of a value the
 * caller already has on the stack. The second form is the one that matters: a
 * 256-bit prime is a 33-byte push, and a ladder performs 512 point operations.
 * Pushed once by the ladder and picked by each operation, that is 17 KB.
 */
function modulusOf (asm, p) {
  if (typeof p === 'string') return { name: p, pushed: false }
  asm.num(p, '_p')
  return { name: '_p', pushed: true }
}

/** 2p, in whichever form the caller has it: a name, or pushed here. */
function doubleModulusOf (asm, p, p2) {
  if (typeof p2 === 'string') return { name: p2, pushed: false }
  asm.num(2n * p, '_p2')
  return { name: '_p2', pushed: true }
}

// ── DEFERRED REDUCTION ──────────────────────────────────────────────────────
//
// The obvious way to write a point addition is one field operation per line of
// the formula: subtract and reduce, multiply and reduce, subtract and reduce.
// That reads beautifully and costs 168 bytes, because two thirds of it is
// reductions nothing needed.
//
// Post-Genesis Script numbers are arbitrary precision. An intermediate does not
// have to fit in a field element — it only has to be CONGRUENT to the right
// value, and reduction can wait until a result must be canonical. λ is never
// reduced at all here; λ² is a 1024-bit number and OP_MUL does not care. Only
// x₃ and y₃ come out in [0, p), because those are what leaves the module.
//
// Two rules make this safe rather than merely smaller:
//
//   OP_MOD IS TRUNCATED. `a mod p` keeps the sign of a, so reducing a value
//   that might be negative does not produce a canonical one. Where the sign is
//   unknown the reduction is `((v mod p) + p) mod p`; where the value is
//   provably non-negative one OP_MOD is enough — and x₃ is made provably
//   non-negative by adding 2p first, which is why the modulus is carried in
//   both forms.
//
//   A CONGRUENCE CHECK NEEDS NO SIGN. `dx·inv ≡ 1 (mod p)` is checked as
//   `(dx·inv − 1) mod p == 0`. Zero is zero under truncation too, so dx never
//   needs reducing before the check — which is what lets dx be a bare OP_SUB.
//
// The cost is paid in the interpreter's arithmetic (bigger BN operands), not in
// bytes. Fees are bytes.

/**
 * Assert that `invName` inverts the value now on TOP of the stack, canonically,
 * consuming that value.
 *
 * The value being inverted is a difference with no other use — dx in an
 * addition, 2y in a doubling — so it is passed on the stack rather than named,
 * and consumed here. A temporary that is never named is one that never has to
 * be dropped.
 */
function checkInverseOfTop (asm, pName, invName) {
  // 0 ≤ inv < p in one opcode rather than two comparisons and two VERIFYs.
  asm.pick(invName, '_i0'); asm.num(0, '_zero'); asm.pick(pName, '_pw'); asm.withinVerify()
  asm.pick(invName, '_i2'); asm.mul('_prod')
  asm.num(1, '_one'); asm.sub('_pm1')
  asm.pick(pName, '_pm'); asm.mod('_res')
  asm.num(0, '_z0'); asm.numEqualVerify()                            // ≡ 1 (mod p)
}

/** r = (v mod p), canonical, when v's sign is unknown. */
function reduceSigned (asm, pName, out) {
  asm.pick(pName, '_ra'); asm.mod('_rm')
  asm.pick(pName, '_rb'); asm.add('_rp')
  asm.pick(pName, '_rc'); asm.mod(out)
}

const add = defineModule({
  name: 'ec.add',
  doc: 'P₁ + P₂ on a short Weierstrass curve, for points with distinct x',
  inputs: ['x1', 'y1', 'x2', 'y2', { name: 'invdx', witness: true }],
  outputs: ['x3', 'y3'],
  hint: ({ x1, x2 }, { p = P }) => ({ invdx: ecJs.inv(ecJs.mod(x2 - x1, p), p) }),
  model: ({ x1, y1, x2, y2 }) => {
    const r = ecJs.add({ x: x1, y: y1 }, { x: x2, y: y2 })
    return { x3: r.x, y3: r.y }
  },
  // Every value is ROLLED at its last use and PICKED before it. A value
  // consumed where it is last needed never becomes a temporary, so this module
  // ends with exactly its two results live and no cleanup at all — where the
  // same code with picks throughout needed eleven bytes of altstack and
  // OP_2DROP to clear what it had left lying about.
  emit: (asm, { p = P, p2 = null }) => {
    const floor = asm.mark(5)
    const N = modulusOf(asm, p)
    const N2 = doubleModulusOf(asm, p, p2)

    // dx is never named: it is built on top, checked, and consumed there
    asm.pick('x2', '_a'); asm.pick('x1', '_b'); asm.sub('_dx')
    checkInverseOfTop(asm, N.name, 'invdx')

    asm.roll('y2'); asm.pick('y1', '_d'); asm.sub('_dy')             // y₂ last used here
    asm.roll('invdx'); asm.mul('_lam')                               // λ = dy·inv, unreduced

    // x₃ = λ² − x₁ − x₂, made non-negative by +2p so ONE OP_MOD is canonical
    asm.pick('_lam', '_f'); asm.pick('_lam', '_g'); asm.mul('_lam2')
    asm.pick('x1', '_h'); asm.sub('_u')
    asm.roll('x2'); asm.sub('_v')                                    // x₂ last used here
    asm.pick(N2.name, '_j'); asm.add('_w')
    asm.pick(N.name, '_k'); asm.mod('x3')

    // y₃ = λ(x₁ − x₃) − y₁, sign unknown, so the two-step reduction
    asm.roll('_lam'); asm.roll('x1'); asm.pick('x3', '_n'); asm.sub('_o')
    asm.mul('_q'); asm.roll('y1'); asm.sub('_s')
    reduceSigned(asm, N.name, 'y3')

    // Only the standalone form has anything left: the constants it pushed
    // itself. Inside a ladder they belong to the caller and this emits nothing.
    if (N.pushed || N2.pushed) asm.dropTo(floor, ['x3', 'y3'])
  },
  attacks: (honest, params) => {
    const p = params.p || P
    const inv = honest.invdx
    return [
      { label: 'off by one', value: inv + 1n },
      { label: 'the same residue (+p)', value: inv + p },
      { label: 'negated', value: p - inv },
      { label: 'zero', value: 0n },
      { label: 'one', value: 1n }
    ]
  },
  cases: (() => {
    const pts = [1n, 2n, 3n, 7n, 11n, 12345n].map((k) => ecJs.mul(k))
    return [
      { name: 'G + 2G', inputs: { x1: pts[0].x, y1: pts[0].y, x2: pts[1].x, y2: pts[1].y } },
      { name: '3G + 7G', inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[3].x, y2: pts[3].y } },
      { name: '11G + 12345G', inputs: { x1: pts[4].x, y1: pts[4].y, x2: pts[5].x, y2: pts[5].y } },
      // The precondition, enforced rather than documented. dx = 0 has no
      // inverse, so no witness makes these pass — the module cannot be tricked
      // into returning the wrong point for a doubling or for P + (−P).
      { name: 'P + P (same point)', refuse: 'dx = 0 has no inverse',
        inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[2].x, y2: pts[2].y, invdx: 1n } },
      { name: 'P + (−P)', refuse: 'dx = 0 has no inverse',
        inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[2].x, y2: ecJs.mod(-pts[2].y), invdx: 0n } },
      { name: 'P + P, witness = p−1', refuse: 'no witness inverts zero',
        inputs: { x1: pts[2].x, y1: pts[2].y, x2: pts[2].x, y2: pts[2].y, invdx: P - 1n } }
    ]
  })(),
  notes: ['refuses two points with the same x — dx is zero and has no inverse']
})

const double = defineModule({
  name: 'ec.double',
  doc: '2P on a short Weierstrass curve with a = 0 (secp256k1), for y ≠ 0',
  inputs: ['x1', 'y1', { name: 'inv2y', witness: true }],
  outputs: ['x3', 'y3'],
  hint: ({ y1 }, { p = P }) => ({ inv2y: ecJs.inv(ecJs.mod(2n * y1, p), p) }),
  model: ({ x1, y1 }) => {
    const r = ecJs.double({ x: x1, y: y1 })
    return { x3: r.x, y3: r.y }
  },
  emit: (asm, { p = P, p2 = null }) => {
    const floor = asm.mark(3)
    const N = modulusOf(asm, p)
    const N2 = doubleModulusOf(asm, p, p2)

    asm.pick('y1', '_a'); asm.op('OP_DUP', 0, ['_b']); asm.add('_2y')  // 2y, unnamed
    checkInverseOfTop(asm, N.name, 'inv2y')

    asm.pick('x1', '_c'); asm.op('OP_DUP', 0, ['_d']); asm.mul('_xx')
    asm.num(3, '_three'); asm.mul('_3xx')
    asm.roll('inv2y'); asm.mul('_lam')                                 // λ = 3x²·inv

    asm.pick('_lam', '_f'); asm.pick('_lam', '_g'); asm.mul('_lam2')
    asm.pick('x1', '_h'); asm.sub('_u')
    asm.pick('x1', '_i'); asm.sub('_v')                                // x₃ = λ² − 2x₁
    asm.pick(N2.name, '_j'); asm.add('_w')
    asm.pick(N.name, '_k'); asm.mod('x3')

    asm.roll('_lam'); asm.roll('x1'); asm.pick('x3', '_n'); asm.sub('_o')
    asm.mul('_q'); asm.roll('y1'); asm.sub('_s')
    reduceSigned(asm, N.name, 'y3')

    if (N.pushed || N2.pushed) asm.dropTo(floor, ['x3', 'y3'])
  },
  attacks: (honest, params) => {
    const p = params.p || P
    const inv = honest.inv2y
    return [
      { label: 'off by one', value: inv + 1n },
      { label: 'the same residue (+p)', value: inv + p },
      { label: 'zero', value: 0n }
    ]
  },
  cases: [
    ...[1n, 3n, 12345n].map((k) => {
      const pt = ecJs.mul(k)
      return { name: `2·(${k}G)`, inputs: { x1: pt.x, y1: pt.y } }
    }),
    { name: 'y = 0 (not a point on secp256k1)', refuse: '2y = 0 has no inverse',
      inputs: { x1: ecJs.G.x, y1: 0n, inv2y: 1n } }
  ],
  notes: ['a = 0 is baked in: this is secp256k1’s doubling, not the general one']
})

module.exports = { add, double, checkInverseOfTop, reduceSigned, modulusOf, doubleModulusOf, P }

// ── SCALAR MULTIPLICATION ───────────────────────────────────────────────────
//
// k·P, for a scalar and a point both known only at spend time. Double-and-add,
// unrolled, with the scalar's bits supplied as witnesses and pinned by
// Σ bᵢ2ⁱ = k together with bᵢ² = bᵢ. That pair is what makes the decomposition
// unique: the sum alone would accept b₀ = 2 in place of b₁ = 1.
//
// THE POINT AT INFINITY. Affine coordinates cannot represent it, and a ladder
// starting from it needs a first-set-bit branch that a runtime scalar does not
// give you. So the accumulator starts at a nothing-up-my-sleeve point H — a
// hash treated as an x coordinate, nobody's known multiple of G — and the
// result is acc − H at the end.
//
// This is SOUND but not COMPLETE, and the difference is worth being exact
// about. If any intermediate addition lands on the point at infinity, dx is
// zero, no inverse exists, and the spend is REFUSED. It is never accepted with
// a wrong answer. For a scalar and point that are not chosen adversarially the
// probability is around 2⁻¹²⁸ per step; an attacker who controls P can force a
// refusal, which costs them a spend they could have declined to make anyway.
//
// UNUSED WITNESSES ARE PINNED TO ZERO. When a bit is zero the step's inverse is
// never read. Leaving it unconstrained would let anyone rewrite that push and
// change the transaction's txid without changing what it does; the ELSE branch
// therefore requires it to be zero. Three bytes per step to keep the spend
// canonical.

const H = ecJs.numsPoint('script-modules/secp256k1/offset/v1')

// ── THE WITNESS IS A TAPE, NOT A STACK ──────────────────────────────────────
//
// A 256-step ladder needs a bit and an inverse at every step, and a second
// inverse when the base point is not a constant: over seven hundred values. The
// interpreter caps the stack at 1000 elements (measured — tools/probe-limits.js),
// so two ladders in one script overflow it long before the fee becomes
// interesting.
//
// The cap is on the COUNT, not the size: a single 100 KB element is fine. So the
// witness arrives as two packed byte strings and the script splits one field off
// the front of each as it goes. Three stack elements per ladder instead of
// seven hundred, a smaller unlocking script (no per-push prefix), and the
// remaining tape is required to be empty at the end — otherwise trailing junk
// would ride along and change the transaction's txid without changing what it
// does.

const FIELD = 33          // a 256-bit inverse, little-endian, plus the sign byte

/**
 * The two witness values one ladder takes.
 *
 * There used to be three. The bits of the scalar were witnessed and then pinned
 * by Σ bᵢ2ⁱ = k and bᵢ² = bᵢ — about twenty-five bytes a step to constrain a
 * value that was never free in the first place. The scalar already determines
 * its own bits; the script derives them with OP_NUM2BIN and a mask, and the
 * range check 0 ≤ k < 2^bits falls out of requiring the sign byte to be zero.
 *
 * A witness that can be derived is not a witness. It is a second copy of
 * something, and every second copy has to be pinned to the first.
 */
function ladderInputs (prefix, bits, fixedBase) {
  return [
    { name: `${prefix}tape`, kind: 'bytes', witness: true },
    { name: `${prefix}fi`, witness: true }
  ]
}

/** A field element as one fixed-width, positive little-endian record. */
function record (v) {
  const b = Buffer.alloc(FIELD)
  let x = v
  for (let i = 0; i < FIELD && x > 0n; i++) { b[i] = Number(x & 0xffn); x >>= 8n }
  if (x !== 0n) throw new Error('ec: value does not fit a tape record')
  return b
}

/**
 * The honest witness for one ladder: a byte per bit, and the inverses in the
 * order the script reads them — the add's inverse at every step, the doubling's
 * after it when the base is not a constant. A skipped step's inverse is zero,
 * which the ELSE branch requires, so it is not a free choice.
 */
function ladderWitness (prefix, bits, k, point, { fixedBase = false, p = P } = {}) {
  const bitBytes = Buffer.alloc(bits)
  const tape = []
  let acc = H
  let D = point
  for (let i = 0; i < bits; i++) {
    const bit = (k >> BigInt(i)) & 1n
    tape.push(record(bit ? ecJs.inv(ecJs.mod(D.x - acc.x, p), p) : 0n))
    if (bit) acc = ecJs.add(acc, D)
    if (i < bits - 1) {
      if (!fixedBase) tape.push(record(ecJs.inv(ecJs.mod(2n * D.y, p), p)))
      D = ecJs.double(D)
    }
  }
  return {
    [`${prefix}tape`]: Buffer.concat(tape),
    [`${prefix}fi`]: ecJs.inv(ecJs.mod(H.x - acc.x, p), p)
  }
}

/** Split one record off the front of the tape and read it as a number. */
function takeInverse (asm, tapeName, out) {
  asm.roll(tapeName)
  asm.splitAt(FIELD, '_rec', '_rest')
  asm.rename(tapeName)                      // the remaining tape stays named
  asm.roll('_rec'); asm.bin2num(out)
}

/**
 * Spread the scalar into a byte string the bits can be read out of, and bound it
 * to [0, 2^bits) on the way.
 *
 * OP_NUM2BIN writes a SIGNED number, so asking for one byte more than the
 * scalar needs puts the sign in that extra byte. Requiring it to be 0x00 says
 * both things at once: the scalar is not negative, and it does not reach into
 * the byte above. The range check costs three bytes and no separate comparison.
 */
function spreadScalar (asm, scalar, bits, out) {
  if (bits % 8 !== 0) throw new Error('ec: the ladder wants a bit width that is a whole number of bytes')
  const nbytes = bits / 8
  asm.pick(scalar, '_kc')
  asm.num2bin(nbytes + 1, '_kb')
  asm.splitAt(nbytes, out, '_ksign')
  asm.data(Buffer.from([0]), '_zb'); asm.equalVerify()
}

/**
 * Bit `t` of the byte named `byteName`, as a clean 0 or 1.
 *
 * `mask AND` alone would nearly do it — the result is either zero or the mask,
 * and OP_IF takes any non-zero value for true. Nearly: a lone 0x80 is negative
 * zero to CastToBool and reads FALSE, so bit 7 of every byte would silently be
 * skipped. Comparing against the mask costs two bytes and is the same shape for
 * all eight, which is worth more here than the two bytes.
 */
function takeBitOfByte (asm, byteName, t, out) {
  const mask = Buffer.from([1 << t])
  asm.pick(byteName, '_bb')
  asm.data(mask, '_mask'); asm.and('_m')
  asm.data(mask, '_mask2'); asm.equal(out)
}

/**
 * Emit one double-and-add ladder, reading its witness off the tape.
 *
 * `scalar` names a live value the bits must sum to; it is read by copy, so the
 * caller still owns it. `point` is either the names of two live coordinates —
 * doubled on chain, with a doubling inverse per step — or a constant {x, y},
 * which is materially cheaper: the whole chain 2ⁱ·P is then known at compile
 * time, so every doubling becomes two pushes instead of a 191-byte operation
 * and the tape carries half as many records.
 */
function emitLadder (asm, { prefix, bits, p = P, point }, scalar, out) {
  const fixedBase = !Array.isArray(point)
  const TAPE = `${prefix}tape`
  const KB = `${prefix}_kb`; const BYTE = `${prefix}_byte`
  const AX = `${prefix}accx`; const AY = `${prefix}accy`
  const DX = `${prefix}_dx`; const DY = `${prefix}_dy`
  const PN = `${prefix}_p`; const PN2 = `${prefix}_p2`

  // The modulus, pushed ONCE for the whole ladder, in both the forms a point
  // operation needs: p to reduce with, and 2p to shift a possibly-negative
  // value non-negative before a single truncated OP_MOD is enough. Each point
  // operation picks them instead of carrying its own 33-byte literals — at 512
  // operations that is 34 KB of constants that never had to be there.
  asm.num(p, PN)
  asm.num(2n * p, PN2)
  const pp = { p: PN, p2: PN2 }

  // The scalar, spread into bytes the bits are read out of. This also bounds it
  // to [0, 2^bits) — see spreadScalar.
  spreadScalar(asm, scalar, bits, KB)

  let D = fixedBase ? point : null
  if (!fixedBase) { asm.roll(point[0]); asm.rename(DX); asm.roll(point[1]); asm.rename(DY) }
  asm.num(H.x, AX); asm.num(H.y, AY)

  for (let i = 0; i < bits; i++) {
    // one byte at a time, least significant first
    if (i % 8 === 0) { asm.roll(KB); asm.splitAt(1, BYTE, KB); }
    takeBitOfByte(asm, BYTE, i % 8, '_b')

    takeInverse(asm, TAPE, '_ai')

    // The invariant the branch depends on: both paths must leave the same
    // values in the same places, so the accumulator and this step's inverse are
    // rolled to the top FIRST. Everything the branch touches is then inside the
    // top few slots, and nothing beneath either path moves.
    asm.roll(AX); asm.roll(AY); asm.roll('_ai'); asm.roll('_b')
    asm.beginIf()
    // The accumulator is already the top pair. Putting the point above it and
    // then rotating the inverse back on top leaves exactly [accx, accy, x, y,
    // inv] — the callee's argument order — so apply() emits nothing at all.
    if (fixedBase) { asm.num(D.x, '_ax'); asm.num(D.y, '_ay') } else { asm.pick(DX, '_ax'); asm.pick(DY, '_ay') }
    asm.roll('_ai')
    apply(asm, add, pp, [AX, AY, '_ax', '_ay', '_ai'], ['_nx', '_ny'])
    asm.relabel('_nx', AX); asm.relabel('_ny', AY)
    asm.elseBranch()
    asm.roll('_ai'); asm.num(0, '_z'); asm.numEqualVerify()      // pin the unused record
    asm.endIf()

    if (i % 8 === 7) asm.discard(BYTE)

    if (i < bits - 1) {
      if (fixedBase) { D = ecJs.double(D) } else {
        takeInverse(asm, TAPE, '_di')
        asm.roll(DX); asm.roll(DY); asm.roll('_di')
        apply(asm, double, pp, [DX, DY, '_di'], ['_ndx', '_ndy'])
        asm.relabel('_ndx', DX); asm.relabel('_ndy', DY)
      }
    }
  }

  // the tape must be exactly used up: no unread bytes riding along
  asm.roll(TAPE); asm.num(0, '_empty2'); asm.equalVerify()
  asm.discard(KB)

  // undo the offset: the result is acc − H
  if (!fixedBase) { asm.discard(DX); asm.discard(DY) }
  asm.num(H.x, '_hx'); asm.num(ecJs.mod(-H.y, p), '_hy'); asm.roll(`${prefix}fi`)
  apply(asm, add, pp, [AX, AY, '_hx', '_hy', `${prefix}fi`], out)
  asm.roll(out[0]); asm.roll(out[1]); asm.discard(PN); asm.discard(PN2)
  asm.roll(out[0]); asm.roll(out[1])
  return asm
}

/** The forgeries to try against a ladder's witness, by name. */
function ladderAttacks (honest, name, p = P) {
  const v = honest[name]
  if (Buffer.isBuffer(v)) {
    const flipped = Buffer.from(v); flipped[0] ^= 0x01
    const late = Buffer.from(v); late[v.length - 1] ^= 0x01
    return [
      { label: `${name}: first byte changed`, value: flipped },
      { label: `${name}: last byte changed`, value: late },
      { label: `${name}: a byte appended`, value: Buffer.concat([v, Buffer.from([0])]) },
      { label: `${name}: truncated`, value: v.subarray(0, v.length - 1) },
      { label: `${name}: emptied`, value: Buffer.alloc(0) }
    ]
  }
  return [
    { label: `${name} off by one`, value: v + 1n },
    { label: `${name} + p`, value: v + p },
    { label: `${name} = 0`, value: 0n }
  ]
}

/**
 * k·P by double-and-add, for a scalar and a point both known at spend time.
 *
 * SOUND BUT NOT COMPLETE, and the difference is worth being exact about. If an
 * intermediate addition lands on the point at infinity, dx is zero, no inverse
 * exists, and the spend is REFUSED — never accepted with a wrong answer. For
 * inputs that are not chosen adversarially the chance is about 2⁻¹²⁸ per step;
 * an attacker who controls P can force a refusal, which costs them a spend they
 * could equally have declined to make.
 */
function mul (bits, scalars, { p = P } = {}) {
  scalars = scalars || defaultScalars(bits)
  return defineModule({
    name: `ec.mul${bits}`,
    doc: `k·P on secp256k1, ${bits}-bit scalar, double-and-add`,
    inputs: ['k', 'px', 'py', ...ladderInputs('', bits, false)],
    outputs: ['rx', 'ry'],
    maxWitnessAttacks: 6,
    hint: ({ k, px, py }) => ladderWitness('', bits, k, { x: px, y: py }, { p }),
    model: ({ k, px, py }) => {
      const r = ecJs.mul(k, { x: px, y: py })
      if (r === ecJs.INFINITY) throw new Error('ec.mul: k·P is the point at infinity')
      return { rx: r.x, ry: r.y }
    },
    emit: (asm) => {
      emitLadder(asm, { prefix: '', bits, p, point: ['px', 'py'] }, 'k', ['rx', 'ry'])
      asm.discard('k')
      asm.roll('rx'); asm.roll('ry')
    },
    attacks: (honest, params, name) => ladderAttacks(honest, name, p),
    cases: scalars.map((k) => ({ name: `k = ${k}`, inputs: { k, px: ecJs.G.x, py: ecJs.G.y } })),
    notes: [
      'sound but not complete: an intermediate at infinity refuses the spend rather than mis-answering',
      'the unused inverse of a skipped step is pinned to zero, so the witness is canonical'
    ]
  })
}

/**
 * k·G — the same ladder over a base point fixed at compile time.
 *
 * Worth its own module because the saving is structural rather than marginal:
 * with the base known, the whole doubling chain 2ⁱ·G is known too, so every
 * doubling becomes two pushes instead of a 191-byte point operation, and the
 * ladder needs no doubling witnesses at all.
 *
 * This is "derive the public key from a secret" as a Script predicate — a coin
 * that anyone holding the scalar can spend, without OP_CHECKSIG and without
 * revealing the scalar to the verifier's own signing code.
 */
function mulG (bits, scalars, { p = P, base = ecJs.G } = {}) {
  scalars = scalars || defaultScalars(bits)
  return defineModule({
    name: `ec.mulG${bits}`,
    doc: `k·G on secp256k1, ${bits}-bit scalar, base fixed at compile time`,
    inputs: ['k', ...ladderInputs('g', bits, true)],
    outputs: ['rx', 'ry'],
    maxWitnessAttacks: 6,
    hint: ({ k }) => ladderWitness('g', bits, k, base, { fixedBase: true, p }),
    model: ({ k }) => {
      const r = ecJs.mul(k, base)
      if (r === ecJs.INFINITY) throw new Error('ec.mulG: k·G is the point at infinity')
      return { rx: r.x, ry: r.y }
    },
    emit: (asm) => {
      emitLadder(asm, { prefix: 'g', bits, p, point: base }, 'k', ['rx', 'ry'])
      asm.discard('k')
      asm.roll('rx'); asm.roll('ry')
    },
    attacks: (honest, params, name) => ladderAttacks(honest, name, p),
    cases: scalars.map((k) => ({ name: `k = ${k}`, inputs: { k } })),
    notes: ['no doubling witnesses: the doubling chain is a compile-time constant']
  })
}

/** 1, all-ones, alternating, and a couple of ordinary values. */
function defaultScalars (bits) {
  const all = (1n << BigInt(bits)) - 1n
  const alt = BigInt('0b' + '10'.repeat(Math.floor(bits / 2)) + (bits % 2 ? '1' : ''))
  const out = [1n, 2n, 3n, all, alt]
  if (bits >= 16) out.push(all - 1n)
  return [...new Set(out)]
}

module.exports.mul = mul
module.exports.mulG = mulG
module.exports.defaultScalars = defaultScalars
module.exports.emitLadder = emitLadder
module.exports.ladderInputs = ladderInputs
module.exports.ladderWitness = ladderWitness
module.exports.ladderAttacks = ladderAttacks
module.exports.FIELD = FIELD
module.exports.record = record
module.exports.H = H

// ── SHAMIR'S TRICK: two scalars, one ladder ─────────────────────────────────
//
// ECDSA verification needs u₁·G + u₂·Q, and doing it as two separate
// multiplications performs 256 doublings for Q and 256 additions for each
// scalar — 768 point operations.
//
// Interleaved, one accumulator serves both: double it once per bit, then add
// whichever of G, Q or G+Q the two bits select. 256 doublings and 256
// additions, 512 operations, and the doubling chain is shared rather than
// duplicated.
//
// WHY WINDOWING DOES NOT HELP, AND NAF DOES NOT EITHER. A branch costs its
// bytes in the locking script whether or not it is taken, so the usual
// optimisations — non-adjacent form, which makes fewer additions HAPPEN, or a
// wider window, which makes fewer additions but a much more expensive selection
// — buy nothing here. Only the static instruction count matters. Measured, a
// 2-bit window is worse: it removes 128 additions and adds a sixteen-way
// selection to all 128 remaining steps.
//
// THE SELECTION IS ARITHMETIC, NOT A BRANCH. Choosing between three points with
// nested OP_IFs would put three copies of the addition in the script. Instead,
// with b₁ and b₂ pinned to 0 or 1:
//
//     S = b₁·G + b₂·Q + b₁b₂·C        where C = T − G − Q  (mod p), T = G + Q
//
// which is the right point for each of the three live cases and is never
// evaluated for the fourth, because that one skips the addition entirely.

/** The tape one Shamir ladder reads: T's inverse, two per step, then the final. */
function shamirWitness (prefix, bits, u1, u2, Q, { p = P, base = ecJs.G } = {}) {
  const G = base
  const tape = []
  const T = ecJs.add(G, Q)
  tape.push(record(ecJs.inv(ecJs.mod(Q.x - G.x, p), p)))

  let acc = H
  for (let i = bits - 1; i >= 0; i--) {
    tape.push(record(ecJs.inv(ecJs.mod(2n * acc.y, p), p)))
    acc = ecJs.double(acc)
    const b1 = (u1 >> BigInt(i)) & 1n
    const b2 = (u2 >> BigInt(i)) & 1n
    const S = (b1 && b2) ? T : b1 ? G : b2 ? Q : null
    tape.push(record(S ? ecJs.inv(ecJs.mod(S.x - acc.x, p), p) : 0n))
    if (S) acc = ecJs.add(acc, S)
  }

  const off = ecJs.neg(ecJs.mul(1n << BigInt(bits), H))
  tape.push(record(ecJs.inv(ecJs.mod(off.x - acc.x, p), p)))
  return { [`${prefix}tape`]: Buffer.concat(tape) }
}

/** What the witness for one Shamir ladder is called. */
function shamirInputs (prefix) {
  return [{ name: `${prefix}tape`, kind: 'bytes', witness: true }]
}

/**
 * Emit u₁·G + u₂·Q as a single interleaved ladder.
 *
 * Consumes the two scalars by copy and the point Q by name; leaves the result
 * under `out`. The offset point H is doubled along with everything else, so the
 * accumulator ends at 2^bits·H + the answer and the last operation subtracts
 * that — a compile-time constant, since H is.
 */
function emitShamir (asm, { prefix = 'sh', bits = 256, p = P, base = ecJs.G }, scalars, qNames, out) {
  const [u1, u2] = scalars
  const [QX, QY] = qNames
  const TAPE = `${prefix}tape`
  const PN = `${prefix}_p`; const PN2 = `${prefix}_p2`
  const GX = `${prefix}gx`; const GY = `${prefix}gy`
  const TX = `${prefix}tx`; const TY = `${prefix}ty`
  const CX = `${prefix}cx`; const CY = `${prefix}cy`
  const AX = `${prefix}accx`; const AY = `${prefix}accy`
  const KB1 = `${prefix}kb1`; const KB2 = `${prefix}kb2`
  const B1 = `${prefix}_b1`; const B2 = `${prefix}_b2`
  const nbytes = bits / 8

  asm.num(p, PN); asm.num(2n * p, PN2)
  const pp = { p: PN, p2: PN2 }

  // G lives on the stack, not in every step's instruction stream
  asm.num(base.x, GX); asm.num(base.y, GY)

  // T = G + Q, once
  takeInverse(asm, TAPE, '_ti')
  asm.pick(GX, '_ga'); asm.pick(GY, '_gb'); asm.pick(QX, '_qa'); asm.pick(QY, '_qb'); asm.roll('_ti')
  apply(asm, add, pp, ['_ga', '_gb', '_qa', '_qb', '_ti'], [TX, TY])

  // C = T − G − Q (mod p), so the three-way selection is three multiplications
  for (const [t, g, q, c] of [[TX, GX, QX, CX], [TY, GY, QY, CY]]) {
    asm.pick(t, '_ca'); asm.pick(g, '_cb'); asm.sub('_cc')
    asm.pick(q, '_cd'); asm.sub('_ce')
    reduceSigned(asm, PN, c)
  }

  spreadScalar(asm, u1, bits, KB1)
  spreadScalar(asm, u2, bits, KB2)

  asm.num(H.x, AX); asm.num(H.y, AY)

  for (let i = bits - 1; i >= 0; i--) {
    // The doubling comes FIRST, while the accumulator is still the top pair:
    // the tape's record lands directly above it, which is already the callee's
    // argument order. Extracting the bits first would bury it.
    takeInverse(asm, TAPE, '_di')
    apply(asm, double, pp, [AX, AY, '_di'], ['_ndx', '_ndy'])
    asm.relabel('_ndx', AX); asm.relabel('_ndy', AY)

    if (i % 8 === 7) {                                     // one byte of each, from the top
      const remaining = Math.floor(i / 8)
      asm.roll(KB1); asm.splitAt(remaining, KB1, `${prefix}_byte1`)
      asm.roll(KB2); asm.splitAt(remaining, KB2, `${prefix}_byte2`)
    }
    takeBitOfByte(asm, `${prefix}_byte1`, i % 8, B1)
    takeBitOfByte(asm, `${prefix}_byte2`, i % 8, B2)

    // acc = acc + S, unless both bits are zero
    takeInverse(asm, TAPE, '_ai')
    asm.pick(B1, '_o1'); asm.pick(B2, '_o2'); asm.op('OP_BOOLOR', 2, [{ name: '_cond', kind: 'num' }])
    asm.roll(AX); asm.roll(AY); asm.roll('_ai'); asm.roll('_cond')
    asm.beginIf()
    // S = b₁·(G + b₂·C) + b₂·Q — the same three cases as b₁G + b₂Q + b₁b₂C, with
    // the shared product factored out, so there is no b₁b₂ to compute or drop.
    for (const [g, q, c, sn] of [[GX, QX, CX, '_sx'], [GY, QY, CY, '_sy']]) {
      asm.pick(B2, '_p1'); asm.pick(c, '_p2'); asm.mul('_t1')
      asm.pick(g, '_p3'); asm.add('_t2')
      asm.pick(B1, '_p4'); asm.mul('_t3')
      asm.pick(B2, '_p5'); asm.pick(q, '_p6'); asm.mul('_t4'); asm.add('_t5')
      asm.pick(PN, '_p7'); asm.mod(sn)                     // non-negative already: one OP_MOD
    }
    // [accx, accy, inv, sx, sy] → one OP_ROT puts the inverse back on top, which
    // is the callee's argument order, so the call emits nothing.
    asm.roll('_ai')
    apply(asm, add, pp, [AX, AY, '_sx', '_sy', '_ai'], ['_nx', '_ny'])
    asm.relabel('_nx', AX); asm.relabel('_ny', AY)
    asm.elseBranch()
    asm.roll('_ai'); asm.num(0, '_z'); asm.numEqualVerify()          // pin the unused record
    asm.endIf()

    asm.discard(B1); asm.discard(B2)
    if (i % 8 === 0) { asm.discard(`${prefix}_byte1`); asm.discard(`${prefix}_byte2`) }
  }

  // the last record is the final inverse; after it the tape must be empty
  takeInverse(asm, TAPE, '_fi')
  asm.roll(TAPE); asm.num(0, '_empty'); asm.equalVerify()
  asm.discard(KB1); asm.discard(KB2)
  for (const n of [TX, TY, CX, CY, GX, GY]) asm.discard(n)

  // undo the offset, which has been doubled along with everything else
  const off = ecJs.neg(ecJs.mul(1n << BigInt(bits), H))
  asm.num(off.x, '_ox'); asm.num(off.y, '_oy')
  asm.roll(AX); asm.roll(AY); asm.roll('_ox'); asm.roll('_oy'); asm.roll('_fi')
  apply(asm, add, pp, [AX, AY, '_ox', '_oy', '_fi'], out)
  asm.roll(out[0]); asm.roll(out[1]); asm.discard(PN); asm.discard(PN2)
  asm.roll(out[0]); asm.roll(out[1])
  return asm
}

module.exports.emitShamir = emitShamir
module.exports.shamirWitness = shamirWitness
module.exports.shamirInputs = shamirInputs
