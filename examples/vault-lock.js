'use strict'

// A VAULT: three independent conditions, one coin.
//
//   the owner's key       — OP_CHECKSIG, which binds the spend to this transaction
//   an allowlist          — Merkle membership in a committed set
//   an authenticator code — RFC 6238, from a secret committed by hash
//
// Each is a module that was proved separately. `all()` makes them one module,
// which the test kit then attacks as a whole — because a composition can be
// broken in ways its parts are not. `predicate()` turns that into a coin.
//
// Nothing here is a new capability. It is what the layers are for: the rules a
// business would state in a sentence, assembled from pieces whose refusals are
// already established, in a locking script under half a kilobyte.

const crypto = require('crypto')
const bsv = require('@smartledger/bsv')
const { predicate, totp, merkle, compose } = require('../src')

const owner = bsv.PrivateKey.fromBuffer(Buffer.from('77'.repeat(32), 'hex'))

// the allowlist, committed to by its root
const members = ['alice', 'bob', 'carol', 'dave']
  .map((n) => crypto.createHash('sha256').update(n).digest())
const tree = merkle.tree(members)

// the authenticator secret, committed to by its hash
const secret = Buffer.from('12345678901234567890')
const commitment = crypto.createHash('sha256').update(secret).digest()

const time = 1111111109n
const code = totp.totpCode(secret, Number(time), { digits: 6 })
const carol = tree.proof(2)

const inputs = {
  ...compose.forPart('totp_', { key: secret, time, code }),
  ...compose.forPart('merkle_', { leaf: members[2], path: carol.path, dirs: carol.dirs })
}

// A composed module is a module: it needs a case, or all() refuses to build it.
// The rule is not a formality here — a composition can be broken in ways its
// parts are not, so the thing that gets deployed is the thing that gets tested.
const rules = compose.all('vault', [
  { module: totp.verify, params: { keyLen: secret.length, digits: 6, step: 30, algo: 'sha1', keyCommitment: commitment } },
  { module: merkle.verify(tree.root, { depth: 2, leaves: members }), params: { depth: 2, root: tree.root } }
], { cases: [{ name: 'carol, on the list, with the current code', inputs }] })

const coin = predicate(rules, {}, { owner: owner.publicKey })

const honest = coin.test(inputs, owner)
const stranger = crypto.createHash('sha256').update('mallory').digest()
const refusals = [
  ['a name that is not on the allowlist', coin.test({ ...inputs, merkle_leaf: stranger }, owner)],
  ['on the allowlist, last window’s code', coin.test({ ...inputs, totp_code: totp.totpCode(secret, Number(time) - 30, { digits: 6 }) }, owner)],
  ['everything right, a stranger’s key', coin.test(inputs, bsv.PrivateKey.fromRandom())],
  ['another member’s proof, carol’s leaf', coin.test({ ...inputs, merkle_path: tree.proof(0).path, merkle_dirs: tree.proof(0).dirs }, owner)]
]

console.log(`
  A vault: the owner's key, an allowlist, and an authenticator code

  locking script     ${coin.size} bytes
  unlocking script   ${honest.unlockSize} bytes
  allowlist root     ${tree.root.toString('hex').slice(0, 32)}…
  code at t=${time}   ${String(code).padStart(6, '0')}

  carol spends, on the list, with the current code   ${honest.ok ? 'ACCEPTED' : 'refused — ' + honest.error}`)
for (const [what, r] of refusals) console.log(`  ${what.padEnd(50)} ${r.ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

const ok = honest.ok && refusals.every(([, r]) => !r.ok)
console.log(`\n  ${ok ? 'Three conditions, one coin, and every refusal was proved before it was assembled.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
