# Script Modules

*High-level mathematics and cryptography, compiled into Bitcoin Script modules
that are tested, priced, and reusable.*

Bitcoin Script has no `OP_CHECKRSASIG`. It does not need one.

RSASSA-PKCS1-v1_5 verification is a single equation — `s^e mod n` compared with a
constant and one hash — and post-Genesis Script does arbitrary-precision modular
arithmetic in one opcode. This repository verifies a **2048-bit RSA signature
produced by OpenSSL** inside a locking script, against the real consensus
interpreter, in **955 bytes**.

That is one module. The idea underneath it is the point:

> If a cryptographic protocol reduces to deterministic mathematics expressible
> in Script's primitives, it can be compiled into a locking predicate without
> Bitcoin needing to understand the protocol. The semantics live above Script;
> consensus only has to agree on the primitives.

So the unit of work is a **module**: one operation, written twice — once as
mathematics in JavaScript, once as Script — with a test kit that proves the two
agree on the real interpreter, and proves what the module *refuses*.

## Quick start

```bash
npm install
npm test                         # every module against the consensus interpreter
npm run probe                    # what the interpreter actually does (measured)
npm run cost                     # what every module costs, in bytes
npm run malleability             # RSA's s + n and ECDSA's n − s, rule on and off
node examples/rsa-lock.js        # a coin an RSA authority unlocks
node examples/oracle-lock.js     # a coin an oracle's ordinary secp256k1 key unlocks
```

## On chain

Five of these are deployed and spent on BSV mainnet. A spend the network
accepted is the only evidence that leaves no room for the harness to have been
wrong — it means a node ran the locking script against the unlocking script and
agreed.

| module | locking script | deploy → spend |
| --- | ---: | --- |
| `rsa.verify` | 981 B | [`37c0c7a7`](https://whatsonchain.com/tx/37c0c7a7109054820e9951f484bf16f9838630e1a642d976147a5282f76d6b7c) → [`4b716dae`](https://whatsonchain.com/tx/4b716dae581fee37692d7820d12e15b67c2260eb0fe68bb35468f9f883bfdacc) |
| `ecdsa.verify` | 59,247 B | [`2e283079`](https://whatsonchain.com/tx/2e2830799509ba4f7dd4cd56f9c88d80dda5ad0b2bd23083c3725e7546b08d46) → [`3d4e284f`](https://whatsonchain.com/tx/3d4e284f9bb7e6d2b6d1b8070c90752e4ee32dacd36c9186d52b929509559467) |
| `sha256.block` | 49,240 B | [`4cbc7f96`](https://whatsonchain.com/tx/4cbc7f96da81f7877af29a944b522cbf79731c2542e113f4a41cae39b95c205a) → [`406026bd`](https://whatsonchain.com/tx/406026bde4cf02e1c63923b87d7f5859d20eb8bee74279cfbc835a0f049b6503) |
| `tx.locktime ▸ totp.verify` | 746 B | [`15dfa4c4`](https://whatsonchain.com/tx/15dfa4c4ea56ad73d9f48215a250a27a9662a26f044dc9583e7d4fe65ff1f6ee) → [`0d58f227`](https://whatsonchain.com/tx/0d58f2275205f67da6a140798cd5225b1de0d9eadf607bc54e125c5268b9a934) |
| `vault` | 433 B | [`0b3055d5`](https://whatsonchain.com/tx/0b3055d52367223d1bc011afe5f8a3d866b319f3c1ed695c257ddf4e64f83e88) → [`8ffb6ecb`](https://whatsonchain.com/tx/8ffb6ecb8f251c8cdcdf683ea2da11d359d859674c48442f27f7f8a8aeb08b73) |

`npm run verify:chain` re-derives each locking script from the code and compares
it byte for byte against what is in the output — so it goes red if the modules
drift from what was deployed. See [mainnet.md](docs/mainnet.md).

Total cost of the five, at 0.05 sat/byte: about 6,600 satoshis.

## Documentation

**Start at [docs/index.md](docs/index.md)** — the map. The individual documents:

- **[limits.md](docs/limits.md)** — what the interpreter actually does, measured
  rather than quoted: 4096-bit `OP_MUL`, truncated `OP_MOD`, signed
  `OP_NUM2BIN`, and the 1000-element stack cap that decides the shape of
  anything with a large witness.
- **[modules.md](docs/modules.md)** — the module contract: `model` and `emit`,
  the calling convention, kinds, composition through `apply()`, refusal cases.
- **[witnesses.md](docs/witnesses.md)** — soundness *and* canonicity, the
  difference between them, and four worked examples of what happens when the
  second one is skipped.
- **[mainnet.md](docs/mainnet.md)** — the deployments, and what a confirmed
  spend does and does not prove.
- **[optimization.md](docs/optimization.md)** — how the curve modules halved:
  deferred reduction, hoisted constants, the altstack, `OP_WITHIN`.
- **[catalog.md](docs/catalog.md)** — every module, generated from the registry:
  inputs, outputs, and which inputs the *spender* supplies.
- **[cost.md](docs/cost.md)** — what every module costs, generated from the code.

## What is here

```
src/run.js            evaluate a fragment against bsv.Script.Interpreter
src/asm.js            a stack-tracking, type-tracking assembler
src/module.js         the module contract, and apply() — how two modules compose
src/testkit.js        correctness, stack discipline, and forgery
src/compose.js        all() conjunction, pipe() chaining
src/recipes.js        compositions worth a name
src/predicate.js      a module with no outputs, as a deployable coin
src/index.js          the library, and the registry behind the catalogue
src/num.js            script numbers: little-endian, sign-magnitude, minimal
src/bigint.js         the reference mathematics
src/modules/int.js    modadd modsub modmul modexp modinv
src/modules/bytes.js  reverse, beToNum — the endianness bridge
src/modules/u32.js    rotr shr xor add ch maj, and SHA-2's four mixing functions
src/modules/sha256.js SHA-256 rebuilt from primitives — the control experiment
src/modules/rsa.js    RSA-2048 signature verification
src/modules/hmac.js   HMAC-SHA256 and HMAC-SHA1 over the native hash opcodes
src/modules/totp.js   RFC 6238 authenticator codes
src/modules/ec.js     secp256k1 point arithmetic and two scalar ladders
src/modules/ecdsa.js  ECDSA verification over an arbitrary message
src/modules/merkle.js membership in a committed tree
src/modules/tx.js     reading the spending transaction: locktime, output binding
tools/                probes, self-tests, the cost report
fixtures/             a throwaway RSA-2048 key, so the suite is deterministic
```

Three of the probes measure a consensus fix this work turned up in
`@smartledger/bsv` — the stack limits diverged from the node in both directions,
and are now era-derived and checked after every opcode (released in 9.7.0; see
[limits.md](docs/limits.md)). They are skipped, with a note, on a library that
predates it. Nothing else here depends on that fix.

Thirty-seven modules, 195 cases, 571 forgery attempts, all green.

## The three claims a module must earn

**It computes what the model says.** Not in a simulator — `bsv.Script.Interpreter`,
the evaluator that validates blocks, under the flags a node relays with
(MINIMALDATA, CLEANSTACK, SIGPUSHONLY, LOW_S, NULLFAIL, DISCOURAGE_UPGRADABLE_NOPS,
NULLDUMMY). `sha256.block` is checked against OpenSSL's digest rather than against
a second implementation of the same misreading.

**It leaves the stack as promised.** A sentinel sits beneath every module during
its suite. A module that leaks a scratch value fails, because the next module
would read the wrong depth.

**It says what it cannot do.** `totp.verify` proves a code matches a time; it
cannot prove *which* time, because the time is a number the spender pushed. That
was written into the module as a note, and then closed: `tx.locktime` proves the
pushed preimage is this transaction — OP_PUSH_TX — reads nLockTime out of it, and
refuses a final sequence, without which consensus ignores nLockTime entirely.
Wired together (`examples/totp-timelock.js`) the code must match the time the
transaction is locked to. What that buys, exactly: the spend cannot be *mined*
before that time. Not that the time is now. A module that overstates itself is
worse than one that does less.

**It refuses everything else.** Some operations are far cheaper to *check* than
to *compute* — modular inverse is one multiplication to verify and the extended
Euclidean algorithm to derive — so a module may declare an input `witness: true`
and have the spender supply it. That is where a module goes quietly wrong, so
the kit attacks every witnessed input on two properties:

- **soundness** — no wrong witness is accepted;
- **canonicity** — no *second* witness is accepted either. `a·inv ≡ 1 (mod n)` is
  true of `inv`, of `inv + n`, of `inv + 2n`. A module that checks only the
  congruence is a function of the spender's choice, and the covenant built on it
  is malleable.

A witnessed module the kit cannot attack is reported as unproven rather than
green. The kit is itself held to this: `npm run selftest` writes five bugs
deliberately — a wrong value, a leaked stack slot, bytes read as a number, a
non-canonical witness, an unattackable one — and fails if any is missed.

`npm run malleability` shows the last of those on the real module:

```
  range check         unlocking script       verdict
  with 0 ≤ s < n      the signature          ACCEPTED
  with 0 ≤ s < n      the signature + n      refused
  WITHOUT the check   the signature + n      ACCEPTED
```

## What it costs

Full table in [docs/cost.md](docs/cost.md), generated from the code.

<!-- cost:table -->
| module | configuration | Script bytes |
| --- | --- | ---: |
| `int.modmul` | 2048-bit modulus | 262 |
| `int.modexp` | e = 65537, 2048-bit | 332 |
| `rsa.verify` | RSA-2048, PKCS#1 v1.5 | 955 |
| `hmac.sha256` | a 32-byte key | 175 |
| `totp.verify` | RFC 6238, 6 digits | 269 |
| `tx.locktime` | OP_PUSH_TX + nLockTime | 410 |
| `merkle.verify` | depth 32 (4 billion leaves) | 905 |
| `ec.add` | secp256k1, witnessed inverse | 139 |
| `u32.add` | one addition mod 2³² | 58 |
| `sha256.block` | one block, no `OP_SHA256` | 49,181 |
| `ec.mul` | k·P, 256-bit, both runtime | 42,086 |
| `ecdsa.verify` | arbitrary message, secp256k1 | 59,141 |
<!-- /cost:table -->

RSA verification — a scheme Bitcoin has no opcode for — costs under a kilobyte,
because every operation it needs is one Script opcode at any width. SHA-256
rebuilt from those same primitives costs **49,181×** what `OP_SHA256` costs for
the same answer, because 32-bit modular addition is *not* one opcode and pays for
two endianness conversions every time.

Both are the same technique. The difference is only whether the primitive you
need is already an opcode — and it is worth four orders of magnitude. This is the
number to compute *before* lowering a new algorithm, not after.

`ecdsa.verify` is the expensive end of that judgement, and worth stating plainly.
`OP_CHECKSIG` answers one question — is this a valid signature over *this*
transaction's sighash — and cannot be asked whether an oracle signed a price or a
manifest. That gap is why the BSV ecosystem reaches for Rabin signatures, which
verify with `OP_MUL` and `OP_MOD` in a few hundred bytes. The gap is in the
opcode, not in Script: 59,141 bytes buys an oracle signing with the secp256k1
key it already has, over any message at all. Whether that is worth 59 KB is an
engineering choice, not a technical limit — but it is now a choice.

## Using one

A module that asserts and returns nothing is a predicate, and `predicate()`
turns it into a coin:

```js
const { predicate, totp } = require('script-modules')

const coin = predicate(totp.verify,
  { keyLen: 20, digits: 6, step: 30, algo: 'sha1', keyCommitment },
  { owner: ownerPublicKey })

coin.lockingScript                                  // 332 bytes
coin.test({ key: secret, time, code }, ownerKey)    // spend it, against the interpreter
```

Several predicates become one with `compose.all()`, and the composition is a
module like any other — so the kit attacks the composed thing, not just the
parts. `examples/vault-lock.js` is an owner's key, a Merkle allowlist and an
authenticator code in a 436-byte lock.

`owner` has no default, on purpose. Every off-chain signature scheme here — RSA,
TOTP, an oracle's ECDSA — authorises a *message*, never a *transaction*. A coin
locked to one of them alone is a hashlock whose preimage is published the first
time it is spent, for anyone reading the block to copy. Passing `owner: null` is
allowed and says you meant it.

## Writing a module

```js
const modmul = defineModule({
  name: 'int.modmul',
  doc: 'r = (a · b) mod n',
  inputs: ['a', 'b'],
  outputs: ['r'],
  model: ({ a, b }, { n }) => ({ r: mod(a * b, n) }),
  emit: (asm, { n }) => { asm.mul('prod'); asm.num(n, '_n'); asm.mod('r') },
  cases: [
    { name: 'small',    inputs: { a: 7n, b: 9n }, params: { n: 11n } },
    { name: '2048-bit', inputs: { a: (1n << 2040n) + 7n, b: (1n << 2039n) + 11n },
                        params: { n: (1n << 2048n) - 1557n } }
  ]
})
```

On entry the declared inputs are the top of the stack in declared order; on exit
they are gone and the outputs are on top. `defineModule` refuses a module with no
cases, and refuses a witnessed input with no `hint()` to produce the honest
value. Modules call each other through `apply()`, which moves the caller's values
into the callee's input names — composition is a rename, not a concatenation.

The assembler tracks a *kind* per value, `num` or `bytes` with a width. Handing a
byte string to `OP_ADD` is the most expensive mistake in Script arithmetic — the
top bit silently becomes a sign — and it is a build-time error here.

## Where this sits

The predicate side of this work — covenants, `OP_PUSH_TX`, state machines, and
forty-five predicates deployed and spent on mainnet — lives in **predicate
bench**. This repository is the layer beneath the mathematics those predicates
assume: what a predicate can *compute* and *check*, priced.

Everything above `int` and `u32` is a composition. An authenticator code is
HMAC-SHA1 of a counter, a truncation that reads its own offset out of the digest,
and a reduction mod 10⁶ — checked against RFC 6238's published vectors. A curve
point addition is six field operations and a witnessed inverse. ECDSA is two
ladders and a comparison. None of them needed a new primitive, and none of them
needed anything from consensus.

Next, on the same principle: PBKDF2 over `hmac`, Schnorr and BIP-340 over the
same ladders (cheaper than ECDSA, and canonical by construction), Merkle
verification, and pairing-based verification equations above the field
arithmetic.

## License

[MIT](LICENSE). Verify every number in this README by running it.
