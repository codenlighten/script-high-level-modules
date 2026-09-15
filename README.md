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

Sixteen of these are deployed and spent on BSV mainnet, a seventeenth is funded and awaiting a miner that will take its spend, and the first five are
**confirmed in block 965487**. The two largest are the **complete 63-round
Miller loop of a BLS12-381 pairing** — 333,676 bytes, 63 tangents, 5 chords, 68
sparse line products and 68 witnessed Fp2 inversions — and the **complete final
exponentiation**, 474,207 bytes, in a field Bitcoin has no opcode for.

**Both stages of a BLS12-381 pairing have executed on the network** — the
complete Miller loop at 333,676 bytes and the complete final exponentiation at
474,207 — which is 98.7% of a pairing by bytes, in two transactions. The second
reached the chain only because compressed cyclotomic squaring took it from
592,008 bytes to 473,466, across the 500 KB policy boundary.

What has *not* run on chain is the chaining: a pairing in one script is 817,031
bytes, past the policy. So the composition moves out of the script and into the
**transaction** — `npm run pairing:split` puts the Miller loop in input 0 and
the final exponentiation in input 1 of one spend, bound by a shared output
commitment, and the interpreter accepts both. Neither script contains the
other's code. That is on mainnet.

The same idea takes a **whole Groth16 verifier** across three inputs.
`npm run groth16:split` cuts the Miller loop itself, at round 31 of 63 — it has
to, because three pairings sharing one accumulator are 705,838 bytes of loop
alone, over the policy before the final exponentiation is considered. The three
stages lock in 399,402 / 371,834 / 475,647 bytes, with A and C checked into G1
in the first and B into G2 in the second; all three are accepted, and the
2,156-byte output they all commit to is what makes them one computation. The
proof being verified is snarkjs's, for *"at least 21 years old as of 2026"*.
Its three coins are **funded on mainnet** — [`025f20f1`](https://whatsonchain.com/tx/025f20f1d4156aa354afef37b1ec67e5c461f11375bc739902845a3b985dc5f0), block 966,795 —
but the spend, [`cad6d2cc`](https://whatsonchain.com/tx/cad6d2cca44fffb2f445009f392b668382d79d120b1c14db0fd4a8d192204bb6), **has not been mined**: miners' nodes refuse it
with `too-long-validation-time`. It verifies; it takes about 1.4× as long to
validate as the pairing spend that did confirm, and nodes limit validation time
per transaction.

Two of the deployments are not single spends but **sequences** — a
coin advancing its own counter 0 → 1 → 2 → 3, and a coin paying three different
people out of an allowance that falls 1500 → 900 → 400 → 0. In each, every
transaction pays the output the next one consumes, so the state is not recorded
alongside the chain: the state **is** the chain. A spend the network accepted is the only evidence
that leaves no room for the harness to have been wrong — it means a node ran the
locking script against the unlocking script and agreed, and a miner put it in a
block.

| module | locking script | deploy → spend |
| --- | ---: | --- |
| `rsa.verify` | 981 B | [`37c0c7a7`](https://whatsonchain.com/tx/37c0c7a7109054820e9951f484bf16f9838630e1a642d976147a5282f76d6b7c) → [`4b716dae`](https://whatsonchain.com/tx/4b716dae581fee37692d7820d12e15b67c2260eb0fe68bb35468f9f883bfdacc) |
| `ecdsa.verify` | 59,297 B | [`fe4184c0`](https://whatsonchain.com/tx/fe4184c05bbd3d41a0ea5641afc571c46fac7dac35577b9887a783081b382576) → [`1a8f52d1`](https://whatsonchain.com/tx/1a8f52d14c0e6a060f20714e75058a6a67e343034e2e8b3e8d3f30381bb4fbef) |
| `schnorr.verify` | 59,721 B | [`28d106a6`](https://whatsonchain.com/tx/28d106a6cff81c70b8507fa0cc2352ca00965adb86281d209edd2022b4e21c6e) → [`4a2bafc9`](https://whatsonchain.com/tx/4a2bafc98fd0789204c20f2be992c1264852399a57c7b20dc05d0a4a3a55d0cb) |
| `sha256.block` | 49,240 B | [`4cbc7f96`](https://whatsonchain.com/tx/4cbc7f96da81f7877af29a944b522cbf79731c2542e113f4a41cae39b95c205a) → [`406026bd`](https://whatsonchain.com/tx/406026bde4cf02e1c63923b87d7f5859d20eb8bee74279cfbc835a0f049b6503) |
| `rsa.verify ▸ tx.hashOutputs` | 1,386 B | [`186ff18e`](https://whatsonchain.com/tx/186ff18e5e480b9065794fc330a6ed5c4f695aae4f997403bd7c510ea77fd946) → [`8edf5581`](https://whatsonchain.com/tx/8edf55810ab7726e67807ccda04d0617daf237c1a1a158c5d89015c97f452320) |
| `tx.locktime ▸ totp.verify` | 746 B | [`15dfa4c4`](https://whatsonchain.com/tx/15dfa4c4ea56ad73d9f48215a250a27a9662a26f044dc9583e7d4fe65ff1f6ee) → [`0d58f227`](https://whatsonchain.com/tx/0d58f2275205f67da6a140798cd5225b1de0d9eadf607bc54e125c5268b9a934) |
| `tx.transitionPaying ▸ state.limit` | 510 B | [`3226e448`](https://whatsonchain.com/tx/3226e448dc8a5c5194a4fc2e4168e702ebde36eed2ec14652b05e1a243a0523a) → [`f7e60726`](https://whatsonchain.com/tx/f7e607262ae7823d3e9e8a5fe1d0d0ff764917ad1ac63b13fa4cf4ad0ac4c6ad) → [`cb39e8c6`](https://whatsonchain.com/tx/cb39e8c6e9dba217fec870cbf44f84698c78a3daa013c25759b1e9526bd2e6c4) → [`5f26ba03`](https://whatsonchain.com/tx/5f26ba03e13ce017ded181ce742a2540a2985a08f4d234374f1d3caa69020a95) |
| `tx.transition ▸ state.counter` | 470 B | [`eb58479a`](https://whatsonchain.com/tx/eb58479abf8ab19ad7baaff4ee8a3288ad2e7c3fafafaca3f989c7771d1acc50) → [`0b41407f`](https://whatsonchain.com/tx/0b41407f3d7dc2389ecb13ff7bde3f3b1fa96c5e3a70f8041413417623db174c) → [`1531805b`](https://whatsonchain.com/tx/1531805bfce61981cb73fcc60cf271cfd3f48149a1fa0d93d13c84c85e4440a7) → [`46674b29`](https://whatsonchain.com/tx/46674b294303cdc9df2bf2dde4d615515b8b5ef41c6f98ba239936720e041231) |
| `vault` | 433 B | [`0b3055d5`](https://whatsonchain.com/tx/0b3055d52367223d1bc011afe5f8a3d866b319f3c1ed695c257ddf4e64f83e88) → [`8ffb6ecb`](https://whatsonchain.com/tx/8ffb6ecb8f251c8cdcdf683ea2da11d359d859674c48442f27f7f8a8aeb08b73) |

`npm run verify:chain` re-derives each locking script from the code and compares
it byte for byte against what is in the output — so it goes red if the modules
drift from what was deployed. See [mainnet.md](docs/mainnet.md).

An earlier `ecdsa.verify` and `rsa.verify` are also on chain and superseded — the
log records the script **as deployed** and says separately whether the code still
builds it, because a module that has since been corrected must build something
else. See [mainnet.md](docs/mainnet.md).

Total for all eight, at the 50 sat/KB they were sent at: about 14,600 satoshis.
At the 100 sat/KB this wallet now pays, about 29,000.

## A post-quantum signature

Script's only signature opcode is ECDSA, which a large quantum computer breaks.
`slhdsa.spend` is a coin that moves only for an **SLH-DSA-SHA2-128s signature
(FIPS 205)** over its own spending transaction — a hash-based signature whose
security rests on SHA-256 alone, verified out of `OP_SHA256`, `OP_CAT` and
`OP_SPLIT` in a **75,324-byte locking script**. The 7,856-byte signature is one
push; OP_PUSH_TX binds it to the transaction's sighash; no elliptic-curve key is
needed to spend.

It is checked against a reference written from the standard, which is checked
against `@noble/post-quantum`, and every region of the signature is forged and
refused. It validates in about 174 ms in the interpreter, against 2,793 ms for the
pairing spend that was mined. It is deployed and spent on mainnet — funding
[`44db75c3`](https://whatsonchain.com/tx/44db75c3235ea1aa18e42284657f29cd700cdc8e9f6cfff687da042b124b7de6),
spend [`a2fd9e75`](https://whatsonchain.com/tx/a2fd9e753507835558e28dd0b4764cee45df33ed1b64a5db94ea2ace1482fd86),
both validated and relayed by GorillaPool's node and awaiting a block. The key is
a public test key. See [docs/postquantum.md](docs/postquantum.md).

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
- **[pairing.md](docs/pairing.md)** — what a BLS12-381 pairing costs in Script,
  and a Groth16 verifier: counted, not estimated.
- **[paper/paper.md](paper/paper.md)** — the preprint draft, with its tables
  generated from `results.json` and its prose figures checked against the code.

## What it is for

```
npm run demo
```

A coin that only moves for someone over 21.

```
the statement    "I am at least 21 years old as of 2026."
public           the year, and the age required
private          the birth year — never on chain, never in the proof

the prover       snarkjs, Groth16 over BLS12-381
the verifier     Bitcoin Script — 1,246,986 bytes, no pairing opcode
```

| | |
| --- | --- |
| a valid proof of the right statement | the coin moves |
| a proof from someone underage | the coin does not move |
| a valid proof of a **different** statement | the coin does not move |
| the valid proof with a point moved out of its subgroup | the coin does not move |

The third is the one worth looking at twice. It is the *same* proof, from the
same prover, and it is valid — for a claim the second coin did not make. The
public inputs are compiled into the locking script, so "at least 21" and "at
least 30" are different coins and a proof of one is not a key to the other.

The underage case is worth a second look too: snarkjs's prover does not check
the constraints, so someone underage **can** produce a proof-shaped object. It
does not verify, and Bitcoin is what notices.

Every one of those refusals is the interpreter's. Until recently the test kit
counted a refusal case whose spend it could not build as refused — and these
were such cases, so for a while "the coin does not move" had not been put to the
interpreter at all. They have been now, and they refuse (paper §10.4).

Nothing about the birth year reaches the chain. The network learned that a
person was old enough, and nothing else, and enforced payment on that basis.

**Its coins are on mainnet; its spend is not yet.** At 1,246,986 bytes the verifier
is past the 500 KB script policy, so it went on chain the way a whole pairing did
— as coins spent together, three rather than two:

| input | | locking | unlocking |
| --- | --- | ---: | ---: |
| 0 | A, C ∈ G1; rounds 1–31 of three Miller loops | 399,402 | 424,186 |
| 1 | rounds 32–63; B ∈ G2 | 371,834 | 383,299 |
| 2 | the final exponentiation | 475,647 | 481,527 |
| output | the state all three commit to | 2,156 | — |

Every script is under the policy. `node bin/deploy-groth16.js` built the funding
and the spend with the same code the tests use, verified all three inputs
against the real funding txid, and broadcast them:
funding [`025f20f1`](https://whatsonchain.com/tx/025f20f1d4156aa354afef37b1ec67e5c461f11375bc739902845a3b985dc5f0), mined in block 966,795, and spend
[`cad6d2cc`](https://whatsonchain.com/tx/cad6d2cca44fffb2f445009f392b668382d79d120b1c14db0fd4a8d192204bb6), which miners have refused for its validation time. The
limit that binds now is per transaction, which is the unit this construction put
all three stages into.

## What is here

```
src/run.js            evaluate a fragment against bsv.Script.Interpreter
src/asm.js            a stack-tracking, type-tracking assembler
src/module.js         the module contract, and apply() — how two modules compose
src/facts.js          what is known about a value, and who has to prove it
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
src/modules/schnorr.js BIP-340 Schnorr, x-only keys
src/modules/merkle.js membership in a committed tree
src/modules/tx.js     reading the spending transaction: locktime, outputs, succession
src/modules/state.js  rules about which successor is legal
tools/                probes, self-tests, the cost report
fixtures/             a throwaway RSA-2048 key, so the suite is deterministic
```

Three of the probes measure a consensus fix this work turned up in
`@smartledger/bsv` — the stack limits diverged from the node in both directions,
and are now era-derived and checked after every opcode (released in 9.7.0; see
[limits.md](docs/limits.md)). They are skipped, with a note, on a library that
predates it. Nothing else here depends on that fix.

75 modules, 357 cases, 1,367 forgery attempts, all green.

## The three claims a module must earn

**It computes what the model says.** Not in a simulator — `bsv.Script.Interpreter`,
the evaluator that validates blocks, under the flags a node relays with
(MINIMALDATA, CLEANSTACK, SIGPUSHONLY, LOW_S, NULLFAIL, DISCOURAGE_UPGRADABLE_NOPS,
NULLDUMMY). `sha256.block` is checked against OpenSSL's digest rather than against
a second implementation of the same misreading, `totp` against RFC 6238's
published vectors, and `schnorr` against BIP-340's — including its ten
**negative** vectors, run through the Script as spends that must be refused.

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

**It says what it requires, and the framework places the checks.** Three modules
here documented a precondition and did not enforce it — all three green, one of
them returning a non-canonical negative result. A module now states its contract,
every stack value carries what is known about it, and at each call a requirement
is discharged from an upstream fact, emitted as a check, or **refused**: some
obligations, like a preimage being this transaction, cannot be checked in Script
at all, and emitting something that looks like a check would be worse than
nothing. Applied to the curve modules it reproduced the hand-placed bounds byte
for byte and added one I had missed.

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

And the cases are the ones somebody thought of, which is where all four of those
bugs lived. `npm run fuzz` generates inputs instead — twenty-three modules, sampled
toward the edges — and checks both that the Script agrees with the model and that
the module's own promise about its output holds. The domains come from
`requires`, so the declaration that places the bounds also says what the module
is defined on.

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
| `int.modmul` | 2048-bit modulus | 279 |
| `int.modexp` | e = 65537, 2048-bit | 355 |
| `rsa.verify` | RSA-2048, PKCS#1 v1.5 | 969 |
| `hmac.sha256` | a 32-byte key | 175 |
| `totp.verify` | RFC 6238, 6 digits | 269 |
| `tx.locktime` | OP_PUSH_TX + nLockTime | 410 |
| `merkle.verify` | depth 32 (4 billion leaves) | 905 |
| `ec.add` | secp256k1, witnessed inverse | 167 |
| `fp2.mul` | BLS12-381, Karatsuba | 117 |
| `fp12.mul` | BLS12-381 | 3,248 |
| `u32.add` | one addition mod 2³² | 58 |
| `sha256.block` | one block, no `OP_SHA256` | 49,181 |
| `ec.mul` | k·P, 256-bit, both runtime | 42,112 |
| `ecdsa.verify` | arbitrary message, secp256k1 | 59,191 |
<!-- /cost:table -->

RSA verification — a scheme Bitcoin has no opcode for — costs under a kilobyte,
because every operation it needs is one Script opcode at any width. SHA-256
rebuilt from those same primitives costs **49,181×** what `OP_SHA256` costs for
the same answer, because 32-bit modular addition is *not* one opcode and pays for
two endianness conversions every time.

Both are the same technique. The difference is only whether the primitive you
need is already an opcode — and it is worth four orders of magnitude. This is the
number to compute *before* lowering a new algorithm, not after.

The same method, run to the end of its rope: `fp12.mul` is one multiplication in
the degree-12 extension field a pairing lives in, and 342 cyclotomic squarings
and 63 of these are what a final exponentiation is. **A BLS12-381 pairing is
817 KB of Script and a Groth16 verifier is about 1.25 MB.**

It is not an estimate. `npm run pairing:prove` emits `e(P, Q)` as **one
817,085-byte locking script**, runs it through `bsv.Script.Interpreter` under
relay policy flags, and checks all twelve Fp12 coefficients against a reference
that matches `@noble/curves` byte for byte — 538,767 opcodes, about thirty
seconds, part of `npm test`. (The tables say 817,031: that is the pairing with its
inputs already known to be reduced, as they are inside a composition; standalone
it bounds them itself.) 208 of the numbers in the unlocking script are
witnesses the spender chooses, and every one is bounded into [0, p) and checked.

And a **Groth16 verifier** — `e(A,B)·e(−L,γ)·e(−C,δ) = e(α,β)` — is
`npm run groth16`: three pairings folded onto one accumulator, with A, B and C
checked into their prime-order subgroups, **1,246,986 bytes, 786,448 opcodes**,
accepting a valid proof and refusing six invalid ones. Three separate pairings
would be 2.45 MB; as a product they are 1.23, because k pairings share the 63
squarings and the one final exponentiation.

**Subgroup membership costs 17,790 bytes — 1.4% of the verifier.** A point can
satisfy its curve equation and lie outside the order-r subgroup the pairing is
defined on, so A and C are checked by φ(P) = [−x²]P on G1 (two 63-bit witnessed
ladders, 8,517 bytes each) and B by ψ(Q) = [x]Q on G2 — which is nearly free,
because a Miller loop over B has already computed [|x|]B by the time it ends.
Every fact those tests rest on, down to the twist's group order and
gcd(h₁, h₂) = 1, is computed by `npm run subgroup` rather than recalled, and
checked there against `@noble/curves`' own torsion test.

`npm run groth16:split` runs that verifier as three stages across three inputs
of one transaction — proving each stage against the interpreter with forged
witnesses refused, then building the spend the network would see. It also
isolates the subgroup checks: stages 1 and 2 are built with them and without,
given a point on its curve and outside its subgroup, and must accept without
them and refuse with them. And it changes which transaction field carries the
OP_PUSH_TX nonce: one preimage in fifty is canonical, so a *triple* lands once in
~123,000, and `nSequence` is the wrong knob because it also sits inside
`hashSequence` at offset 36. `nLockTime` appears once, eight bytes from the end,
so every SHA-256 block but the last is reusable — 168,127 tries in 2.5 seconds
instead of rehashing 400 KB apiece.

`npm run groth16:external` runs the same verifier against a proof **snarkjs**
generated over BLS12-381 — an independent trusted setup, prover and field
implementation. It is accepted; a displaced proof, points off their curves and
points outside their subgroups are refused; and the same valid proof is refused
by a verifier built for a different public input, because the statement is a
compile-time constant and therefore a different coin.

`npm run audit` is this repository trying to break its own soundness
assumptions, and five of its findings have changed the code.

The newest one is the sharpest. The split construction binds its stages through
`hashOutputs`, which pins the **bytes** the inputs agree on — and says nothing
about **which inputs are present**. Spend the final-exponentiation coin alone
and its covenant is satisfied trivially; all that is left is finding an f with
F(f) = e(P,Q), and since F is exponentiation by d = 3(p¹²−1)/r against a target
of order r with gcd(d, r) = 1, `f = e(P,Q)^(d⁻¹ mod r)` does it in two modexps.
`npm run attack:siblings` runs that against the interpreter and the coin is
accepted. The fix is `hashPrevouts`, the field none of this code read: rebuild
the spend's whole outpoint list from one witnessed txid, match its hash, and
require this input to be the slot it claims — 47 bytes at two stages, 56 at
three. Every stage of the three-way split uses it. The two-way pairing split is
already on chain and its bytes are the record, so it is reported as it stands
rather than quietly amended. **All 1,970 numeric
witnesses — the library's and every stage of the three-way split — are
bounded**, checked by provenance rather than by sampling attacks: a slot carries
the input it descends from, and every bound records it. Chasing a false positive
from that check exposed a true one: the attack generator looked for the modulus
under `params.n` and the curve modules call it `p`, so the *same-residue* attacks
were silently skipped for every `ec.*` module for as long as they have existed.

The audit also found that A, B and C were never checked to be **on the curve**,
and then that they were never checked to be **in their subgroups** — its
longest-standing finding, closed now at 17,790 bytes (above). The audit keeps a
list of accepted findings and fails on anything not on it; the only entry left is
the two-way split already on chain, which predates sibling binding.

Its soundness is not the arithmetic, it is who chooses what: **only A, B and C
come from the unlocking script**, while γ, δ and L are constants the locking
script pushes. A spender who could choose γ could choose one that satisfies the
equation for a proof of nothing. `npm test` asserts that separation on every
run. L is a constant because the statement is fixed when the coin is locked —
which is what makes the public-input combination free rather than 40 KB per
input.

The pricing model that preceded all of it was low by 6% on the Miller loop and
high by 8.7% on the final exponentiation, for two different and identifiable
reasons. See [docs/pairing.md](docs/pairing.md).

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
