# The map

Start here.

**[limits.md](limits.md)** — what the interpreter actually does, measured rather
than quoted. Numbers are arbitrary precision to 750,000 bytes and `OP_MUL` works
at 4096 bits, which is the fact everything else rests on; `OP_MOD` is truncated
rather than Euclidean; `OP_NUM2BIN` writes a signed number; the stack is capped
at 1000 elements and that cap decides the shape of anything with a large witness.
Every statement is a passing probe in `tools/probe-limits.js`.

**[modules.md](modules.md)** — the module contract. What `model` and `emit` are,
the calling convention, kinds and why a byte string handed to `OP_ADD` is a
build-time error here, parameters, composition through `apply()`, branches, and
refusal cases.

**[witnesses.md](witnesses.md)** — the part that decides whether a module can be
trusted inside someone else's covenant. Some operations are far cheaper to check
than to compute, so the spender supplies the answer; a module that takes a
witness owes both soundness *and* canonicity, and the difference between those
two is where the bugs live. Four worked examples, three of them real bugs.

**[optimization.md](optimization.md)** — sixteen techniques, each a measured
before-and-after. The first nine took the elliptic-curve modules down by 70%:
deferring modular reduction to where canonicity is actually required, hoisting
constants, the altstack, `OP_WITHIN`, one ladder for two scalars. The last seven
came out of the pairing and are larger in scale — sharing an accumulator across
k pairings, turning a 1,270-bit exponent into 315 squarings, and the one that
generalises furthest: **in Script, affine beats projective, because a witnessed
inversion is four multiplications and the received wisdom is a CPU's, not a
locking script's.** With what was tried and rejected, including two failed
attempts at a formula that were thrown away rather than published.

**[mainnet.md](mainnet.md)** — the thirteen that are deployed and spent on BSV
mainnet, generated from `deployments.json` and checked against the chain, and
the exact limits of what that shows: relayable and spendable today, which is not
the same as cryptographically sound. The largest is a 333,676-byte locking
script running the whole Miller loop of a BLS12-381 pairing.

**[catalog.md](catalog.md)** — every module, generated from the registry: what
it takes, what it returns, and which of its inputs the *spender* supplies. That
last column is the one to read first.

**[pairing.md](pairing.md)** — what a BLS12-381 pairing costs in Script. The one
claim this repository could not put a number on for a long time — "ZK
verification reduces to field arithmetic" is true and is not a number. It is
817,031 bytes, and it is not arrived at by counting: `npm run pairing:prove`
emits the whole pairing as one locking script and runs it through the
interpreter. A Groth16 verifier is 1,240,810 and `npm run groth16` runs that
too, accepting a valid proof and refusing two forged ones. The Miller loop is on
mainnet, and compressed squaring has brought the final exponentiation under the
script-size policy as well.

**[../paper/paper.md](../paper/paper.md)** — the preprint draft: what was
computed, under what assumptions, how correctness was established, what the
network verified, what it consumed, and what general technique it demonstrates.
Its tables come from `results.json`, and `npm test` fails if either drifts from
the code — including a check that the prose still quotes the figures it claims.

**[cost.md](cost.md)** — what every module costs, generated from the code.

<!-- cost:line -->
RSA verification is 969 bytes; SHA-256 rebuilt from primitives is 49,181; ECDSA over an arbitrary message is 59,191. Reading those three against each other is most of what there is to know about lowering an algorithm into Script.
<!-- /cost:line -->

## The modules

| | |
| --- | --- |
| `src/modules/int.js` | `modadd` `modsub` `modmul` `modexp` `modinv` |
| `src/modules/bytes.js` | `reverse` `beToNum` — the endianness bridge |
| `src/modules/u32.js` | `rotr` `shr` `xor` `add` `ch` `maj`, and SHA-2's four mixing functions |
| `src/modules/sha256.js` | SHA-256 rebuilt from primitives — the control experiment |
| `src/modules/rsa.js` | RSA-2048 PKCS#1 v1.5 verification |
| `src/modules/hmac.js` | HMAC-SHA256 and HMAC-SHA1 over the native hash opcodes |
| `src/modules/totp.js` | RFC 6238 authenticator codes |
| `src/modules/ec.js` | point addition, doubling, and two ladders |
| `src/modules/ecdsa.js` | ECDSA verification over an arbitrary message |
| `src/modules/schnorr.js` | BIP-340 Schnorr, checked against the BIP's own vectors |
| `src/modules/merkle.js` | membership in a committed tree |
| `src/modules/state.js` | rules about which successor is legal |
| `src/modules/tx.js` | reading the spending transaction, via OP_PUSH_TX |
| `src/modules/fp2.js` | Fp2 = Fp[u]/(u² + 1) — the field a pairing tower stands on |
| `src/modules/fp6.js` | Fp6 = Fp2[v]/(v³ − ξ), built by calling the Fp2 modules |
| `src/modules/fp12.js` | Fp12 — multiply, square, cyclotomic square, sparse line, Frobenius, inverse |
| `src/modules/g2.js` | the Miller loop's step function on the twist |
| `src/modules/pairing.js` | the Miller loop, the final exponentiation, and products of pairings |
| `src/modules/groth16.js` | a Groth16 verifier for a statement fixed at lock time |

## The apparatus

| | |
| --- | --- |
| `src/run.js` | evaluate a fragment, or a spend that has to sign, against the interpreter |
| `src/asm.js` | the stack-tracking, type-tracking assembler |
| `src/module.js` | the module contract, `requires`/`ensures`, and `apply()` |
| `src/facts.js` | what is known about a value: discharged, emitted, or refused |
| `src/testkit.js` | correctness, stack discipline, refusal, forgery |
| `src/compose.js` | `all()` conjunction, `pipe()` chaining |
| `src/recipes.js` | compositions worth a name |
| `src/predicate.js` | a module with no outputs, as a deployable coin |
| `src/index.js` | the library, and the registry the catalogue is generated from |
| `src/onchain.js` | fund an output, spend it, verify before broadcasting |
| `src/woc.js` | the only network this repository touches |
| `src/num.js` | script numbers: little-endian, sign-magnitude, minimal |
| `src/bigint.js` `src/rsa.js` | the reference mathematics |
| `src/ec.js` | short Weierstrass curves — `secp256k1`, `bls12381G1`, and the `curve()` that makes both |
| `src/bls12381.js` | a whole BLS12-381, instrumented, checked against `@noble/curves` |

## The checks

```bash
npm test                # everything below, in order
npm run probe           # what the interpreter does
npm run selftest        # eight deliberate bugs the kit must catch
npm run fuzz            # the model against the Script, on inputs nobody chose
npm run rfc6238         # the JS reference against RFC 6238's published vectors
npm run bip340          # the JS reference against BIP-340's published vectors
npm run ec              # src/ec.js against the library's own secp256k1
npm run merkle          # the tree against the library's own block merkle tree
npm run malleability    # RSA's s + n and ECDSA's n − s, with the rule on and off
npm run cost            # regenerate cost.md from the code
npm run pairing         # what a BLS12-381 pairing costs, from first principles
npm run pairing:prove   # emit e(P, Q) and run it through the interpreter
npm run groth16         # emit a Groth16 verifier and run it, valid proof and two forged
npm run catalog         # regenerate catalog.md from the registry
npm run results         # measure everything into results.json
npm run paper           # results.json, then the paper's tables
npm run verify:chain    # every deployed txid, against the chain (needs network)
npm run deploy          # list the deployable targets; --broadcast to send one
node bin/sequence.js counter|budget   # run a stateful coin on chain, step by step
```

Eight examples, all spending against the real interpreter:

```bash
node examples/totp-lock.js     # the whole path in five lines, via predicate()
node examples/totp-timelock.js # a code bound to the time the coin is locked to
node examples/authority-pays.js # a payment an authority directs, not merely permits
node examples/counter-coin.js  # a coin that can only be spent by advancing itself
node examples/budget-coin.js   # a coin with a spending ceiling nobody can raise
node examples/vault-lock.js    # three conditions, one coin, via all()
node examples/rsa-lock.js      # a coin an RSA authority unlocks
node examples/oracle-lock.js   # a coin an oracle's ordinary secp256k1 key unlocks
```

## How anything here gets believed

Every claim in this repository is settled the same way, and the order matters
because each step can fail independently of the ones before it.

1. **A model.** Plain JavaScript that says what the answer is. Never the same
   code as the Script — a schedule and its specification have to be able to
   disagree.
2. **An emitter.** Script, through an assembler that tracks the stack and the
   type of every value, so that handing a byte string to `OP_ADD` is a
   build-time error rather than a wrong answer.
3. **The interpreter.** `bsv.Script.Interpreter`, under relay policy flags —
   not a simulation of it.
4. **Attack.** Every witnessed input gets forged: near misses, off-by-p,
   sign flips, zero, the modulus itself. A module owes soundness *and*
   canonicity, and the second is where the bugs were.
5. **A second opinion.** RFC 6238's vectors, BIP-340's vectors, the library's
   own secp256k1, its own Merkle root, `@noble/curves` for the pairing. One
   implementation agreeing with itself is not evidence.
6. **Measurement.** Emit it and count the bytes. Nothing is estimated that can
   be emitted.
7. **The network.** Deploy it, spend it, and rebuild the deployed script from
   the code to check it is the same bytes.

Where a step cannot be taken, the document says so and says what is missing
instead of rounding it off.

## Where this sits

The predicate side of this work — covenants, `OP_PUSH_TX`, state machines, and
forty-five predicates deployed and spent on mainnet — is **predicate bench**.
This repository is the layer beneath the mathematics those predicates assume:
what a predicate can compute and check, and what each of those costs.
