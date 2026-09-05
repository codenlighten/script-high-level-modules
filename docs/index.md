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

**[optimization.md](optimization.md)** — how the elliptic-curve modules got half
their size back: deferring modular reduction to where canonicity is actually
required, hoisting constants out of the loop, clearing temporaries with the
altstack instead of rolls, and `OP_WITHIN`. With the before-and-after, and what
was tried and rejected.

**[mainnet.md](mainnet.md)** — the five that are deployed and spent on BSV
mainnet, and the exact limits of what that shows: relayable and spendable today,
which is not the same as cryptographically sound.

**[catalog.md](catalog.md)** — every module, generated from the registry: what
it takes, what it returns, and which of its inputs the *spender* supplies. That
last column is the one to read first.

**[pairing.md](pairing.md)** — what a BLS12-381 pairing costs in Script. The one
claim this repository could not put a number on for a long time — "ZK
verification reduces to field arithmetic" is true and is not a number. It is
978 KB, and a Groth16 verifier is 1.80 MB, arrived at by counting the operations
a verified pairing performs and measuring the modules that perform them.

**[cost.md](cost.md)** — what every module costs, generated from the code. RSA
verification is 955 bytes; SHA-256 rebuilt from primitives is 49,181; ECDSA over
an arbitrary message is 59,141. Reading those three against each other is most
of what there is to know about lowering an algorithm into Script.

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
| `src/modules/ec.js` | secp256k1 point addition, doubling, and two ladders |
| `src/modules/ecdsa.js` | ECDSA verification over an arbitrary message |
| `src/modules/schnorr.js` | BIP-340 Schnorr, checked against the BIP's own vectors |
| `src/modules/merkle.js` | membership in a committed tree |
| `src/modules/state.js` | rules about which successor is legal |
| `src/modules/tx.js` | reading the spending transaction, via OP_PUSH_TX |

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
| `src/bigint.js` `src/ec.js` `src/rsa.js` | the reference mathematics |

## The checks

```bash
npm test                # everything below, in order
npm run probe           # what the interpreter does          (24 probes)
npm run selftest        # eight deliberate bugs the kit must catch
npm run fuzz            # the model against the Script, on inputs nobody chose
npm run rfc6238         # the JS reference against RFC 6238's published vectors
npm run bip340          # the JS reference against BIP-340's published vectors
npm run ec              # src/ec.js against the library's own secp256k1
npm run merkle          # the tree against the library's own block merkle tree
npm run malleability    # RSA's s + n and ECDSA's n − s, with the rule on and off
npm run cost            # regenerate cost.md from the code
npm run pairing         # what a BLS12-381 pairing costs, from first principles
npm run catalog         # regenerate catalog.md from the registry
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

## Where this sits

The predicate side of this work — covenants, `OP_PUSH_TX`, state machines, and
forty-five predicates deployed and spent on mainnet — is **predicate bench**.
This repository is the layer beneath the mathematics those predicates assume:
what a predicate can compute and check, and what each of those costs.
