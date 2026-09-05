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

**[cost.md](cost.md)** — what every module costs, generated from the code. RSA
verification is 955 bytes; SHA-256 rebuilt from primitives is 50,765; ECDSA over
an arbitrary message is 196,778. Reading those three against each other is most
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

## The apparatus

| | |
| --- | --- |
| `src/run.js` | evaluate a fragment, or a spend that has to sign, against the interpreter |
| `src/asm.js` | the stack-tracking, type-tracking assembler |
| `src/module.js` | the module contract, and `apply()` |
| `src/testkit.js` | correctness, stack discipline, refusal, forgery |
| `src/num.js` | script numbers: little-endian, sign-magnitude, minimal |
| `src/bigint.js` `src/ec.js` `src/rsa.js` | the reference mathematics |

## The checks

```bash
npm test                # everything below, in order
npm run probe           # what the interpreter does          (24 probes)
npm run selftest        # five deliberate bugs the kit must catch
npm run rfc6238         # the JS reference against RFC 6238's published vectors
npm run ec              # src/ec.js against the library's own secp256k1
npm run malleability    # RSA's s + n and ECDSA's n − s, with the rule on and off
npm run cost            # regenerate cost.md from the code
```

Two examples, both spending against the real interpreter:

```bash
node examples/rsa-lock.js      # a coin an RSA authority unlocks
node examples/oracle-lock.js   # a coin an oracle's ordinary secp256k1 key unlocks
```

## Where this sits

The predicate side of this work — covenants, `OP_PUSH_TX`, state machines, and
forty-five predicates deployed and spent on mainnet — is **predicate bench**.
This repository is the layer beneath the mathematics those predicates assume:
what a predicate can compute and check, and what each of those costs.
