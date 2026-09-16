# Bitcoin Just Evaluated a BLS12-381 Pairing: Two Scripts, One Transaction

*No pairing opcode, no extension-field type, no inversion primitive. What an 830 KB transaction on BSV mainnet taught me about witnesses, verification, and where programmable Bitcoin is going.*

**Bitcoin as a Mathematical Machine, Part I**

---

Most developers think of Bitcoin Script as simple on purpose. It does signatures, multisig, hashlocks, timelocks. It's a small language for saying when a coin can move.

I wanted to ask a different question. Forget what Script was *designed* to do. What mathematics can you build from the operations it already has?

After the Genesis upgrade, BSV's interpreter does arbitrary-precision integer arithmetic. `OP_MUL` and `OP_MOD` work on numbers thousands of bits long. That's a small foothold, but in principle a finite field fits on it, then a tower of fields, then an elliptic curve, then a pairing.

This month the experiment got all the way to the end of that chain.

## What happened on mainnet

[Transaction `fd0f553e…2fb9e2`](https://whatsonchain.com/tx/fd0f553ee9a96b2cb48a4a9712824580910cd6056fc42f93f49eae83da2fb9e2), mined in block 965,524, spends two coins in a single transaction:

```text
input 0   the 63-round BLS12-381 Miller loop            343,799-byte locking script
input 1   the final exponentiation                      475,017-byte locking script
output    the Miller loop's result, 12 field elements       588 bytes
```

The first input runs the Miller loop and publishes its result. The second input takes that same result and raises it to the final exponent. The transaction ties the two together, so if the network accepts it, the network has confirmed that a complete BLS12-381 pairing e(P, Q) was computed correctly.

The network accepted it. The transaction is 830,928 bytes and paid 164,997 satoshis in fees.

Before that, each half was deployed and spent **on its own**:

- the **Miller loop** as one 333,676-byte locking script: 63 doublings, 5 additions, 68 line multiplications, 63 squarings in a degree-12 field, and 68 field inversions supplied by the spender and checked by the script;
- the **final exponentiation** as one 474,207-byte locking script.

Every one of those scripts is rebuilt from source and compared byte for byte against what's on chain.

I need to be precise about one thing, and I'll come back to it later: **this is not a pairing in a single script.** In one script it's 817,031 bytes, and the default relay policy is 500,000. What ran on mainnet is two scripts in one transaction, checking each other. That qualifier matters, and I won't drop it.

## Why a pairing?

BLS12-381 is the curve behind a lot of the cryptography people get excited about:

- **BLS signatures**, where many signatures collapse into one;
- **threshold schemes**, where *k of n* parties sign without anyone holding the whole key;
- **KZG polynomial commitments**, which Ethereum's data-availability roadmap is built on;
- **Groth16 and related zk-SNARKs**, where a small proof certifies a large computation.

All of these come down to checking a *pairing equation*. If Bitcoin Script can evaluate a pairing, every one of them becomes something a coin could enforce, not just something an application talks about.

## Bitcoin doesn't have to compute everything

This is the idea that made the rest possible, and it's more important than any particular byte count.

Take a modular inverse. Computing `z = a⁻¹ mod p` in Script means an extended Euclidean algorithm or a 381-bit exponentiation, which is enormous. But *checking* an inverse takes one line:

```text
a · z ≡ 1 (mod p)
```

So the script doesn't compute the inverse. The spender computes it off chain and puts it in the unlocking script. The script checks one multiplication, one reduction and one comparison.

Bitcoin never has to **trust** the value. It checks the **relationship**.

```text
Spender
   │  does the expensive work
   ▼
witnesses
   │
   ▼
Bitcoin Script
   │  checks field identities
   │  checks curve equations
   │  checks range bounds
   ▼
TRUE
```

A locking script is a verifier, and verifying is often much cheaper than recomputing.

There's a catch, and it's where most of the bugs I found were hiding. A witness has to be **sound**, meaning no wrong value is accepted. It also has to be **canonical**, meaning no *second* right-looking value is accepted either. `z` and `z + p` both satisfy `a·z ≡ 1 (mod p)`. If you don't bound every witness into `[0, p)`, a later comparison ends up comparing numbers that are congruent but not equal. An audit that asked "what can the spender choose, and is each choice pinned to exactly one value?" found four bugs like this. Three were in code whose tests passed.

### The textbook gets it backwards

This model has a consequence I didn't expect.

Standard elliptic-curve practice says inversions are expensive, so you use projective coordinates to avoid them and accept a few extra multiplications per step. That's the right call on a CPU.

Under witness-assisted verification, an inversion costs about four multiplications to *check*. The tradeoff reverses. **Affine coordinates beat projective ones**, so the Miller loop on chain is affine throughout.

The same thing happened again in the final exponentiation. There's a compressed way to square elements of the relevant subgroup, but getting back out of the compressed form costs an inversion. Normally that means you only use it for long runs of squarings. Here the inversion is cheap, so it pays off right away. That change cut the final exponentiation from 592,008 bytes to 473,466, which put it under the policy limit. That's the only reason it's on mainnet and not just in the interpreter.

The lesson carries well beyond pairings: **the best algorithm depends on the verifier's cost model.** Implementation habits built for processors don't automatically transfer.

## Computation across a transaction

A pairing doesn't fit in one relayable script. But a transaction can have more than one input.

```text
one script                         one transaction
──────────                         ───────────────
817 KB pairing                     input 0: Miller loop    → publishes f
     ✗ too big                     input 1: final exp      → consumes f
                                   output:  f  (588 bytes)
                                        ✓ each input fits
```

Every input of a transaction sees the same outputs. The Miller-loop input requires the transaction's output to be exactly its result, `f`. The final-exponentiation input requires the output to be exactly the `f` it started from. There's only one output, so both inputs must have used the same `f`. The transaction is valid only if

```text
y = FinalExp(f) = FinalExp(Miller(P, Q)) = e(P, Q)
```

Nothing in that argument is specific to pairings. Any computation too big for one script can be cut wherever the state passed between the pieces is small. Here the state is 588 bytes and the computation is 817,031.

### The hole the proof didn't mention

That argument is correct, and it still left a gap. I found the gap by attacking my own construction.

The shared output ties together *what the transaction publishes*. It says nothing about *which inputs are in the transaction*. So the final-exponentiation coin can be spent **alone**. Given a target value, there's a fake `f` that passes, and computing it takes two modular exponentiations and no Miller loop at all. I ran that forgery against the interpreter and the coin accepted it.

No money is stolen, because the covenant forbids change. But anyone who looks at that one input would conclude a computation happened when it didn't. An attacker could also spend the coin before the honest transaction, so the real result never gets published.

The fix reads a field the construction was ignoring. `hashPrevouts` commits to every outpoint the transaction spends. Each stage now checks that the transaction spends exactly the stages of its own computation, in order, and that it is the stage it claims to be. It costs 47 bytes.

To be clear: **the pairing on mainnet predates this fix.** That particular transaction did spend both stages together (anyone can check it has two inputs), so what it proves still stands. The deployed coins, though, were vulnerable to the lone-spend attack until they were spent. The attack is kept in the repository as a permanent test, not deleted once fixed.

## From pairings to proofs

The same trick scales further. A Groth16 verifier is three pairings sharing one Miller loop, and at about 1.25 MB it has to be cut three ways. It even has to be cut in the middle of the Miller loop, at round 31 of 63, because three pairings sharing one loop already come to 705,838 bytes before the final exponentiation starts. Nothing in the math makes round 31 special. It's just where the state passed between the pieces is small (44 field elements, 2,156 bytes) and each half fits.

That three-input transaction is on mainnet: [`cad6d2cc…4bb6`](https://whatsonchain.com/tx/cad6d2cca44fffb2f445009f392b668382d79d120b1c14db0fd4a8d192204bb6), 1,291,329 bytes, spending three coins created by [`025f20f1…c5f0`](https://whatsonchain.com/tx/025f20f1d4156aa354afef37b1ec67e5c461f11375bc739902845a3b985dc5f0).

It got there the hard way, and that's the more useful story. Bitcoin nodes cap how long they'll spend validating any one transaction that arrives from a peer — about a second — to stop cheap-to-send, expensive-to-check spam. This transaction takes roughly 1.5× as long as the pairing spend that sailed through. So it was valid, and it simply couldn't travel: one node held it, no miner ever saw it, and it sat there for 128 blocks until a mining pool submitted it to their own node by hand and mined it.

Size limits are per script. This one is per transaction, and it's a limit on *relay*, not on validity. The remedy is to spread the stages across transactions instead of inputs, so no single transaction asks for more than a second of anyone's time.

That version now exists, and it is on chain. The same verifier runs as three transactions chained through a small carrier coin — funding [`1c0b9af1`](https://whatsonchain.com/tx/1c0b9af1f1b39d40c3d296060a86e8847303cd5709dbd78f917ab65a2f35c9ea) and three links, all mined in **block 966,988**, the block after they were broadcast. Every one of them relayed normally. The heaviest asks a node for about 0.58× of what the pairing spend above asked, and that spend travelled without trouble. Part II has the construction and what it costs; the short version is that nothing here needed a pool's goodwill the second time.

The proof it verifies was generated by **snarkjs**, an independent proving stack with its own trusted setup, for the statement:

> *"The holder was at least 21 years old as of 2026."*

The birth year never reaches the chain or the proof. The coin moves for a valid proof. It doesn't move for a proof generated from someone underage; the prover will happily produce something proof-shaped, and Bitcoin is what rejects it. It also doesn't move for a *valid* proof of a *different* statement, like "at least 30", because the statement is compiled into the coin.

```text
huge computation
      ↓
succinct proof
      ↓
pairing equation
      ↓
Bitcoin Script
      ↓
TRUE / FALSE
```

### A point can be on the curve and still be the wrong point

The first version of this piece listed a gap: the verifier checked that the proof's points were on their curves, but not that they were in the right *subgroup*. A BLS12-381 curve contains more points than the group the pairing is defined on, and on the extra ones the pairing stops behaving the way the proof system's security argument assumes. A production verifier has to reject them.

It does now, and for less than I'd estimated. Each curve has a symmetry that acts on the proper subgroup as multiplication by a small number, so instead of a full 255-bit scalar multiplication you can compare two cheap things:

- for A and C, two short ladders (136 point operations with inverses supplied by the spender) against a one-multiplication symmetry;
- for B, almost nothing. A Miller loop over B *already computes* [|x|]B by the time it finishes. The check is a comparison against a value the verifier already has.

Together they add **17,790 bytes, 1.4%** of the verifier. I didn't take the underlying number theory on trust: a script in the repository computes every fact the checks depend on, and cross-checks the verdicts against an independent implementation's own test.

I also wanted proof that the new checks are what does the rejecting. The whole verifier would reject a bad point anyway, because the pairing equation fails too. But the first stage of the three-way split checks no equation at all. Built without the subgroup checks, that stage happily accepts a point from the wrong subgroup. Built with them, it refuses.

### And a bug in my own tests

While adding those cases I found something less flattering. My test kit had been counting a "should be refused" case as refused whenever it *couldn't even build the spend*. Every refusal case on the whole Groth16 verifier was built that way. So "the coin doesn't move for someone underage" had been reported as passing without the interpreter ever running it.

It's fixed. The kit fills in the missing witnesses and runs the script, and a case it can't build is now a failure. Every one of those cases has since been run for real, and every one still refuses. But a test that can't fail isn't a test, and I'd rather say so than let the green checkmarks speak for themselves.

## What we have, and what we don't

| Result | Size | Where it ran |
| --- | ---: | --- |
| Miller loop, 63 rounds | 333,676 bytes | **Mainnet** ✓ |
| Final exponentiation | 474,207 bytes | **Mainnet** ✓ |
| Complete pairing, two inputs of one transaction | 343,799 + 475,017 bytes | **Mainnet** ✓ |
| Complete pairing, one script | 817,031 bytes | Interpreter only; over policy |
| Groth16 verifier with subgroup checks, three inputs of one transaction | 1,291,329-byte transaction | **Mainnet** ✓ (by direct submission) |
| The same verifier, three chained transactions | 429 + 389 + 491 KB | **Mainnet** ✓ (relayed normally) |

The limits, stated plainly:

- **No single-script pairing.** Getting there needs another 317,031 bytes cut, about 39%. Measuring where the bytes go says that will be hard from this direction: a pairing is 82% stack traffic and 17% arithmetic, and the stack opcodes themselves — not their operands — are most of it.
- **The Groth16 verifier checks a fixed statement.** Public inputs are compiled into the locking script. Accepting them at spend time needs on-chain scalar multiplication, which I've priced (about 40 KB per input) but haven't built.
- **Groth16's own soundness and trusted setup are out of scope.** A verifier checks the equation; it can't know whether anyone kept the setup's trapdoor.
- **500 KB is policy, not consensus.**
- **I haven't done a proper literature search**, so I'm not claiming this is a first.

## The interesting part is becoming the compiler

The Miller loop on chain is 215,308 opcodes. Nobody should write that by hand, and nobody should have to.

Here's what I think the real direction is:

```text
mathematical predicate
        ↓
typed IR
        ↓
witness planning
        ↓
lowerings, checked for agreement
        ↓
cost-model selection
        ↓
stack scheduling
        ↓
Bitcoin Script
```

Part of this already exists. Each module carries a specification written separately from the script it emits, plus requirements and guarantees that pass from module to module. When a range check is already proven upstream, it isn't emitted again. When it can be neither proven nor emitted, the build fails.

There's also a small selection pass. Give it two implementations of the same function, say general squaring and cyclotomic squaring, and it first **proves they agree on the domain in question**, then picks one by measured cost. Nobody told it the compressed ladder wins. It measured that.

The agreement step matters more than the ranking. A selector that picks the cheaper of two programs without checking that they compute the same thing is just a benchmark attached to a bug.

What's missing is the front end: something that takes a formula and produces the lowerings itself, and a scheduler that allocates the stack instead of following the order a human wrote. That's the actual project.

> Developers shouldn't have to write thousands of `OP_PICK`, `OP_ROLL`, `OP_MUL` and `OP_MOD` instructions.
>
> They should write the mathematical statement they want Bitcoin to enforce, and let the compiler work out how to prove it.

## The point

Bitcoin Script's simplicity isn't mathematical simplicity.

Primitive operations compose. Expensive computation can move into witnesses. Bitcoin can check the relationships between those witnesses, and a transaction can connect checks that don't fit in one script.

A missing opcode doesn't mean the computation is impossible. It's a cost, and costs can be measured.

---

*The code, test vectors, deployed scripts and a one-command reproduction path are in the repository, along with the technical paper covering the field arithmetic, soundness arguments and measurements. Every number in this article comes from measuring the code.*

| | deploy | spend |
| --- | --- | --- |
| Miller loop | [`10c52d6d…4d20`](https://whatsonchain.com/tx/10c52d6dfb2831ecff79fe40e827695187d1e8453af845e5ab31f17a84684d20) | [`f90cc1e3…0d40`](https://whatsonchain.com/tx/f90cc1e3d60eecfb4f1a849dc4798db601b3085ca07a4155c4ae2d0890170d40) |
| Final exponentiation | [`038dbe94…b5f4`](https://whatsonchain.com/tx/038dbe94167beee28ad273f3e2d66dcda6098a5cbe0c1613109621352088b5f4) | [`1b1d0f04…3c90`](https://whatsonchain.com/tx/1b1d0f042b863cdc9ce33cdac0893db77da9c05a3eac91bb462364073fae3c90) |
| Groth16 proof of age, three inputs | [`025f20f1…c5f0`](https://whatsonchain.com/tx/025f20f1d4156aa354afef37b1ec67e5c461f11375bc739902845a3b985dc5f0) | [`cad6d2cc…4bb6`](https://whatsonchain.com/tx/cad6d2cca44fffb2f445009f392b668382d79d120b1c14db0fd4a8d192204bb6) |
| Complete pairing | [`92bb3f0e…667c`](https://whatsonchain.com/tx/92bb3f0e790ace19f1afec51141f87a3d6a911f10e82e765dba5368a6765667c) | [`fd0f553e…b9e2`](https://whatsonchain.com/tx/fd0f553ee9a96b2cb48a4a9712824580910cd6056fc42f93f49eae83da2fb9e2) |
| Groth16 proof of age, three chained transactions | [`1c0b9af1…c9ea`](https://whatsonchain.com/tx/1c0b9af1f1b39d40c3d296060a86e8847303cd5709dbd78f917ab65a2f35c9ea) | [`3b68669c…9ee7`](https://whatsonchain.com/tx/3b68669ce3bdf2e1a7dd4a12e449c0b51a4d8a7f137b5eca9c3b64726c859ee7) |

**Part II:** a coin that only moves for someone over 21 — a zero-knowledge proof of age verified on mainnet, and the limit that almost kept it off the chain.

**Part III:** Bitcoin Script verifies a post-quantum signature — SLH-DSA, the NIST standard, with no elliptic-curve key needed to spend.
