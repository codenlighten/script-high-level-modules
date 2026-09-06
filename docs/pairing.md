# What a pairing costs

For a long time this repository could say what everything cost except the one
thing people mean when they ask whether Bitcoin Script can do cryptography. A
Groth16 verifier reduces to field arithmetic — everybody says so, it is true,
and it is not a number.

This is the number.

**One BLS12-381 pairing is 935,334 bytes of Script — 935 KB, about 93,500
satoshis at 100 sat/KB. The Groth16 verification equation is 1,346,218 bytes.**

Neither is an estimate.

| | what it does | bytes | run it |
| --- | --- | ---: | --- |
| `pairing.e` | e(P, Q) | 935,334 | `npm run pairing:prove` |
| `groth16.verify` | e(A,B)·e(−L,γ)·e(−C,δ) = e(α,β) | 1,350,790 | `npm run groth16` |
| `pairing.miller(63)` | the Miller loop alone | 333,676 | **on mainnet** |

Each of those emits a locking script, hands it to `bsv.Script.Interpreter`
under relay policy flags, and checks the result against a reference that matches
`@noble/curves` byte for byte. The pairing runs in about thirty seconds and is
part of `npm test`; the Groth16 equation takes about a minute and is on demand.

`npm run groth16` accepts a valid proof and **refuses two invalid ones** — an
A and a C each off by one generator, with every point still on the curve and
every witnessed inverse still correct for the points supplied, so that nothing
fails until the equation itself does. A verifier that accepts a valid proof and
does not notice an invalid one is not a verifier, and forged *witnesses* are a
different question from a forged *proof*.

Bitcoin Script has no pairing opcode. No Fp12, no Fp6, no Fp2, no
extension-field arithmetic of any kind. It has `OP_MUL` and `OP_MOD` at
arbitrary width, and this is what that turns out to be sufficient for.

## How it was arrived at

Two halves, measured separately, multiplied together.

**The operations**, counted by running a real pairing. `src/bls12381.js` is a
complete BLS12-381 — Fp, Fp2, Fp6, Fp12, G1, G2, Miller loop, final
exponentiation — with a counter on every field operation it performs. It is
checked against `@noble/curves` on all twelve Fp12 coefficients for eight
different scalar pairs, not merely on bilinearity: an early version of the line
function here was non-degenerate, produced values of order r, satisfied every
component test, and was wrong. Byte equality with an independent implementation
is the check that caught it.

**The bytes**, measured by emitting the module. `src/modules/fp2.js`, `fp6.js`
and `fp12.js` implement the tower as real modules, proven against
`bsv.Script.Interpreter` at the BLS12-381 prime under relay policy flags, the
same way every other module here is proven.

Multiply and there is nothing left to assume.

## Why the tower is built three layers deep

Costing a pairing by adding up Fp2 module bodies would price the arithmetic and
price the stack at zero, and the stack is not free. An Fp12 product has to bring
twenty-four values to the top before it can read them.

So `fp6.mul` is built by *calling* the Fp2 modules through the same `apply()`
every other composition here uses, and measured whole:

| | bytes |
| --- | ---: |
| `fp6.mul` as the sum of its Fp2 parts | 489 |
| `fp6.mul` measured | 721 |
| the difference — `OP_PICK` and `OP_ROLL` | **×1.47** |

Composition costs about half again as much as the arithmetic it composes. That
factor is measured, not guessed, and the four modules that carry the pairing —
`fp12.mul`, `fp12.sqr`, `fp12.cycSqr`, `fp12.mulLine` — are measured whole so
they do not need it applied. Only the leftovers are priced at the Fp2 floor.

The decomposition is checked rather than asserted: the Fp2 operations a pairing
performs, minus the ones the four Fp12 modules account for, must come out
non-negative in every component. `tools/pairing-cost.js` throws if it does not.

## Products of pairings, which is what protocols actually check

Nobody computes two pairings and compares them. Every pairing-based protocol
checks a *product* — and a product shares the Miller accumulator, so k pairings
pay for 63 squarings **between them** and **one** final exponentiation, not k of
each.

| pairs | emitted | as separate pairings | saved |
| ---: | ---: | ---: | ---: |
| 1 | 935,334 | 935,334 | — |
| 2 | 1,142,571 | 1,870,668 | 728,097 |
| 3 | 1,346,218 | 2,806,002 | 1,459,784 |

Each pair after the first costs about 204 KB rather than 935 KB. What goes is
the 63 squarings it would have duplicated and the 592 KB final exponentiation it
would have repeated.

That is `pairing.product(k)`, and `pairing.verify(k, expected)` wraps it as a
**predicate** — it asserts and returns nothing, so `all()` composes it and
`predicate()` turns it into a coin, like anything else here.

The protocols land on it directly:

| | as a product |
| --- | --- |
| BLS signature | e(H(m), pk) · e(−σ, G₂) = 1 |
| Groth16 | e(A,B) · e(−L,γ) · e(−C,δ) = e(α,β) |

Groth16's right-hand side is fixed by the verifying key, so it is a compile-time
constant in the locking script — 576 bytes of Fp12. Comparing against it rather
than folding e(α,β) in as a fourth pair is 68 fewer lines and about 204 KB
cheaper. That is why `verify` takes an expected value instead of testing for one.

## Where the cost is

| stage | what it does | bytes, emitted |
| --- | --- | ---: |
| Miller loop | 63 tangents, 5 chords, 68 line products, 63 squarings | 332,977 |
| final exponentiation | the easy part, then 15 terms over 6 shared ladders | 592,008 |
| **e(P, Q)** | | **935,334** |

The final exponentiation is two thirds of it, which is why three of the four
optimisations below live there.

### The model, checked against the thing itself

Before either half was emitted, the pricing model said 314,005 for the loop and
648,653 for the exponentiation. Emitted, they are 332,977 and 592,008.

| | model | emitted | |
| --- | ---: | ---: | --- |
| Miller loop | 314,005 | 332,977 | model **low by 6.0%** |
| final exponentiation | 648,653 | 592,008 | model **high by 8.7%** |

Both errors have causes, and they are different causes. The loop is *more* than
the model because the model prices the stack at zero and a real emitter pays for
`OP_PICK` and `OP_ROLL`. The exponentiation is *less* because the emitted ladder
is better than the reference it was counted from: unrolled and MSB-first, it
costs 63 squarings and 5 multiplications for each exponentiation by the curve
parameter, where the JavaScript runs LSB-first from an accumulator of one and
pays 64 and 6 — the extra multiply being by one, which is free to compute and is
not free to emit.

A model that was wrong in only one direction would be suspicious. `npm run
pairing` prints both comparisons every time it runs, so neither can quietly stop
being true.

## The four things that made it this small

Each was checked against the general routine it replaces. Two of them are places
where an earlier version of this file was wrong in a way bilinearity did not
catch, which is the reason they are checked and not trusted.

**The hard part as an addition chain.** λ = 3(p⁴ − p² + 1)/r is 1,270 bits, and
raising to it directly is 1,270 squarings. Written in balanced base p its four
digits are applied by Frobenius maps rather than exponentiations, and each of
*those* digits is a small polynomial in the 63-bit curve parameter — so what is
left is five exponentiations by a 63-bit number, shared across all four digits,
and a handful of multiplications by coefficients no larger than 3. **315
squarings, not 1,270.** The digits are derived at load time rather than
transcribed, so a wrong constant is not a thing that can happen.

**Granger–Scott cyclotomic squaring.** After the easy part the value lies in
G_Φ6(Fp2), where a square is half the price. Two earlier attempts at this
formula disagreed with general squaring and were thrown away. What makes the
third work is presenting the tower *flat*: Fp12 = Fp6[w]/(w² − v) over
Fp2[v]/(v³ − ξ) means w⁶ = ξ, so it is equally Fp2[w]/(w⁶ − ξ) with basis
1, w, …, w⁵ — and since (w³)² = ξ, the element is three Fp4 coefficients
**(g0,g3), (g1,g4), (g2,g5)**. Those pairs are what the nested indexing hides,
and having them wrong is what sank both earlier attempts. **1,292 bytes against
2,301.**

**Sparse line multiplication.** Nine of a line's twelve Fp2 coefficients are
zero, and multiplying by zero is still an `OP_MUL`. Skipping them takes the
product from eighteen Fp2 multiplications to fourteen. **2,018 bytes against
3,110.**

**Witnessed inversion — and this one inverts the usual engineering.** Every fast
pairing implementation uses projective coordinates specifically to *avoid*
inverting, paying several extra multiplications at every step, because on a CPU
an inversion is hundreds of multiplications. In Script it is four: the spender
supplies a⁻¹ off-chain and the script checks a·a⁻¹ = 1, which is one Fp2
multiplication written out. So the trade reverses, and **affine arithmetic is
the cheap choice here** — the formulas everyone reaches for would make this
bigger, not smaller.

`fp2.inv` bounds both coefficients into [0, p) before checking. Without that a
spender has infinitely many encodings of the same inverse: r and r + p verify
the identical multiplication, and a downstream module comparing results would be
comparing numbers that are congruent rather than equal.

Together the four take one pairing from roughly 4 MB to under 1 MB.

## The Groth16 verifier, and where its soundness lives

The equation is arithmetic. The *verifier* is a question about who chooses what.

```
e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)
```

**Only A, B and C come from the unlocking script.** γ, δ and L are pushed as
constants by the locking script, and e(α,β) is the constant they are compared
against. A spender who could choose γ could choose a γ that makes the equation
hold for a proof of nothing — so `pairing.verify(3, …)`, which takes all three
pairs as inputs, is a check of the *equation* and not a verifier. The two are
one wrapper apart, the wrapper is 490 bytes of pushed constant, and the wrapper
is the entire point.

`npm test` asserts that separation on every run — that `groth16.verify`'s
non-witness inputs are exactly `Ax, Ay, Bx0, Bx1, By0, By1, Cx, Cy`, and that
γ, δ and L appear in the locking script as constants the interpreter would read
as those numbers. It is a two-second check standing in for a fifty-second one,
and it is the property that must never regress.

### Why L is free

L = IC₀ + Σ xᵢ·ICᵢ combines the public inputs into a G1 point, and a general
verifier computes it on chain: one fixed-base scalar multiplication per input at
about 39,910 bytes.

This one does not need to. **The statement is fixed when the coin is locked.** A
covenant that says "pay out to whoever proves *this*" knows its public inputs
when it is written, so L is computed off chain, once, and pushed — 96 bytes, not
40 KB per input. Change a public input and L changes, the locking script
changes, and it is a different coin. That is what fixing the statement means, and
it is the normal shape for a Bitcoin covenant.

A verifier whose public inputs are chosen at *spend* time is a different object
and does need the multiplications. `src/ec.js` now takes curve parameters — it
carries `secp256k1` and `bls12381G1` and the `curve()` factory that makes both —
so the arithmetic exists; wiring the `ec` ladder modules to an arbitrary curve
is the remaining step, and it is ordinary work on ground this repository already
holds.

## What is left on the table

Nothing in the pairing, and nothing in the verifier for a fixed statement: all
of it is emitted and executed. The Fp2 floor still appears in the tables above
because the model is kept alongside the measurement as a cross-check, not
because anything depends on it.

The Fp2 leftovers — G2 point arithmetic, the line coefficients, the Frobenius
maps, the single Fp12 inversion — are priced at the sum of their module bodies
with the stack at zero, so read ×1.47 onto the 47 KB and 11 KB rows. That is
about 27 KB unaccounted, under 3% of the total, and it is an underestimate
rather than an overestimate.

Every inversion the loop needs is a witness — 68 of them, 136 numbers a spender
chooses. Every one is bounded into [0, p) and checked against a·a⁻¹ = 1, and the
test kit forges them: `npm test` refuses 943 forged witnesses across the library,
21 of them against the full loop.

`fp12.cycSqr` is correct **only** on the cyclotomic subgroup. On a general Fp12
element it returns something that is not the square, and no bound the fact
system can express says otherwise — the requirement is membership of a subgroup,
not a range. In a pairing it is discharged structurally: the easy part raises to
(p⁶ − 1)(p² + 1) and everything after it is cyclotomic by construction. The test
vectors are real subgroup elements for the same reason — they are produced by
running an easy part.

## On chain

**The whole Miller loop is deployed and spent on BSV mainnet.** All 63 rounds:
a **333,676-byte locking script** doing 63 tangents, 5 chords, 68 sparse line
products, 63 Fp12 squarings and 68 witnessed Fp2 inversions — 136 numbers the
spender chose, every one bounded into [0, p) and checked.

```
deploy  10c52d6dfb2831ecff79fe40e827695187d1e8453af845e5ab31f17a84684d20
spend   f90cc1e3d60eecfb4f1a849dc4798db601b3085ca07a4155c4ae2d0890170d40
```

A 48-round prefix went out first, when that was what the wallet could pay for,
and is kept:

```
deploy  d5395e02a492a7af05e92bb01ee2b0bcc75ba2fda621420f96236e52e87ccdeb
spend   2b81cc0811029f43c75ed9fcb355e0af4a62fbf47e0f6021ee0288d70af7101f
```

`pairing.miller(n)` takes the round count as a parameter, which is what makes a
truncated loop a real checkable object rather than a demonstration: the script
that went on chain is the script the test suite proves, stopped at a bit.
`npm run verify:chain` rebuilds both byte for byte from the code.

Both are inside the default 500 KB script policy. A whole pairing, at 935,388
bytes, is not — it is proven against the interpreter and cannot be relayed.

### What it took to get 334 KB to relay

The first attempt came back `too-long-mempool-chain`, and the fee was not the
problem. The wallet took outputs in whatever order the indexer returned them,
which meant sweeping up the dust left by earlier deployments — and that dust
sits at the *end* of the unconfirmed chain those deployments built. A single
fresh 50,000-satoshi output funds this transaction on its own; funded by three
satoshis of dust first, it inherited fourteen links of ancestry.

It also stopped funding at `satoshis + 5000`, a fine constant for a 400-byte
covenant and nonsense for a script whose fee alone is 33,389. Both are fixed in
`src/onchain.js`: largest-first within each confirmation status, and the fee
sized from the script that is about to be deployed.

## The honest caveat

At 935 KB a pairing is past the default 500 KB script policy, and so is the
Groth16 equation at 1.35 MB. The Miller loop, at 333 KB, is not — and is on
chain. Neither is standard relay today. That is a policy
number, not a consensus one, and it is the kind of number that moves; the
arithmetic underneath it is what this measures, and the arithmetic does not
change when the policy does.

## What it means

Bitcoin Script has no pairing opcode. It has no Fp12, no Fp6, no Fp2, no
extension-field arithmetic of any kind. It has `OP_MUL` and `OP_MOD` at
arbitrary width, and that turns out to be sufficient.

The absence of an opcode is not the absence of the computation. It is a price,
and now it is one that has been paid and counted rather than argued about.

## Reproducing all of it

```
npm test                # everything, including one whole pairing (~65 s)
npm run pairing         # the cost report: model and measurement side by side
npm run pairing:prove   # emit e(P, Q), run it, check twelve coefficients
npm run groth16         # the Groth16 equation, one valid proof and two forged
npm run verify:chain    # rebuild every deployed script and compare to the chain
```

The order these were built in matters, because each step could have been the one
that failed:

1. a BLS12-381 in BigInt, agreeing with `@noble/curves` on all twelve Fp12
   coefficients — not on bilinearity, which a wrong pairing can also satisfy;
2. `fp2`, `fp6`, `fp12` as modules, each proven against the interpreter at the
   BLS prime, composed through the same `apply()` as everything else here so
   that stack traffic is measured rather than assumed;
3. the operation counts and module sizes multiplied into a model;
4. the Miller loop emitted whole and run — the model was low by 6%;
5. the final exponentiation emitted whole and run — the model was high by 8.7%,
   for a different and identifiable reason;
6. the two chained into one pairing;
7. the loop deployed to mainnet and spent;
8. k pairings folded onto one accumulator, and the Groth16 equation checked.

No step was taken on the strength of the one before it. Every one was verified
against something that did not come from this repository.
