# What a pairing costs

For a long time this repository could say what everything cost except the one
thing people mean when they ask whether Bitcoin Script can do cryptography. A
Groth16 verifier reduces to field arithmetic — everybody says so, it is true,
and it is not a number.

This is the number.

**One BLS12-381 pairing is 817,031 bytes of Script — about 82,000 satoshis at
100 sat/KB. A Groth16 verifier, with its proof points checked into their
subgroups, is 1,246,986 bytes.**

Neither is an estimate.

| | what it does | bytes | run it |
| --- | --- | ---: | --- |
| `pairing.e` | e(P, Q) | 817,031 | `npm run pairing:prove` |
| `groth16.verify` | e(A,B)·e(−L,γ)·e(−C,δ) = e(α,β), A, C ∈ G1, B ∈ G2 | 1,246,986 | `npm run groth16` |
| `pairing.miller(63)` | the Miller loop alone | 333,676 | **on mainnet** |
| `fp12.powX` | f ↦ f^\|x\|, one of the exponentiation's five ladders | 99,631 | **on mainnet** |

Each of those emits a locking script, hands it to `bsv.Script.Interpreter`
under relay policy flags, and checks the result against a reference that matches
`@noble/curves` byte for byte. The pairing runs in about thirty seconds and is
part of `npm test`; the Groth16 equation takes about a minute and is on demand.

`npm run groth16:external` runs the verifier against a proof **snarkjs** made
over BLS12-381 — its own setup, its own prover, its own arithmetic — for the
circuit c = a·b with c public. It is accepted. A displaced proof is refused. And
the same valid proof is refused by a verifier built for a different public
input, which is the case worth having: L is a compile-time constant, so a
different statement is a different locking script, and the statement is bound
into the coin rather than supplied beside the proof.

Checking it required two agreements neither of which was guaranteed: that
snarkjs's G2 coordinates are in the same Fp2 basis (tested by putting the
swapped reading on the twist, where it does not lie), and that its verification
equation is this one rearranged.

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
| 1 | 817,031 | 817,031 | — |
| 2 | 1,024,268 | 1,634,062 | 609,794 |
| 3 | 1,227,915 | 2,451,093 | 1,223,178 |

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
| final exponentiation | the easy part, then 15 terms over 6 shared ladders | 473,466 |
| **e(P, Q)** | | **817,031** |

The final exponentiation is two thirds of it, which is why three of the four
optimisations below live there.

### The model, checked against the thing itself

Before either half was emitted, the pricing model said 314,005 for the loop and
648,653 for the exponentiation. Emitted, they were 332,977 and 592,008. (Those
are the figures at the time of the comparison; compressed squaring has since
taken the exponentiation to 473,466. The comparison is kept as it stood, because
the point of it is what the model got wrong, not what the code costs now.)

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

## Is each proof point in the right group?

`npm run audit` is this repository trying to break its own soundness
assumptions. It first found that A, B and C were never checked to be **on the
curve** — bounded into [0, p), which makes each coordinate one field element
rather than a congruence class, and does not make a pair of them a point.

Its longest-standing finding went one step further: **subgroup membership**.
E(Fp) has order h₁·r and the twist h₂·r, so a point can satisfy its curve
equation and lie outside the order-r subgroup, where the pairing is not the
bilinear map Groth16's security argument is about. A standard verifier checks
it. This one does now.

| point | check | how |
| --- | --- | --- |
| A, C ∈ G1 | φ(P) = [−x²]P, φ(x, y) = (βx, y) | `g1.inSubgroup`: two 63-bit witnessed ladders and a comparison |
| B ∈ G2 | ψ(Q) = [x]Q, ψ = untwist ∘ Frobenius ∘ twist | `g2.inSubgroup`: a comparison against the loop's own T |

**Why a comparison decides membership.** On G1, φ³ = 1 and φ ≠ 1, so
φ² + φ + 1 = 0; if φ(P) = [−x²]P then O = [x⁴ − x² + 1]P = [r]P. On G2, ψ
satisfies Frobenius's characteristic polynomial ψ² − tψ + p = 0 with t = x + 1;
if ψ(Q) = [x]Q then O = [p − x]Q = [h₁·r]Q, and since Q also has [h₂·r]Q = O and
gcd(h₁, h₂) = 1, [r]Q = O. Every one of those facts — and which cube root β is,
and ψ's two coefficients, and the twist order h₂·r, chosen from the six
candidate orders a sextic twist can have — is computed by `npm run subgroup`
rather than recalled, and checked there against **@noble/curves**' own torsion
test on points inside and outside both subgroups.

**The G2 check costs a comparison, not a ladder.** A Miller loop over Q starts
T at Q and runs the bits of |x| through it, so when the loop ends T *is* [|x|]Q,
computed by the same witnessed steps a standalone check would have emitted.
Checking B is then four congruences against a value the verifier already had.
The same holds for any spender-supplied G2 point that enters a pairing — σ in a
BLS signature is one.

**The curve check is part of the G1 check, not a neighbour of it.** Doubling
and addition on y² = x³ + b never read b. Coordinates off the curve still run the
ladder — on whichever y² = x³ + b′ they lie — and the argument above holds on
that curve too, so without the curve equation `g1.inSubgroup` would certify
order r on some curve nobody asked about.

| | bytes |
| --- | ---: |
| `g1.inSubgroup`, standalone | 8,517 |
| `g2.inSubgroup`, standalone | 389 |
| the verifier without subgroup checks | 1,229,196 |
| the verifier with them | 1,246,986 |
| **what they cost** | **17,790 — 1.4%** |

The earlier estimate was 5–10%, priced as ladders. The G2 half turned out to be
nearly free, and the G1 half cheaper than a ladder by the scalar: two ladders by
|x|, whose six set bits make 136 point operations where one ladder by x² would
make about 190 and [r]P about 380.

**Which check refuses is tested, not inferred.** The whole verifier refuses a
proof whose A is outside G1 for two reasons at once — the subgroup check, and an
equation that no longer holds — so it cannot say which did the work. A split
stage can: stage 1 checks no equation, it computes rounds 1–31 and publishes.
`npm run groth16:split` builds each of stages 1 and 2 twice, with and without the
checks, and gives them A + (0, 2) — on the curve, of order 3r — and B plus a
point of the twist's cofactor group. Without the checks both stages accept; with
them both refuse.

The verifying key is checked too, once, when the coin is built: a key with α, β,
γ, δ or any ICᵢ outside its subgroup does not compile.

The audit carries a list of accepted findings with the reason each is tolerable,
and fails on anything not on it. Closing this one meant deleting a line.

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

And a **piece of the final exponentiation** is there. `fp12.powX` is the ladder
it runs five times — f ↦ f^|x|, 63 cyclotomic squarings and 5 Fp12
multiplications on a genuine element of the subgroup — in a 99,631-byte locking
script:

```
deploy  1caac568ad58e9049ce4760d2998c31cef57045f84cb03c170a3243fdb936958
spend   0025ca4c616f9ea2bd5ccbc7a03e12ed3cf434003bc4b490609cae995c8d2cfb
```

### Exactly how much of a pairing has run on the network

This document said "both halves" for one commit, and that was wrong. f^|x| is
**one of five** ladders inside the final exponentiation, not the exponentiation.
The precise position:

| | bytes | share of a pairing | where |
| --- | ---: | ---: | --- |
| Miller loop, complete | 332,977 | 40.8% | **mainnet** |
| final exponentiation, complete | 473,466 | 57.9% | **mainnet** |
| e(P, Q) in one script | 817,031 | 100% | interpreter |
| `fp12.powX`, superseded | 98,902 | — | mainnet |

**A complete BLS12-381 pairing has been evaluated by the Bitcoin network** — see
"Not one script — one transaction" below. Its two stages were also deployed and
spent individually:

```
Miller loop           deploy 10c52d6dfb2831ecff79fe40e827695187d1e8453af845e5ab31f17a84684d20
                      spend  f90cc1e3d60eecfb4f1a849dc4798db601b3085ca07a4155c4ae2d0890170d40
final exponentiation  deploy 038dbe94167beee28ad273f3e2d66dcda6098a5cbe0c1613109621352088b5f4
                      spend  1b1d0f042b863cdc9ce33cdac0893db77da9c05a3eac91bb462364073fae3c90
```

What has **not** run on chain is the chaining. A single script that runs the
loop and feeds its twelve outputs to the exponentiation is 817,031 bytes, past
the policy, and the **10,588 bytes** by which the whole exceeds its two stages
are exactly that plumbing. "Both stages have executed on mainnet" is the claim.
"A pairing has executed on mainnet" is not.

## Not one script — one transaction

No amount of shaving gets 817 KB under 500 KB. So the composition moves out of
the script and into the **transaction**:

```
input 0   the Miller loop            publishes f as an OP_RETURN output
input 1   the final exponentiation   consumes that same output
```

Both inputs of a spend see the same `hashOutputs`. Each requires that commitment
to be the data output *it* constructs, so they must have constructed the same
bytes — input 1's f is input 0's f, enforced by the transaction rather than by
trust. Neither script contains the other's code, which is the whole point: a
covenant can only commit to a successor whose bytes it can build, and a 344 KB
script cannot carry a 475 KB one.

**This is on mainnet.**

```
funding  92bb3f0e790ace19f1afec51141f87a3d6a911f10e82e765dba5368a6765667c
spend    fd0f553ee9a96b2cb48a4a9712824580910cd6056fc42f93f49eae83da2fb9e2
```

164,997 satoshis: 81,904 to fund the two coins in one transaction, 83,093 for
the spend that consumes them together. The spend carries no change — the
covenant requires the output set to be exactly the data output — so every
satoshi the coins hold becomes its fee, and the funding sizes them for it in
advance. `npm run verify:chain` checks that output 0 is `pairing.publish`, that
output 1 is `pairing.consume`, that one transaction consumes both, and that it
publishes the value they agree on.

`npm run pairing:split` builds the same thing offline and hands both inputs to
the interpreter:

```
input 0   pairing.publish     343,799 bytes of lock, 350,922 of unlock   ACCEPTED
input 1   pairing.consume     475,017 bytes of lock, 479,302 of unlock   ACCEPTED
output    OP_RETURN               588 bytes — twelve Fp12 coefficients
```

What the network verifies, in one transaction: that the Miller loop ran
correctly on P and Q, that its twelve outputs were published, that the same
twelve were consumed, and that their final exponentiation is e(P, Q). That is a
complete pairing.

### Joint grinding

OP_PUSH_TX needs each preimage to satisfy a canonical low-S condition, and
`grind` finds one by moving that input's `nSequence`. But `hashSequence` covers
**every** input's sequence, so moving input 0's changes input 1's preimage and
vice versa. Two independent grinds invalidate each other; the search has to be
over the pair. About one preimage in fifty passes, so a pair lands in a couple
of thousand tries — 733, here.

Rebuilding a preimage that carries a 344 KB scriptCode two thousand times is the
slow way to find that out. Only 36 bytes of it change, so each preimage is built
once and `hashSequence` and `nSequence` are patched in place, then checked
against the ones the library builds. 0.9 seconds instead of minutes.

### The constraint this surfaced

OP_PUSH_TX's preimage **contains the script it unlocks**, so a covenant's
unlocking script is as large as its locking script. `pairing.consume` locks in
475,017 bytes and unlocks in **479,302** — under the 500,000-byte policy by
20,698. The binding constraint on this construction is the *unlocking* script,
not the locking one, and the final exponentiation has less headroom than its own
size suggests.

It cost 164,997 satoshis.

### What the shared commitment does not establish

`hashOutputs` binds the **bytes** two inputs agree on. It says nothing about
**which inputs are present**, and that gap is not academic here.

Spend `pairing.consume` alone, in a transaction whose one data output carries an
f of your choosing. The covenant is satisfied — the data *is* what the
transaction publishes. All that remains is finding an f with F(f) = e(P, Q)
without running a Miller loop, and that is cheap: F is exponentiation by
d = 3(p¹²−1)/r, the target has order r, and gcd(d, r) = 1, so

```
f = e(P,Q)^(d⁻¹ mod r)      two modexps, no pairing
```

satisfies it. `npm run attack:siblings` does exactly this against the
interpreter, and the coin is accepted. Nothing is stolen — the covenant forbids
change, so the satoshis go to fees — but the claim the construction makes is
that the *transaction* establishes the computation, and a reader who checks one
input is deceived. It is also a live griefing attack on a deployment:
front-run the honest spend, consume its final-exponentiation coin with a forged
f, and the honest spend can never be published, because its input is gone.

**The fix is `hashPrevouts`**, the field this repository never read. It is the
double-SHA of every spent outpoint in order — 32-byte txid, then 4-byte
little-endian index. The stages of one computation are outputs of a single
funding transaction, so the whole list is determined by that one txid: rebuild
it in script from a witnessed 32 bytes, require the hash to match, and then
require this input's own outpoint — at offset 68 of the preimage — to be the
slot the script claims.

```
commitData(width, { siblings: { count, index } })    47 bytes at two, 56 at three
```

That pins the spend to exactly `count` inputs, all outputs of one transaction at
indices 0..count-1, with this script at `index`. What it cannot pin is which
*scripts* those outputs carry — an outpoint does not name a script. That last
step stays outside, and it is one check on one funding transaction rather than a
judgement about the spend; `npm run verify:chain` is where it lives.

All three stages of the Groth16 split bind their siblings. The two-way pairing
split does **not**, because it is already on chain and its bytes are the record;
`tools/pairing-split.js` reproduces it as deployed, and the audit carries the
finding rather than quietly closing it.

The last row carries its own caveat. `fp12.powX` — one uncompressed f^|x| ladder
— was deployed and spent and is correct, and it is no longer what the
implementation does: `fp12.powXc` replaced it at 73,582 bytes. Counting its
bytes toward "a pairing on chain" would be counting a version that no longer
exists, so the figure above does not.

The stages do not sum to the whole either: chaining them costs bytes neither
separate measurement contains, and the shares are taken against the emitted
pairing rather than against the sum of its parts, which is smaller and would
have flattered them. Every figure here is generated into `results.json` by
`npm run results`, and `npm test` checks it.

Compressed squaring is what put the second one there: the final exponentiation
was 592,008 bytes before it and 473,466 after, which is the difference between
over the 500,000-byte policy boundary and under it.

The Miller-loop stage is complete and that is the substantive claim. The final
exponentiation additionally needs four more of those ladders, an easy part —
f ↦ conj(f)·f⁻¹ then φ²(·)·(·), with the pairing's single witnessed Fp12
inversion in it — and 15 term combinations over 19 Frobenius applications. At
473,466 bytes it is under the 500 KB script policy, and it has been deployed and
spent.

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

Both are inside the default 500 KB script policy. A whole pairing, at 817,031
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

## Three ways: a whole Groth16 verifier across one transaction

Cutting a pairing in two worked because a pairing already comes in two pieces. A
Groth16 verifier does not. It is 1,246,986 bytes, and its Miller loop — three
pairings sharing one accumulator — is **705,838 on its own**, which is 205,838
over the policy before the final exponentiation is even considered. There is no
two-way cut. The loop has to be cut.

It is cut at round 31 of 63. Round 31 is not a seam in the mathematics; it is
simply where the halves are each small enough. What makes an arbitrary cut
legal is that the state there is small — the accumulator f, twelve Fp
coefficients, plus each pairing's running point T, four apiece. Twenty-four
values.

```
input 0   rounds 1–31 of three loops, publishes S₁
input 1   rounds 32–63, resuming from S₁, publishes S₂
input 2   the final exponentiation of S₂, against e(α, β)
```

`npm run groth16:split` proves all three stages against the interpreter — with
forged witnesses substituted and refused — then isolates the subgroup checks,
and then builds the transaction:

```
input 0   A, C ∈ G1; rounds 1–31, publishes S₁   399,402 lock   424,186 unlock   ACCEPTED
input 1   rounds 32–63; B ∈ G2, publishes S₂     371,834 lock   383,299 unlock   ACCEPTED
input 2   final exponentiation vs e(α,β)         475,647 lock   481,527 unlock   ACCEPTED
output    the blob all three commit to             2,156 bytes — 44 field elements
```

A and C are checked into G1 in stage 1, at 16,849 bytes for the two ladders. B is
checked into G2 in stage 2, at 957 bytes, because its check needs [|x|]B and at
round 31 the running point is only [|x| ≫ 32]B. The point stage 2 resumes from is
a witness, but the blob pins it to the one stage 1 computed, so the point it
finishes with is [|x|]B and not a number the spender chose.

The isolation is the part that shows the checks matter. The whole verifier would
refuse a proof whose A is outside G1 anyway, because the equation fails for it
too — so the whole verifier cannot say which check did the work. Stage 1 checks
no equation. Built without the subgroup checks, stage 1 accepts A + (0, 2) and
stage 2 accepts B plus a cofactor point; built with them, both refuse.

Each stage bounds only the blob's values at its door — the proof and the cut
states, which are serialised and compared as bytes. Every inverse is bounded by
the module that reads it, and `npm run audit` checks by provenance that every
numeric witness of every stage is bounded somewhere.

The proof being verified is a real one: snarkjs generated it from a circuit
asserting *"the holder was at least 21 years old as of 2026"*, and nothing in
this repository produced it. The transaction is 1,291,329 bytes.

**This is on mainnet.** Every locking script here is under the 500 KB limit and so
is every unlocking script. `node bin/deploy-groth16.js` built the funding
transaction and the spend with the same code the tool uses, verified all three
inputs against the real funding txid, and broadcast them — 253,934 satoshis of
fees for the pair:

```
funding  025f20f1d4156aa354afef37b1ec67e5c461f11375bc739902845a3b985dc5f0   mined, block 966,795
spend    cad6d2cca44fffb2f445009f392b668382d79d120b1c14db0fd4a8d192204bb6   mined, block 966,923
```

The spend took 128 blocks to get there, and the reason is worth more than the
result. It reached WhatsOnChain's node and no miner; submitted to GorillaPool's
ARC it came back `REJECTED: too-long-validation-time`. A node gives a
peer-relayed transaction about a second to validate — `maxnonstdtxvalidationduration`,
1000 ms by default — and this one's three inputs take 3.9 seconds in the
JavaScript interpreter against 2.8 for the two-way pairing spend that relayed
normally. The pool then submitted it to their own node directly and mined it.

So validation time bounds the *transaction*, which is exactly the unit this
construction packed three stages into — and unlike the script-size policy it
bounds RELAY rather than validity. The spend is valid and its block is valid; it
simply could not travel. A version that does not depend on an operator's goodwill
has to put the stages in separate transactions.

### Why every stage carries the whole blob

Each stage computes its own transition and **witnesses** everything else. A
witness may be anything the spender likes; what removes the freedom is that all
three inputs see the same `hashOutputs`, and each requires it to be the data
output *it* builds. So all three built the same bytes, and stage i's witnessed
input is stage i−1's computed output. Written out for N stages, with s_i the
state after stage i and B the single output carrying all of them:

```
P_i(s_{i-1}, s_i) = [ s_i = F_i(s_{i-1}) ] ∧ C(B)
```

C is a function of the transaction alone, so it holds identically at every
input, and B determines every s_i. Chaining gives s_N = f(s_0). The blob must
therefore carry the whole state, not just one stage's endpoints — which is why
it is kept to 2,156 bytes for a computation of 1,246,986, and why the cut point
is chosen by the size of the state it exposes rather than by the sizes of the
pieces.

### Grinding three preimages, and picking the right field

One preimage in fifty is canonical (measured: 2.01%). A pair lands in about
2,500 tries; a **triple in about 123,000**. The two-way split ground
`nSequence`, and at three inputs that stops working — for a reason that is
entirely about BIP-143's byte layout.

`nSequence` appears **twice** in a preimage: as its own field near the end, and
inside `hashSequence` at offset 36. Move it and every SHA-256 block from byte 36
onward changes, so each attempt rehashes a ~400 KB preimage. A hundred thousand
attempts across three inputs is not a search, it is an afternoon.

`nLockTime` appears **once**, eight bytes from the end. Grind that instead and
every block but the last is untouched, so each input's SHA-256 midstate is
computed once and copied per attempt. The cost per try drops from hashing 400 KB
to hashing 64 bytes:

```
168,127 nLockTimes, 3,451 cleared input 0, 62 cleared inputs 0 and 1 — 2.5 seconds
```

Small nLockTime values are block heights already in the past, so the transaction
stays final — `src/groth16spend.js` stops the search well short of the chain
height, and the deployment refuses a result that is not below it. The fast filter
is checked against the library's own canonicalisation before it is trusted, not
after.

The general lesson is not about pairings. "Which field should carry the nonce?"
has no cryptographic answer at all — it is decided by where the field sits
relative to a hash function's block boundaries.

### Headroom

Stage 3 unlocks in 481,527 bytes, 18,473 under the policy — the binding
constraint is again the *unlocking* script. A four-way split would relieve it,
and nothing in the construction would have to change.

## The honest caveat

At 817 KB a pairing is past the default 500 KB script policy, and so is a
Groth16 verifier at 1.24 MB. Neither is ever emitted as a single locking script
on chain; both are, in pieces, across the inputs of one transaction. The Miller
loop at 333 KB is under the policy, and is on chain; the final exponentiation at
473 KB is too, and is also on chain. Neither is standard relay today. That is a policy
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
npm run groth16:split   # the whole verifier across three inputs of one tx
npm run attack:siblings # spend a stage without its siblings; then stop it
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
