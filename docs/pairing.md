# What a pairing costs

For a long time this repository could say what everything cost except the one
thing people mean when they ask whether Bitcoin Script can do cryptography. A
Groth16 verifier reduces to field arithmetic — everybody says so, it is true,
and it is not a number.

This is the number.

**One BLS12-381 pairing is about 978 KB of Script: roughly 98,000 satoshis at
100 sat/KB. A Groth16 verification with four public inputs is about 1.80 MB and
roughly 180,000 satoshis.**

Run `npm run pairing` to reproduce it.

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

## Where the cost is

| stage | operations | bytes |
| --- | --- | ---: |
| Miller loop | 63 × `fp12.sqr`, 68 × `fp12.mulLine` | 329,406 |
| final exponentiation | 63 × `fp12.mul`, 342 × `fp12.cycSqr` | 648,653 |
| **one pairing** | | **978,059** |

The final exponentiation is two thirds of it, which is why three of the four
optimisations below live there.

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

## What is left on the table

The Fp2 leftovers — G2 point arithmetic, the line coefficients, the Frobenius
maps, the single Fp12 inversion — are priced at the sum of their module bodies
with the stack at zero, so read ×1.47 onto the 47 KB and 11 KB rows. That is
about 27 KB unaccounted, under 3% of the total, and it is an underestimate
rather than an overestimate.

`fp12.cycSqr` is correct **only** on the cyclotomic subgroup. On a general Fp12
element it returns something that is not the square, and no bound the fact
system can express says otherwise — the requirement is membership of a subgroup,
not a range. In a pairing it is discharged structurally: the easy part raises to
(p⁶ − 1)(p² + 1) and everything after it is cyclotomic by construction. The test
vectors are real subgroup elements for the same reason — they are produced by
running an easy part.

## The honest caveat

At 978 KB a pairing is past the default 500 KB script policy, and so is a
Groth16 verifier at 1.80 MB. Neither is standard relay today. That is a policy
number, not a consensus one, and it is the kind of number that moves; the
arithmetic underneath it is what this measures, and the arithmetic does not
change when the policy does.

## What it means

Bitcoin Script has no pairing opcode. It has no Fp12, no Fp6, no Fp2, no
extension-field arithmetic of any kind. It has `OP_MUL` and `OP_MOD` at
arbitrary width, and that turns out to be sufficient.

The absence of an opcode is not the absence of the computation. It is a price,
and now it is one that has been paid and counted rather than argued about.
