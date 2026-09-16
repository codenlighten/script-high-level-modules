# Making it smaller

Fees are bytes. Everything in this document is a measured before-and-after on
the real interpreter, and every one of them left the suite green — the point of
attacking every witnessed input on every run is to be able to restructure code
like this and know immediately whether it still refuses what it used to.

The **before** column is history. The **now** column is measured from the code
every time `npm run cost` runs, because this table once claimed `ec.add` was 139
bytes long after a missing-bound audit had made it 167.

<!-- cost:optimized -->
| | before | now | |
| --- | ---: | ---: | ---: |
| `ec.add` | 191 | 167 | -13% |
| `ec.double` | 191 | 153 | -20% |
| `ec.mul` | 116,127 | 42,112 | -64% |
| `ec.mulG` | 80,216 | 39,833 | -50% |
| `ecdsa.verify` | 196,778 | 59,191 | -70% |
<!-- /cost:optimized -->

The standalone figures for `ec.add` and `ec.double` are mostly the two 33-byte
modulus constants they push for themselves; inside a ladder, where those are
hoisted, each is about 65 bytes. They grew back a little when the audit in
[witnesses.md](witnesses.md) found that the coordinate range they documented was
not enforced — a bound that is emitted costs bytes, and a bound that is only
documented costs correctness.

The pairing tower, built later, is the same techniques at a different scale:

| | |
| --- | ---: |
| one BLS12-381 pairing | 935,334 |
| three pairings, as a product | 1,346,218 |
| the same three, separately | 2,806,002 |

§10 to §16 below are what makes the difference between those last two lines,
§16 is the one worth reading if you read only one, and §17 is what happens when
you stop asserting §16 and let the target work it out.

## 1. Reduce only where it must be canonical

The largest win, and the one that changes how the formulas are written.

The obvious way to write a point addition is one field operation per line:
subtract and reduce, multiply and reduce, subtract and reduce. It reads exactly
like the mathematics, and two thirds of it is reductions nothing needed.

Post-Genesis Script numbers are arbitrary precision. An intermediate does not
have to fit in a field element — it only has to be **congruent** to the right
value. λ is never reduced at all: λ² is a 1024-bit number and `OP_MUL` does not
care. Only x₃ and y₃ come out in [0, p), because those are what leaves the
module and what the next operation's canonicity depends on.

Two rules make that safe rather than merely smaller.

**`OP_MOD` is truncated.** `a mod p` keeps the sign of `a`, so reducing a value
that might be negative does not make it canonical. Where the sign is unknown the
reduction is `((v mod p) + p) mod p`. Where the value is provably non-negative,
one `OP_MOD` is enough — and x₃ is *made* provably non-negative by adding 2p
first, since λ² ≥ 0 and x₁ + x₂ < 2p. That is why the modulus is carried in two
forms.

**A congruence check needs no sign at all.** `dx·inv ≡ 1 (mod p)` is checked as
`(dx·inv − 1) mod p == 0`. Zero is zero under truncation too, so `dx` never needs
reducing before the check — which is what lets `dx` be a bare `OP_SUB` instead of
a five-opcode field subtraction.

The cost is paid in the interpreter's arithmetic — bigger BN operands — and not
in bytes. Fees are bytes.

## 2. Hoist the constants out of the loop

A 256-bit modulus is a 33-byte push. A point operation needs it four times; a
256-step ladder performs 512 point operations. Pushed inside each operation,
that is 34 KB of the same constant.

`int`'s modules and `ec`'s therefore accept the modulus as **either a BigInt or
the name of a value already on the stack**. The ladder pushes p and 2p once and
every operation picks them, at two bytes a reference.

This is the reason the assembler tracks values by name at all. A depth cannot be
hoisted out of a loop; a name can.

## 3. Clear temporaries with the altstack, not with rolls

A point operation creates a dozen temporaries and leaves two results. Rolling
each dead value to the top and dropping it costs three bytes — a depth push,
`OP_ROLL`, `OP_DROP`:

```
13 temporaries, 2 survivors:   39 bytes
```

Park the two survivors on the altstack instead and the rest go with `OP_2DROP`,
which takes two at a time and needs no depth:

```
2×OP_TOALTSTACK + 6×OP_2DROP + 2×OP_FROMALTSTACK:   11 bytes
```

`Asm.dropTo(floor, keep)` does this, and `Asm.mark(n)` gives it the floor — the
boundary between what the module owns and what belongs to the caller. Dropping
past that boundary is a build-time error rather than a corrupted stack.

## 4. One opcode instead of two comparisons

Every witnessed inverse needs `0 ≤ inv < p`. Written as two comparisons and two
`OP_VERIFY`s that is eleven bytes. `OP_WITHIN` does exactly this — `min ≤ x <
max` — in seven. There are 512 of them in a ladder.

## 5. The witness is a tape

A 256-step ladder needs a bit and one or two inverses per step: over seven
hundred values. Pushed individually they cost a push prefix each and fill the
stack; packed into two byte strings the script splits fields off the front of,
they cost nothing extra and occupy three stack slots.

The tape also buys a property that individual pushes do not: the script can
require what remains of it to be **empty** at the end, so no unread bytes ride
along in the unlocking script to change the txid without changing what it does.

This was originally forced by a 1000-element stack cap that turned out to be an
interpreter bug (see [limits.md](limits.md)). The constraint went away; the
design stayed, because it was the better one for three other reasons.

## 6. A witness that can be derived is not a witness

The ladder used to take the scalar's bits as a witness and then spend about
twenty-five bytes a step pinning them: `Σ bᵢ2ⁱ = k` to tie them to the scalar,
and `bᵢ² = bᵢ` so a 2 could not stand in for the next bit's 1.

All of that was constraining a value that was never free. The scalar already
determines its own bits. `OP_NUM2BIN` spreads it into a byte string, and each
bit is a mask and a comparison — seven bytes, with nothing to pin because
nothing was supplied.

The range check came free with it. `OP_NUM2BIN` writes a *signed* number, so
asking for one byte more than the scalar needs puts the sign in that extra byte;
requiring it to be `0x00` says both that the scalar is not negative and that it
does not reach into the byte above. `0 ≤ k < 2^bits` in three bytes and no
comparison.

One subtlety is load-bearing. `mask AND` alone would nearly work — the result is
either zero or the mask, and `OP_IF` takes any non-zero value for true. Nearly:
a lone `0x80` is negative zero to `CastToBool` and reads FALSE, so bit 7 of every
byte would be silently skipped. Comparing against the mask costs two bytes and is
the same shape for all eight.

## 7. Arrange the stack so the calling convention is already satisfied

`apply()` moves the caller's values into the callee's declared order. When they
are already there, it should emit nothing — and it now checks, instead of
rolling five arguments into the positions they were in.

That makes the arrangement worth designing. In the ladder's conditional
addition, the accumulator is already the top pair; pushing the point above it and
rotating the inverse back on top leaves exactly `[accx, accy, x, y, inv]`, which
is the callee's argument order, so the call itself is free. Ten bytes a step,
512 steps in an ECDSA verification.

This is the payoff for tracking values by name rather than by depth. The
assembler knows what is where, so it can tell when the answer is "already
correct" — which a hand-written `OP_ROLL` cannot.

## 8. Consume a value where it is last needed

The cleanest of them, and the one that made the previous trick unnecessary.

Every read of a live value is either a `pick` — copy it, I need it again — or a
`roll` — take it, this is the last time. They cost the same. But a value that is
rolled at its last use is gone, and a value that is picked is still there at the
end, waiting to be dropped.

Written with picks throughout, `ec.add` finished with nine values live and paid
eleven bytes of altstack and `OP_2DROP` to clear the seven it no longer wanted.
Written with a roll at each last use, it finishes with exactly its two results
and pays nothing:

```
x₂  read in dx, read in x₃            → pick, then roll
y₂  read once, in λ                    → roll
invdx  read in the check, then in λ    → pick, then roll
λ   read twice in x₃, once in y₃       → pick, pick, then roll
```

The same idea removes the temporaries that were never worth naming. `dx` has
exactly one use — the inverse check — so it is built on top of the stack, checked
there, and consumed there. A temporary that is never named is one that never has
to be dropped.

This is a register allocator's job, done by hand and checked by the assembler:
reading a value after its last use is a build-time error, because the name is
gone from the model.

## 9. One ladder for two scalars

ECDSA needs u₁·G + u₂·Q. Done as two separate multiplications that is 256
doublings for Q, 256 conditional additions for each scalar, and — because G is
fixed at compile time — a 68-byte pair of constants pushed at every step of the
first ladder. 768 point operations and 17 KB of table.

Interleaved, one accumulator serves both. Double it once per bit, then add
whichever of G, Q or G+Q the two bits select: 512 operations, one doubling chain
instead of two, and G lives on the stack rather than in every step's instruction
stream. 82,280 → 59,141 bytes, and the witness with it, 25,622 → 17,169.

**Windowing and NAF buy nothing here, and it is worth knowing why.** Both make
fewer additions *happen*. In a locking script an untaken branch still costs its
bytes, so only the static instruction count matters. Measured, a 2-bit window is
worse: it removes 128 additions and adds a sixteen-way selection to each of the
128 remaining steps.

**The selection is arithmetic, not a branch.** Choosing between three points with
nested `OP_IF`s would put three copies of the addition in the script. With b₁ and
b₂ pinned to 0 or 1:

```
S = b₁·(G + b₂·C) + b₂·Q      where C = T − G − Q (mod p),  T = G + Q
```

which is G, Q and T for the three live cases, and is never evaluated for the
fourth because that one skips the addition entirely. Written as
`b₁G + b₂Q + b₁b₂C` it needs the shared product computed and then dropped;
factored this way it does not.

**And the order of the step is chosen so the calls are free.** The doubling comes
first, while the accumulator is still the top pair, so the tape's record lands
directly above it in the callee's argument order. After the selection, one
`OP_ROT` puts the inverse back on top and the addition's call emits nothing
either. Extracting the bits first would bury the accumulator and cost ten bytes
a step to dig it out.

## 10. Share the accumulator: the squaring belongs to the bit

A Miller loop squares its accumulator once per bit of the curve parameter and
multiplies in one line per point-step. That is a correctness statement before it
is an economic one — a set bit contributes *two* lines and still only one square,
and squaring again before the chord gives f² where f was wanted. It cost 2,375
extra bytes to compute the wrong answer, and every component test passed while
it did.

Read the other way round, it is the whole economics of a multi-pairing. k
pairings on one accumulator pay for 63 squarings **between them**:

| pairs | emitted | as separate pairings | saved |
| ---: | ---: | ---: | ---: |
| 1 | 935,334 | 935,334 | — |
| 2 | 1,142,571 | 1,870,668 | 728,097 |
| 3 | 1,346,218 | 2,806,002 | 1,459,784 |

Each pair after the first costs about 204 KB instead of 935 KB. What goes is the
squarings it would have duplicated and the 592 KB final exponentiation it would
have repeated. This is why every pairing-based protocol is written as a *product*
of pairings and never as pairings compared one at a time.

## 11. An exponent is an addition chain, and p is free

The final exponentiation raises to λ = 3(p⁴ − p² + 1)/r, which is 1,270 bits.
Done directly that is 1,270 squarings. Two structural facts collapse it:

- **p is a Frobenius map, not an exponentiation.** Write λ in base p and its
  four digits are applied by φ, which is six conjugations and seven Fp2
  multiplications — 798 bytes.
- **each digit is a small polynomial in the 63-bit curve parameter.** Write the
  digits in base y = |x| and every coefficient comes out with |a| ≤ 3, so what
  remains is five exponentiations by a 63-bit number, *shared* across all four
  digits.

1,270 squarings → 887 with the base-p step alone → **315** with both. The digits
are derived at load time by the same arithmetic everything else uses, so a
mistranscribed constant is not a thing that can happen.

## 12. Present the tower flat to find the right basis

Squaring in the cyclotomic subgroup costs half a general squaring — `fp12.sqr`
is 2,375 bytes and `fp12.cycSqr` is 1,342, and the final exponentiation does 342
of them. Two attempts at the formula disagreed with general squaring and were
thrown away.

What made the third work was changing the *presentation*, not the algebra.
Fp12 = Fp6[w]/(w² − v) over Fp2[v]/(v³ − ξ) means w² = v and w⁶ = ξ, so it is
equally Fp2[w]/(w⁶ − ξ) with basis 1, w, …, w⁵. And since (w³)² = ξ, the element
is three Fp4 coefficients — **(g0,g3), (g1,g4), (g2,g5)**.

Those pairs are what the nested indexing hides. Both failed attempts had them
wrong. The lesson generalises past this one formula: when a published identity
will not reproduce, suspect the basis before the algebra.

## 13. Multiplying by zero is still an OP_MUL

Nine of a Miller line's twelve Fp2 coefficients are zero. A general Fp12 product
multiplies all twelve, and on a CPU that is nearly free because the zeros cost
nothing to skip at runtime. In a locking script the multiplication is *bytes*,
present whether or not it does anything.

Writing the product against the three live coefficients takes it from eighteen
Fp2 multiplications to fourteen: `fp12.mul` is 3,248 bytes and `fp12.mulLine`
is 2,178. The Miller loop does 68 of them.

## 14. If you already have λ, do not ask for it again

The obvious factoring computes the line from the slope and then asks a general
point-addition routine for the next point — and that routine finds the slope
again, which is a second modular inversion for a number the caller is holding.
The reference implementation here had exactly that shape.

Deriving the next point from the λ already in hand: **68 inversions where there
were 136.** Each is a witness the spender supplies and the script bounds and
checks, so halving them halves 136 numbers down to 68.

## 15. MSB-first, so nothing is multiplied by one

Square-and-multiply written LSB-first starts from an accumulator of one and
multiplies into it, so the first multiplication is by one. At runtime that is
free. Unrolled into a script it is a full Fp12 multiplication — 3,110 bytes —
that provably does nothing.

MSB-first consumes the leading bit as the initial value instead: 63 squarings
and 5 multiplications per exponentiation by the curve parameter, where the
reference pays 64 and 6. Over the five ladders in the final exponentiation that
is most of why the emitted script came out **8.7% smaller than the model built
from the reference's operation counts** — the model was counting a schedule the
emitter improved on.

## 16. In Script, affine beats projective — the trade inverts

Every fast pairing implementation uses projective coordinates specifically to
*avoid* inversions, paying several extra multiplications at every step, because
on a CPU an inversion is hundreds of multiplications.

In Script an inversion is four. The spender supplies a⁻¹ off chain and the
script checks a·a⁻¹ = 1, which is one Fp2 multiplication written out —
`fp2.inv` is 145 bytes including the two `OP_WITHIN`s that pin the answer. So
the usual trade reverses and **affine arithmetic is the cheap choice**: the
formulas everyone reaches for would make this bigger, not smaller.

This is the most transferable thing in this document. The cost model of a
locking script is not the cost model of a CPU, and an optimisation that is
received wisdom in one is sometimes backwards in the other. The way to find out
is to emit both and count.

## 17. Let the target decide — instruction selection

Sixteen sections of measured before-and-after, and the honest summary of them is
that the target's cost model is not the one the literature assumes. `npm run
select` makes that operational: given several modules that compute the same
function, it proves they agree and then picks by a stated objective.

```
  f ↦ f² in Fp12   —   agreement checked on 4 vectors from the cyclotomic subgroup
    candidate        lock      unlock       total    opcodes   stack   fee
    fp12.sqr         2,292         588       2,880      1,540      37   288
    fp12.cycSqr      1,259         588       1,847        968      34   185  ◀

  f ↦ f^|x| in Fp12   —   agreement checked on 2 vectors from the cyclotomic subgroup
    fp12.powX       98,902         588      99,490     71,954      61 9,949
    fp12.powXc      73,582       1,175      74,757     54,204      71 7,476  ◀
```

Nothing there was told that the cyclotomic identities or the compression win.
It emitted both and counted, and the cost model did the rest — which is the
difference between hard-coding "affine is better" and a target that discovers
it. The objective is a flag: `--optimize=bytes`, `total`, `opcodes`, `stack`,
`witness`. `total` is the one that matters for a fee, and it is the one where a
witnessed alternative can lose: `fp12.powXc` buys 25,320 bytes of locking script
with 587 bytes of unlocking script, and a construction with a worse ratio would
be rejected on the same evidence.

**The agreement step is the part worth stating.** A selector that picks the
cheaper of two modules without first establishing that they compute the same
thing is a bug generator with a benchmark attached. And comparing their MODELS
is not enough — finding that out was the point of trying. `fp12.cycSqr`'s model
is the general square, correct everywhere; only its emit is confined to the
cyclotomic subgroup. Two candidates whose models agree can have scripts that do
not. So every candidate's script is checked against its own model on every
vector, and the models against each other, which gives

```
script_i = model_i = model_j = script_j
```

Run off the subgroup, the same two candidates are refused rather than ranked.
That refusal is a test: `npm test` fails if it stops happening.

Agreement is always agreement ON A DOMAIN, and every contest names the one its
vectors came from. "Cheaper" without "and equivalent, here" is not a finding.

## 18. Then let a minimizer rebuild the stack traffic

Everything above is decided while emitting, one module at a time. What no
module can see is the script it ends up inside: the value it parks on the
altstack that the next module fetches straight back, the swap into a calling
convention that the next module swaps out of, the modulus every module picks
from wherever the stack has left it.

[scriptmin](https://github.com/codenlighten/scriptmin) works on the emitted
bytes instead. It lifts a whole script to its dataflow and re-emits the stack
choreography: moves at last use, hot values rolled up once, repeated
expressions kept rather than recomputed, balanced altstack round trips dropped,
short sequences replaced by the cheapest equivalent. Every result carries a
proof that the new script fails on exactly the stacks the old one failed on and
leaves exactly the same stack. `src/minimize.js` refuses a result without that
proof.

It is opt-in, because the chain walkers compare rebuilt stage scripts with
what is on mainnet byte for byte:

```
SCRIPTMIN=1 node tools/groth16-chain.js
SCRIPTMIN=1 node tools/pairing-chain.js
SCRIPTMIN=1 node bin/deploy-groth16-chain.js     # build, verify and price
```

Only stage scripts go through it. The carrier reads its own script code and
every stage embeds the carrier's body, so the carrier is left exactly as
emitted. A stage's OP_PUSH_TX preimage contains its locking script, which is
fine: every tool grinds its preimages against whatever script it deploys.

Measured with the tools' own honest runs and attacks, all of which behave as
before (every honest link accepted, every forged state, forged `cur`, wrong
statement and forged witness refused by the same script with the same error).
Sizes are exact; they depend only on the scriptmin commit.

| locking script | as emitted | scriptmin `2a45495` | scriptmin `6efc957` |
| --- | ---: | ---: | ---: |
| groth16.chain1 — A, C ∈ G1, rounds 1–31 | 401,185 | 240,371 | 234,054 |
| groth16.chain2 — rounds 32–63, B ∈ G2 | 368,525 | 216,214 | 210,647 |
| groth16.chain3 — final exponentiation | 477,044 | 298,248 | 286,491 |
| pairing.chainMiller | 344,840 | 206,795 | 200,678 |
| pairing.chainExp | 476,067 | 297,263 | 286,816 |

`6efc957` adds a beam search over the scheduler's choices; most of what it finds
is the modulus, rolled up just before an operation whose result it then sits
under, so the reduction after it fetches p with a one-byte `OP_OVER`.

With `6efc957`, on an idle machine, the heaviest link of the Groth16 chain
validates in 0.38× the time of the pairing spend that relayed, and the heaviest
link of the pairing chain in 0.41×; the largest unlocking script in the Groth16
chain is 208,246 bytes under the 500,000-byte policy, against 17,693 as emitted.
Validation time falls with size because much of what disappears is executed
stack traffic, not dead bytes.

**Which scriptmin.** A minimized script is reproducible only with the optimizer
that built it. `scriptmin` in `optionalDependencies` is pinned to a commit and
builds everything new; a deployment records the commit it was built with; and a
commit an existing deployment still needs is installed beside it under an alias,
`scriptmin-2a45495` for the pairing chain on mainnet. The walkers rebuild each
deployment with its own commit, and say so when it is not installed.

That raises the question the chain was built to avoid: could the
single-transaction Groth16 split relay again? `npm run relay:scriptmin` times it
against the two on-chain yardsticks. On an idle machine, two runs with
`6efc957` put the minimized split at 1.06× and 1.12× the pairing spend that
relayed (`2a45495`: 1.10× and 1.20×), against 1.48–1.57× for the split as it
was deployed, which relay refused. (Runs on a heavily loaded machine said 0.93×
and 1.13×; the idle runs replace them.) So minimizing takes the one-transaction
verifier most of the way back but not under the spend known to relay, and the
answer stays the chain.

## What was tried and rejected

**Reversing bytes arithmetically.** `bytes.reverse` is 4 bytes per byte
reversed — a split, a swap, a concatenation. Reconstructing the value from
individual bytes with multiplications is 32 bytes per four, which is worse, and
the altstack does not help: pushing n items and popping them reverses the order
twice, which is the order you started with.

**Granger–Scott cyclotomic squaring, twice.** Two versions of the formula, both
written from the nested Fp6[w] indexing, both of which disagreed with general
squaring on an element known to be in the subgroup. Neither was kept: a pairing
cost derived from an unverified optimisation is worth less than a conservative
one that can be checked, and for a while `docs/pairing.md` said exactly that and
named the ~25% it was leaving on the table. The third attempt worked and is
§12 above. **What made it publishable was that the two failures were checked
against `f12sqr` rather than against a test that could pass either way.**

**A hard-part chain remembered rather than derived.** The first final
exponentiation used an addition chain written from memory. It was wrong, and it
was wrong in a way that still produced an order-r element — so it looked right.
Replacing it with a balanced base-p decomposition derived at load time made it
correct and slower (887 squarings), and only then was it worth optimising into
§11's 315. Deriving before optimising is what made the second step safe.

**Storing 32-bit words little-endian.** It would make `u32.add` about four times
cheaper by removing two byte reversals per addition. It also makes every
rotation more expensive, because `OP_LSHIFT` and `OP_RSHIFT` treat a byte string
as big-endian, and SHA-256 does more rotations than additions. Measured on the
round structure it is roughly a wash, and `sha256.block` is the control
experiment rather than something anyone should deploy — the effort belongs where
the bytes are actually spent.
