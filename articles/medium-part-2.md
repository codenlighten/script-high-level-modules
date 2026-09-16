# A Coin That Only Moves for Someone Over 21

*A zero-knowledge proof of age, verified by Bitcoin Script on mainnet — and the limit that nearly kept it off the chain.*

**Bitcoin as a Mathematical Machine, Part II**

---

[Part I](#) ended with a complete BLS12-381 pairing evaluated on BSV mainnet, across two inputs of one transaction. A pairing is machinery. This is what the machinery is for.

There is a coin on the Bitcoin SV blockchain that moves only for someone who can prove they were at least 21 years old in 2026. The proof reveals nothing else. Not a birth date, not a name, not a document — nothing but the fact itself. Bitcoin Script checked the proof and released the coin.

```text
the statement    "I am at least 21 years old as of 2026."
public           the year, and the age required
private          the birth year — never on chain, never in the proof

the prover       snarkjs, Groth16 over BLS12-381
the verifier     Bitcoin Script — 1,246,986 bytes, no pairing opcode
```

Three outcomes, and the third is the one worth staring at:

| | |
| --- | --- |
| a valid proof of the right statement | the coin moves |
| a proof from someone underage | the coin does not move |
| a valid proof of a **different** statement | the coin does not move |

The third case uses the *same* proof, from the same prover, and it is perfectly valid — for a claim the coin never made. The public inputs are compiled into the locking script, so "at least 21" and "at least 30" are different coins, and a proof of one is not a key to the other. The statement isn't attached to the proof. The statement **is** the coin.

The underage case is worth a second look too. snarkjs's prover will happily produce a proof-shaped object from a witness that doesn't satisfy the circuit. It just doesn't verify. Bitcoin is what notices.

## Verifying a SNARK is three pairings

A Groth16 proof is three group elements — A, B and C — and verifying it is one equation:

```text
e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)
```

Everything except A, B and C is fixed by the verifying key and the statement, so the locking script pushes those as constants. **That distinction is the entire security property.** A verifier where the spender could also choose γ would be a script that checks an equation, not one that checks a proof: pick a convenient γ and the equation holds for a proof of nothing. The two constructions differ by 490 bytes of pushed constant.

Three pairings sharing one Miller loop come to 1,246,986 bytes of Script. The relay policy limit is 500,000. So, as in Part I, the computation is split across the inputs of one transaction — three this time:

```text
input 0   A and C are in G1; rounds 1–31 of three Miller loops   399,402 B
input 1   rounds 32–63; B is in G2                               371,834 B
input 2   the final exponentiation, against e(α, β)              475,647 B
output    the state all three commit to, 44 field elements         2,156 B
```

The Miller loop itself had to be cut, at round 31 of 63, because three loops sharing one accumulator are 705,838 bytes before the final exponentiation even starts. Nothing makes round 31 special. It's the point where the state passed between halves is small enough — 44 field elements — and each half fits.

## A point on the curve is not necessarily the right point

Here's a bug class that never appears in a textbook equation.

A BLS12-381 curve contains more points than the subgroup a pairing is defined on. A proof point can satisfy the curve equation perfectly and still lie outside that subgroup, where the pairing stops being the bilinear map the proof system's security argument assumes. Every production verifier rejects such points. Part I listed this as an open gap in mine.

It's closed now, and for less than I'd estimated. Each curve has a symmetry that acts on the proper subgroup as multiplication by a small number, so instead of a full 255-bit scalar multiplication you compare two cheap things:

- **A and C** get two short ladders — 136 point operations with the inverses supplied by the spender — against a one-multiplication symmetry.
- **B** gets almost nothing. A Miller loop over B *already computes* the exact point the check needs. The check is a comparison against a value the verifier is already holding.

Together: **17,790 bytes, 1.4% of the verifier.** My earlier guess was 5–10%.

I didn't take the underlying number theory on faith. A script in the repository computes every fact the checks rely on — which cube root, the twist's group order chosen from six candidates, that two cofactors are coprime — and cross-checks the verdicts against an independent implementation's own torsion test, on points inside and outside both subgroups.

Then I checked that the new checks are what actually rejects bad points. That sounds circular, but it isn't. The whole verifier would reject an out-of-subgroup point anyway, because the pairing equation fails too — so the whole verifier can't tell you which check did the work. The first stage of the split checks no equation at all. Built without the subgroup checks, it accepts a bad point and carries it forward. Built with them, it refuses.

## It was valid. It couldn't travel.

Here's the part I didn't expect.

The three coins were funded and confirmed immediately. The spend — 1,291,329 bytes, all three inputs verified locally against the real funding transaction — was accepted by a node and then **sat there for 128 blocks.**

Five miners' blocks passed it over. A second block explorer never saw it at all. Submitting it to a mining pool's API came back:

```text
REJECTED: too-long-validation-time
```

I asked the pool. The answer was specific and useful: their node gives any transaction arriving from a peer **at most one second** to validate. This one exceeded it under load. My own timing agreed with the shape of that: its three inputs take about 4.5 seconds in my (much slower) JavaScript interpreter, against 3.0 seconds for the pairing spend from Part I that relayed without trouble. Same interpreter, same machine, 1.5× the work.

The pool then submitted the transaction to their own node directly and mined it. It's in **block 966,923**.

So the transaction is on chain — and the interesting part is *how*.

**Three different limits bound this work, and they are not the same kind of thing:**

1. **Script size** bounds one script. That's why the computation was split at all.
2. **The unlocking script's size** bounds each stage — because the OP_PUSH_TX preimage contains the very script it unlocks, so a covenant's unlocking script is as big as its locking script. Not where you'd look for a limit.
3. **Validation time** bounds the *transaction* — which is exactly the unit the three-stage design packed everything into.

The third one is different in kind. Script size is policy about a transaction's contents; validation time is a budget a node spends on work arriving from strangers. **A transaction can be consensus-valid, relayable nowhere, and mined anyway** by an operator willing to take it by hand. The spend is valid. The block containing it is valid. It simply could not travel.

That's not a complaint about the limit — it's a sensible defence against cheap-to-send, expensive-to-check spam. It's a design constraint I hadn't priced, and now do: **a construction that doesn't depend on anyone's goodwill has to spread its stages across transactions rather than inputs**, so no single transaction asks for more than a second of anyone's time. That's the next build.

## The next build, built

It's built, and it's on chain.

The mechanism is a **carrier coin** holding a *pair* of states — the previous one and the current one — which demands that whatever spends it produce a successor holding **its** current value as the new previous. Beside it sits one stage of the computation, demanding that the successor's current value be whatever that stage computed. Neither coin reads the other's script; an outpoint doesn't name one. They agree because they each rebuild the same output bytes, and the transaction has to hash to what both of them expect:

```text
carrier:  output = body ‖ myCur ‖ X       X witnessed, unconstrained
stage:    output = body ‖ p     ‖ F(p)    p witnessed, unconstrained
```

Both hash the same output, so `p` must be `myCur` and `X` must be `F(p)`. With that, the pairing from Part I runs again, one stage per transaction:

| | lock | unlock | a node spends |
| --- | ---: | ---: | ---: |
| tx₁, the Miller loop | 344,840 B | 351,963 B | 1,229 ms |
| tx₂, the final exponentiation | 476,067 B | 480,352 B | 1,834 ms |

The heaviest link is **0.60×** the Part I spend that relayed without trouble — well inside the budget that refused the transaction above. All three transactions were mined in **block 966,954**, the first block after they were broadcast, by the same pool whose relay check had turned down the Groth16 spend.

Two honest footnotes. Minutes earlier, that pool also refused tx₁ — for paying two satoshis under its minimum fee, which was my arithmetic and not its policy. The useful part is what the episode says about the platform: a node's relay threshold, a miner's mining threshold, and consensus are three different thresholds, and only the last one is the rule.

The second matters more. **This is Part I's pairing, not Part II's SNARK.** The machinery is identical and the verifier is the obvious next thing to chain, but what travelled here on its own merits is one pairing, not three.

And it costs something real: **atomicity.** When the stages were three inputs of one transaction, each could check through `hashPrevouts` that it was being spent beside its siblings, and the transaction's validity *was* the whole claim. Spread across transactions, the carrier arrives from a transaction whose txid nothing could have known when the stage coins were written — so no stage can insist the carrier beside it is genuine. The claim becomes one about a *chain*, and somebody has to walk it: `npm run verify:chainwalk` rebuilds both stage coins from source, finds them in the funding transaction, follows the carrier from link to link, and compares the value the last one holds against the pairing computed locally.

That's the trade. The single-transaction version binds everything at once and cannot be sent; this one travels, and asks the reader for the last step.

## And a bug in my own tests

While adding the subgroup cases I found something less flattering. My test kit had been counting a "must be refused" case as refused whenever it *couldn't even build the spend* — for instance, when the case named the proof but not its witnesses. Every refusal case on the whole Groth16 verifier was built that way.

So "the coin does not move for someone underage" had been reported as passing without the interpreter ever running it.

It's fixed. The kit fills in the missing witnesses and runs the script, and a case it can't build is now a failure rather than a pass. Every affected case has since been run for real, and every one still refuses. A test that cannot fail isn't a test, and I'd rather publish that than let the green checkmarks speak for themselves.

## What is actually on chain

| | |
| --- | --- |
| funding | [`025f20f1…c5f0`](https://whatsonchain.com/tx/025f20f1d4156aa354afef37b1ec67e5c461f11375bc739902845a3b985dc5f0), block 966,795 |
| spend | [`cad6d2cc…4bb6`](https://whatsonchain.com/tx/cad6d2cca44fffb2f445009f392b668382d79d120b1c14db0fd4a8d192204bb6), block 966,923 |
| what it establishes | a snarkjs Groth16 proof of age verifies, points in their subgroups and pairing equation both |

The birth year never touched the chain. The network learned that someone was old enough, and nothing else, and enforced payment on that basis.

**Next, Part III:** Bitcoin Script verifies a post-quantum signature — and this time I measured validation time *before* spending the money.
