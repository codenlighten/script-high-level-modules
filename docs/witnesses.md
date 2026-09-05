# Witnessed values: soundness, and the other thing

Some operations are far cheaper to **check** than to **compute**.

The modular inverse is the standard example. Computing it means the extended
Euclidean algorithm — a data-dependent loop, which an unrolled Script cannot
express without bounding it by the size of the modulus. Checking it is one
multiplication:

```
0 ≤ inv < n   ∧   a · inv ≡ 1 (mod n)
```

So the spender supplies it, and the module verifies it. `int.modinv` is 82 bytes
at 256 bits. That single trade is what makes affine elliptic-curve arithmetic
affordable in Script at all, and it is why every point operation in this
repository takes a witness.

It is also where a module goes quietly, dangerously wrong. A witnessed module
carries two obligations, not one.

## Soundness: no wrong witness is accepted

The obvious one. If the module accepts a witness that does not satisfy the
relation, it computes the wrong answer and the covenant above it is broken.

## Canonicity: no *second* witness is accepted either

The one that gets skipped.

`a · inv ≡ 1 (mod n)` is true of `inv`. It is also true of `inv + n`, and of
`inv + 2n`, and of every other representative of the same residue class. A
module that checks only the congruence is sound — it never accepts a *wrong*
answer — and still broken, because its output is a function of the spender's
choice rather than of its inputs.

What that costs depends on what sits above it:

- a module that **returns** the witness produces a different result for each
  accepted witness, so the covenant computes something the spender picked;
- a module that only **verifies** still lets the unlocking script be rewritten,
  which changes the transaction's txid without changing what it does. Anything
  downstream that referenced the old txid — a chain of unbroadcast transactions,
  a payment channel — breaks.

The range check `0 ≤ inv < n` is what reduces the residue class to one member.
Two comparisons.

## The kit attacks both

For every witnessed input, the test kit builds an **acceptance** script — the
module with its outputs dropped and nothing asserted about them — and asks
whether the module accepts a forged witness. The near-misses, not random noise:
off by one, zero, one, negated, and the same residue plus or minus the modulus.

Asking the *correctness* script instead is the mistake that hides all of this,
and it is the first thing this kit got wrong. A forged witness that the module
happily accepts still fails the test's own comparison against the honest answer,
so the run reports a refusal that never happened. Separating "did the module
accept?" from "did it compute the right value?" is the whole difference.

Three rules follow, and each is enforced rather than recommended:

**A witness that cannot be attacked is not proven.** If the module supplies no
`attacks()` and the kit cannot construct the near-misses itself, it reports
`UNPROVEN` rather than a green run it did not earn.

**An attack equal to the honest value is not an attack.** Flipping a bit of an
empty message produces the empty message; being accepted is then correct
behaviour. Counting it as a refusal, or as a break, would both be lies, so the
kit discards it — and if nothing survives, says so.

**Witnesses that are the point of a module are always attacked.** A module with
hundreds of witnessed inputs cannot be attacked exhaustively, so the kit samples
and reports the sample honestly (`a sample of 10 of the 13 witnessed inputs`).
But a signature's own `r` and `s` are never left to a sample.

## Four worked examples

### `int.modinv` — the range check is the module

Drop `0 ≤ inv < n` and `inv + n` is accepted. `npm run selftest` writes exactly
that bug on purpose and fails if the kit misses it.

### `rsa.verify` — s and s + n are both e-th roots

`s^e mod n` does not distinguish `s` from `s + n`. Without the bound, one RSA
signature is an unbounded family of valid unlocking scripts:

```
  range check         unlocking script       verdict
  with 0 ≤ s < n      the signature          ACCEPTED
  with 0 ≤ s < n      the signature + n      refused
  WITHOUT the check   the signature + n      ACCEPTED
```

Cost of the check: 267 bytes. `npm run malleability`.

### `ecdsa.verify` — the malleability is in the scheme, not the module

If `(r, s)` verifies then so does `(r, n − s)`: `R` and `−R` share an x
coordinate, and x is all the equation looks at. Both are genuine signatures over
the same message by the same key, so this is not a bug to fix — it is a
canonicity rule to choose. Enforcing `s ≤ (n−1)/2` picks one.

This is the same rule Bitcoin applies to `OP_CHECKSIG`, where `LOW_S` is
mandatory policy, for the same reason. A verifier built out of arithmetic
inherits the problem and should inherit the answer.

### `schnorr.verify` — the scheme that needed no rule

Worth putting beside the ECDSA case, because it is the same problem answered by
the design rather than by policy. A BIP-340 signature over a message under a key
is **unique**: there is no second representation to choose between, so there is
no low-S rule to impose and no 267 bytes to spend imposing it. Canonicity can be
a property of the cryptography instead of a property of the covenant, and when
it is, the covenant is smaller and the argument is shorter.

Its x-only public key is a witnessed value of exactly the kind this document is
about. Thirty-two bytes name the x coordinate and imply the even-y point; y is
recovered with a square root, which is expensive to compute and cheap to check,
so the spender supplies it. Both obligations are attacked: a wrong y fails
y² = x³ + 7, and the *other* y of the same x — the odd one, which satisfies the
equation perfectly — fails the parity check. Soundness and canonicity, in two
comparisons.

### `ec.mul` — the witness that is never read

In a double-and-add ladder, a step whose bit is zero never reads its inverse.
Leaving it unconstrained would let anyone rewrite that push — a value the script
does not look at — and change the txid. The `ELSE` branch therefore requires it
to be zero. Three bytes per step.

The same reasoning applies to the packed witness tape: after the last step, the
script requires what remains of the tape to be **empty**. Trailing junk would
otherwise ride along in the unlocking script, unread and unconstrained.

## Testing against the standard, not against yourself

Three modules here are checked against vectors published with the specification
rather than against a second implementation: `totp` against RFC 6238's,
`sha256.block` against OpenSSL's digest, and `schnorr` against BIP-340's.

The BIP-340 set is the one worth describing, because ten of its nineteen vectors
are **negative** — and those are run through the Script module, on the
interpreter, as spends that must be refused. A public key that is not on the
curve. An r past the field size. An s equal to the group order. An odd R.y. A
negated message. A negated s. Two where sG − eP is the point at infinity.

Every one of them is a way to be wrong that verifying honest signatures would
never reveal, and none of them is a way a second implementation by the same
author would think to be wrong either. A refused vector still needs a witness,
or the harness refuses it before the script is reached and the case proves
nothing; where no honest witness can exist, a zero-filled one of the right shape
is supplied so the script refuses it at the point it should.

## The audit that found three of these

Everything above was written before the modules were audited for it. Going back
over them with one question — *what values can a spender choose, and is each of
them pinned to exactly one?* — found the same defect three times, in three
modules, none of which any test had caught.

**`schnorr.liftX` did not bound x below the field size.** BIP-340 says it must.
Thirty-two bytes can encode more than the field holds, and `x mod p` is then a
different valid key. It is reachable: x = 1 is on secp256k1, so `1 + p` fits in
32 bytes and names the same point. The standard's own vector 14 misses it,
because the value that vector uses has no y at all — which is why nineteen green
vectors did not catch it.

**`ecdsa.verify` did not bound the public key's coordinates**, and there the
encoding is a Script number rather than 32 bytes, so there is no width to run
out of. Measured before the fix: the key as given, ACCEPTED; the same key as
`qx + p`, ACCEPTED; as `qy + p`, ACCEPTED. Every public key had infinitely many
accepted encodings. The curve equation does not catch it because the curve
equation is checked mod p and holds for all of them.

**`ec.add` documented that its coordinates were in [0, p) and did not check.**
The formulas defer reduction, and x₃ = λ² − x₁ − x₂ + 2p is non-negative only
because x₁ + x₂ < 2p. With λ = 0 and both x above p, x₃ comes out negative, and
`OP_MOD`'s truncation leaves it negative: congruent to the right answer, and not
the canonical representative of it.

The lesson is not that bounds are important — everyone knows that. It is that
**a precondition is not enforced by being written down**, and the place these hid
is the gap between a module that is used correctly by its own ladder and a module
that is used at all by anybody else. `ec.add` enforces the bound only in its
standalone form, where the caller is whoever wrote the unlocking script; inside
the ladder every coordinate is a reduction the module itself produced, and
checking it 512 times would cost 7 KB to learn nothing.

Two of the three are now deliberate bugs in `npm run selftest`, where the module
with its bound removed accepts what the standard refuses.

There was a fourth, one layer down, and the same question found it: `int.modadd`
had documented "for a, b already in [0, n)" since the first week and enforced
nothing. Measured — `modadd(−3, 1) mod 11` is **−2**, `modmul(−3, 4) mod 11` is
**−1**. `OP_MOD` truncates, so a negative anywhere upstream stays negative, and a
result congruent to the right answer is not the right answer.

And the class is closed rather than patched. A module states what it requires of
each input and promises of each output; every value carries what is known about
it; and at each call the framework discharges the requirement from an upstream
fact, emits the check, or refuses to build. See
[modules.md](modules.md#what-a-module-requires-and-what-it-promises). Applying it
to `ec.add` reproduced the hand-placed checks byte for byte — and put one more in
`ec.mul`, on the input point, which I had missed by hand.

## Inputs nobody chose

Every module is checked against its own cases, and the cases are the ones
somebody thought of. All four bugs above lived in exactly that gap: each was a
value outside the range anybody had written a case for.

`npm run fuzz` generates inputs instead of choosing them, and asks the two
questions the suite otherwise asks only where a case exists — does the Script
compute what the model says, and does the module's own `ensures` hold of what
the model returned. Eighteen modules, forty rounds each, sampled toward the edges
of the domain where the bugs were found.

**The domains come from `requires`.** That is the second dividend of stating
them: the declaration that decides where a bound is emitted also says what the
module is defined on, so the fuzzer samples the domain rather than guessing at
it. A module that states nothing and offers no generator is skipped **and said to
be skipped**, because a fuzzer that quietly tests nothing is worse than none.

Which witnesses to generate is answered by the module rather than by a rule about
them. `schnorr.liftX` takes an x-only key *and* the y for it, both marked
`witness`, and only the second is derived — so the fuzzer generates candidates
for all of them, asks `hint()` what it works out for itself, and drops those. A
generated value for a derived witness would be a wrong one, and would take
precedence over the honest answer.

The fuzzer checks itself first. A module whose promise is true of the cases a
careful author would write and false of the domain it claims runs before
anything else, and if generated inputs do not catch it, the run stops there.

```
selfcheck  its own cases pass, generated inputs catch it
           r = 192215 is not in [0, 100), which the module promises
```

## Sound but not complete

One more distinction worth keeping separate from the two above.

The elliptic-curve ladder starts its accumulator at a nothing-up-my-sleeve point,
because affine coordinates cannot represent the point at infinity and a runtime
scalar gives no first-set-bit to start from. If an intermediate addition lands on
infinity, `dx` is zero, no inverse exists, and the spend is **refused**.

That is a completeness failure, not a soundness one: the module never accepts a
wrong answer, it occasionally declines to accept a right one. For inputs that are
not chosen adversarially the chance is about 2⁻¹²⁸ per step. An attacker who
controls the point can force a refusal — which costs them a spend they could
equally have declined to make.

Saying which of the two a limitation is, is most of the work of documenting it.
