# Making it smaller

Fees are bytes. Everything in this document is a measured before-and-after on
the real interpreter, and every one of them left the suite green — the point of
having 179 cases and 648 forgeries is to be able to restructure code like this
and know immediately whether it still refuses what it used to.

| | before | after | |
| --- | ---: | ---: | ---: |
| `ec.add` | 191 | 139 | −27% |
| `ec.double` | 191 | 139 | −27% |
| `ec.mul` (256-bit) | 116,127 | 42,086 | −64% |
| `ec.mulG` (256-bit) | 80,216 | 39,833 | −50% |
| `ecdsa.verify` | 196,778 | 59,141 | −70% |

The standalone figures for `ec.add` and `ec.double` are mostly the two 33-byte
modulus constants they push for themselves; inside a ladder, where those are
hoisted, each is about 65 bytes.

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

## What was tried and rejected

**Reversing bytes arithmetically.** `bytes.reverse` is 4 bytes per byte
reversed — a split, a swap, a concatenation. Reconstructing the value from
individual bytes with multiplications is 32 bytes per four, which is worse, and
the altstack does not help: pushing n items and popping them reverses the order
twice, which is the order you started with.

**Storing 32-bit words little-endian.** It would make `u32.add` about four times
cheaper by removing two byte reversals per addition. It also makes every
rotation more expensive, because `OP_LSHIFT` and `OP_RSHIFT` treat a byte string
as big-endian, and SHA-256 does more rotations than additions. Measured on the
round structure it is roughly a wash, and `sha256.block` is the control
experiment rather than something anyone should deploy — the effort belongs where
the bytes are actually spent.
