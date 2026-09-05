# What the interpreter actually does

Every statement here is a passing probe in `tools/probe-limits.js` (`npm run
probe`). None of it is quoted from a specification, because the specification is
not what validates the spend — this interpreter is, under the flags a node
relays with.

## Numbers are arbitrary precision

Post-Genesis, `MAX_SCRIPT_NUM_LENGTH` is **750,000 bytes**, element size and
opcode count are unlimited, and `OP_MUL` / `OP_MOD` operate on the full width.
Measured working at 64, 256, 512, 1024, 2048 and **4096 bits**.

This is the fact the whole library rests on. A 2048-bit modular multiplication
is *one opcode*, not a bignum library written in Script. RSA verification is
cheap for the same reason.

## `OP_MOD` is truncated, not Euclidean

    (−3) MOD 5  =  −3          3 MOD (−5)  =  3
    (−7) DIV 2  =  −3          7 DIV (−2)  =  −3

The sign follows the dividend. "Reduce mod n" is only correct when the value
entering `OP_MOD` is known non-negative — which is why `int.modsub` adds `n`
before reducing, and why it is a module rather than three opcodes written inline.

## The sign bit is the top bit of the last byte

A byte string read as a number is little-endian sign-magnitude. `ff` is −127,
not 255; `ff00` is 255. Anything assembled with `OP_CAT` and then read with
`OP_BIN2NUM` needs the trailing `0x00` — `bytes.beToNum` is that conversion,
with cases.

`OP_BIN2NUM` accepts a non-minimal input even under MINIMALDATA (it is a
conversion). A non-minimal *push* read as a number is refused
(`SCRIPT_ERR_SCRIPTNUM_MINENCODE`).

## `OP_NUM2BIN` writes a *signed* number

`0x80000000` does not fit in four bytes: the interpreter refuses it with
`SCRIPT_ERR_IMPOSSIBLE_ENCODING`. A 32-bit word needs `OP_NUM2BIN` to five bytes
and the sign byte split off. `u32.add` does this, and carries the case that
proves it — a case its first version did not have, which is how the bug got in.

## Bitwise operations need equal lengths

`OP_AND`, `OP_OR`, `OP_XOR` on unequal-length operands is
`SCRIPT_ERR_INVALID_OPERAND_SIZE`. The assembler tracks widths and refuses at
build time instead.

`OP_LSHIFT` and `OP_RSHIFT` shift the byte *string* as a big-endian bit string
and preserve its length (`01020304 << 8 = 02030400`, `0f0f << 4 = f0f0`). That
is why a 32-bit word is stored big-endian here: rotations are two shifts and an
OR, one opcode each.

## The stack cap is era-derived — and this repository is why

Pre-Genesis the two stacks may hold 1000 elements between them. Genesis removed
that cap, replacing the element *count* with a bound on the memory the stacks
occupy, so a script is limited by what it uses rather than by how it is divided
up. Measured: 5,000 elements verify post-Genesis, and 1,001 is
`SCRIPT_ERR_STACK_SIZE` under pre-Genesis flags.

**This document used to say the opposite**, because the interpreter said the
opposite. Building a 256-step elliptic-curve ladder is what found it: the
library applied 1000 unconditionally, and it checked the cap *once, at the end
of the script* rather than after every opcode. Two divergences from the node in
five lines, in opposite directions —

- a **false reject**: post-Genesis scripts the network accepts were refused here;
- a **false accept**: a script that piles up 1,001 elements and drops back to one
  before it finishes passed here and is rejected by the network. No vector in the
  node's corpus catches that one, because every `STACK_SIZE` vector ends over the
  cap, which is exactly the case an end-of-script check does see.

Both are fixed in **`@smartledger/bsv` 9.7.0** — `maxStackSize()`,
`maxStackMemoryUsage()`, and `checkStackLimits()` called after every opcode — and
that is the version this repository depends on. The probes above measure the
corrected behaviour and go red if it regresses.

The pre-Genesis half is worth a note on how it was tested. The obvious
regression test — 1,001 pushes and 1,001 `OP_DROP`s — passes for the wrong
reason: 1,001 drops exceed the pre-Genesis 500-opcode budget, so the script is
refused by the opcode cap before the stack cap is ever the deciding rule. The
test that isolates it uses 500 `OP_2DROP`s, which clear two elements apiece and
land exactly inside the budget.

### The packed tape stays anyway

The ladder was designed around the old cap: the bits and inverses a 256-step
ladder needs — over seven hundred values — arrive as **two packed byte strings**
that the script splits one field off the front of as it goes, three stack
elements instead of seven hundred.

The cap is gone and the tape is still the right design, which is worth saying
plainly rather than quietly deleting the constraint that produced it. It makes
the unlocking script smaller (no per-push prefix on seven hundred values), it
lets the script require the tape to be *exactly* used up so no unread bytes ride
along, and it leaves the stack shallow enough that every `OP_PICK` depth stays a
one-byte push. See `emitLadder` in `src/modules/ec.js`.

### The memory bound

The post-Genesis replacement is a policy limit — the node's
`-maxstackmemoryusagepolicy`, default 100 MB — and each element is charged the
footprint of its container as well as its bytes, so a stack of many small
elements is not free. Nothing here comes close to it; the largest module holds a
few dozen elements.

## Size is not the constraint people expect

50,000 sequential opcodes in a 100 KB script verify without complaint, and the
largest module here is a 197 KB script that runs 112,753 opcodes. The budget
that matters is the fee, and the fee is bytes — see [cost.md](cost.md).
