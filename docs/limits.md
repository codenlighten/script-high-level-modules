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

## The stack is capped at 1000 elements

The one limit here that actually bites. `999` elements verify; `1001` is
`SCRIPT_ERR_STACK_SIZE`. It is a cap on the COUNT, not the size: a single
100 KB element is fine.

This is what decides the shape of any construction with a large witness. A
256-step elliptic-curve ladder needs a bit and one or two inverses per step —
over seven hundred values — and two ladders in one script overflow the cap long
before the fee becomes interesting. So the witness arrives as **a packed tape**:
two byte strings that the script splits one field off the front of as it goes.
Three stack elements per ladder instead of seven hundred. See `emitLadder` in
`src/modules/ec.js`.

A caveat worth stating rather than hiding: post-Genesis BSV nodes replaced the
element-count limit with a limit on stack *memory*. This interpreter enforces
1000 elements unconditionally. Since this interpreter is what proves every
module here, that is the number the modules are built against — but a script
that fails only on this limit might be accepted by a node, and one that passes
here is not thereby proven to fit a node's memory limit. Neither direction is
assumed.

## Size is not the constraint people expect

50,000 sequential opcodes in a 100 KB script verify without complaint, and the
largest module here is a 197 KB script that runs 112,753 opcodes. The budget
that matters is the fee, and the fee is bytes — see [cost.md](cost.md).
