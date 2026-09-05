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

## Size is not the constraint people expect

50,000 sequential opcodes in a 100 KB script verify without complaint. The
budget that matters is the fee, and the fee is bytes — see [cost.md](cost.md).
