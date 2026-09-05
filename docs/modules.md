# Writing a module

A module is one operation, written twice.

```js
const modmul = defineModule({
  name: 'int.modmul',
  doc: 'r = (a · b) mod n',
  inputs: ['a', 'b'],
  outputs: ['r'],
  model: ({ a, b }, { n }) => ({ r: mod(a * b, n) }),
  emit: (asm, { n }) => { asm.mul('prod'); withModulus(asm, n); asm.mod('r') },
  cases: [
    { name: 'small',    inputs: { a: 7n, b: 9n }, params: { n: 11n } },
    { name: '2048-bit', inputs: { a: (1n << 2040n) + 7n, b: (1n << 2039n) + 11n },
                        params: { n: (1n << 2048n) - 1557n } }
  ]
})
```

`model` is the specification: the operation in JavaScript, readable by someone
who knows the mathematics and nothing about Script. `emit` is the same operation
as Script. Nothing asserts that they agree except the test kit, which runs the
emitted Script on `bsv.Script.Interpreter` — the evaluator that validates blocks
— and compares.

`defineModule` refuses a module with no cases, and refuses a witnessed input with
no `hint()` to produce the honest value. An untested module is not a module.

## The calling convention

On entry, the module's declared inputs are the top of the stack in declared
order — the last declared is on top. On exit those are gone and the declared
outputs are on top, in declared order. Everything beneath is untouched.

The kit proves the last part rather than trusting it: a sentinel sits under
every module during its suite, and a module that leaks a scratch value fails,
because the next module in a composition would read the wrong depth.

## Kinds

Every value the assembler tracks has a kind: `num`, or `bytes` with a width.

This is not bookkeeping. Handing a byte string to `OP_ADD` is the single most
expensive mistake in Script arithmetic — the top bit of the last byte silently
becomes a sign, so `ff` is −127 rather than 255 — and it produces a script that
verifies against the wrong number rather than failing. The assembler refuses it
at build time:

```
asm: 'blob' is bytes, but an arithmetic opcode is about to read it as a number
```

Widths are tracked for the same reason: `OP_AND`, `OP_OR` and `OP_XOR` refuse
unequal-length operands with `SCRIPT_ERR_INVALID_OPERAND_SIZE`, and the
assembler says so before the interpreter has to.

## Parameters

`params` are compile-time. They decide what the Script *is*, not what it computes
on: a modulus, an exponent, a key length, a bit width. A parameter that has to
be a runtime value is an input instead.

One parameter convention is worth knowing. `int`'s modules take `n` as either a
BigInt — pushed as a literal — or **the name of a value already live on the
stack**, which is copied with `OP_PICK` instead. A 256-bit modulus is a 33-byte
push and a curve operation needs it ten times; pushing once and picking is worth
about 300 bytes per point operation.

## Composition

Modules call each other through `apply()`:

```js
apply(asm, int.modexp, { n, e }, ['sig'], ['r'])
```

`args` are existing stack names in the callee's input order and are consumed;
`outs` renames the callee's outputs for the caller. A value needed afterwards
must be copied first with `asm.pick`.

Composition is a rename, not a concatenation. A module reaches for its inputs by
the names it declared, so the caller's values have to be moved into the callee's
order and relabelled — and doing that in one place is what stops composition from
being the step that reintroduces stack bugs.

## Branches

`asm.beginIf()` / `elseBranch()` / `endIf()` model a conditional. At `OP_ENDIF`
the assembler requires both branches to agree on depth **and on names**:

```
asm: IF/ELSE branches disagree at depth 5: 'bits' vs 'accx'
     — relabel both to the same name before OP_ENDIF
```

Equal depth alone is not enough. If the two paths leave the same values under
different names, the model after the branch describes only one of them and every
depth computed from it afterwards is wrong on the other path. That check found a
real bug in the elliptic-curve ladder, where the accumulator ended up in
different places on the two paths.

## Refusal cases

A case marked `refuse` asserts the other half of a module: an input it must not
accept, whatever the spender supplies.

```js
{ name: 'P + P (same point)', refuse: 'dx = 0 has no inverse',
  inputs: { x1, y1, x2: x1, y2: y1, invdx: 1n } }
```

A precondition stated in a comment is a hope. `ec.add` covers points with
distinct x; the case above is what makes that a property rather than a note,
because `dx = 0` has no inverse and no witness can invent one.

## What a module requires, and what it promises

Three modules here documented a precondition and did not enforce it, and all
three were green. The fix each time was a bound; the interesting question was
*where to put it*, and for a while the answer was a hand-written `if` in
`ec.add` deciding which callers could be trusted.

A module can now state its contract instead:

```js
requires: ({ pn }) => ({ x1: range(0, pn), y1: range(0, pn) }),
ensures:  ({ pn }) => ({ x3: range(0, pn), y3: range(0, pn) })
```

Every value on the stack carries **facts** — what is known about it. At each
call, each requirement is one of three things:

- **discharged** — an upstream fact already implies it, and nothing is emitted;
- **emitted** — the framework knows a check for it and inserts one;
- **refused** — neither, and the build fails naming the obligation.

The third is the point. Some obligations cannot be checked in Script at all:
that a preimage *is* this spending transaction is established by `OP_PUSH_TX` or
not established, and no bound substitutes for it. A module that requires
`authenticated` and is handed an ordinary byte string does not compile.

### Facts are derived, not asserted

A range is only useful if it survives arithmetic, so the assembler propagates
intervals through `OP_ADD`, `OP_SUB`, `OP_MUL` and `OP_MOD`, and refuses to
guess: where a bound cannot be justified the result carries **no** fact, and a
module that needs one has to say so.

Two of those rules are load-bearing. A literal knows its own range exactly, which
is what lets the framework find a modulus already on the stack and copy it — two
bytes instead of a thirty-four-byte push, four times per point operation. And
`OP_MOD` truncates, so it bounds the *magnitude* whatever the sign: that is what
makes the two-step reduction `((v mod p) + p) mod p` derivable rather than
claimed, because the first step lands in (−p, p), the addition makes it positive,
and the second is then the non-negative case.

Where the framework genuinely cannot derive something, `asm.assert(name, facts,
why)` records it — and **requires a reason**, because an unchecked claim with no
argument for it is how the bounds went missing in the first place.
`asm.bound(name, lo, hi)` is the other half: it *emits* the check and records
the result, so the fact is established rather than claimed.

### An `ensures` is checked

A module's promise about its outputs is a claim that nothing in the build can
verify. The test kit therefore checks it against the model, on every case: a
module that promises `[0, p)` and returns `p − 3 + p` has said something false,
and the case that shows it is one that was already being run.

### What it cost

Nothing, and it found something. `ec.add` and `ec.double` come out **byte for
byte** what the hand-placed checks produced, and `ecdsa.verify` is unchanged at
59,155. `ec.mul` is 26 bytes larger — a bound on the input point that the
hand-written version did not have, and without which `px + p` was a second
encoding of the same point.

## Conjunction

`compose.all(name, parts)` builds one module out of several predicates:

```js
const rules = compose.all('vault', [
  { module: totp.verify,  params: { keyLen: 20, digits: 6, keyCommitment } },
  { module: merkleVerify, params: { depth: 2, root } }
], { cases: [{ name: 'carol, with the current code', inputs }] })
```

Its inputs are theirs, prefixed so two modules that both call something `msg` do
not collide; its `emit` runs each in turn through `apply()`; its `hint` merges
theirs. `compose.forPart('totp_', { … })` builds one part's share of a case.

The result is a module like any other, which is the point: **the test kit
attacks the composition, not just the parts.** A composition can be broken in
ways its parts are not — one module leaving a value where the next reads a
depth, two modules sharing a witness that only one of them constrains — and the
only way to find that is to put the composed thing in front of the interpreter.
`all()` refuses a part that returns a value, and refuses to build without cases,
for the same reason `defineModule` does.

## Chaining

`all()` composes predicates that each stand alone. The other shape is a chain,
where one module's output is the next one's input — `tx.locktime` produces the
transaction's locktime and `totp.verify` consumes it as the time its code must
match. That is `compose.pipe()`:

```js
compose.pipe('tx.locktime ▸ totp.verify', [
  { module: tx.locktime, as: { locktime: 'time' } },
  { module: totp.verify, params: { keyLen: 20, digits: 6, keyCommitment } }
], { cases: [...] })
```

It is a small linker. Walking the parts in order it keeps track of what has been
produced; a part's input is either taken from something an earlier part produced
or becomes an input of the composed module, and whatever is still unconsumed at
the end is the composed module's output. A chain that consumes everything is a
predicate, and `predicate()` will take it. It infers the rest too: the
composition is contextual if any part is, and a piped value has exactly one
reader — a second would need a copy, and being asked for it explicitly is better
than getting it silently.

Two things do not compose automatically, and the reason is the same in both. A
part's `hint()` works out an honest witness **off chain**; in a chain some of its
inputs do not exist off chain, because an earlier part produces them at spend
time. Such a part is skipped rather than called with an undefined, and its
witness has to come from the case — which is the honest position, since nothing
off chain knows what the transaction will say. The part's own `attacks()` have
the same problem, and there the composition falls back to near-misses of the
value itself: a weaker forgery, but a real one, so the rule that an unattackable
witness is UNPROVEN still bites.

Compositions worth a name live in `src/recipes.js`. A composition written out
twice will drift — one of these had already been hand-wired in an example and in
a deployment target, with different names for the same value.

## The escape hatch

`asm.op(name, pop, push)` emits any opcode in the release by name, with an
explicit stack effect, resolved through the complete opcode catalogue in
`src/opcodes.js`. It is honest rather than encouraging: several BSV opcodes are
inert NOPs or traps, and the catalogue says which.

## What a module costs

`npm run cost` regenerates [cost.md](cost.md) by emitting every module and
measuring it. `npm test` fails if the committed table no longer matches the code,
so the documented numbers are derived rather than transcribed.
