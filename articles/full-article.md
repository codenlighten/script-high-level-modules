# Bitcoin as a Mathematical Machine

## Pairings, Zero-Knowledge Proofs, and Post-Quantum Signatures Without Adding a Single Opcode

Bitcoin Script is usually described as intentionally limited. It checks signatures. It checks hashes. It handles timelocks, multisig conditions, and comparatively simple rules governing when a coin may move. That description is accurate, but incomplete.

Over a series of mainnet experiments, I wanted to ask a different question:

**What mathematics can Bitcoin enforce using only the primitives it already has?**

The answer turned out to be much broader than I expected. Bitcoin Script has now been used to verify:

* a complete **BLS12-381 pairing**,
* a **Groth16 zero-knowledge proof** asserting that someone is at least 21 years old without revealing their birth year,
* and an **SLH-DSA post-quantum signature**, using the NIST-standardized hash-based signature system derived from SPHINCS+.

None of those exist as Bitcoin opcodes. No pairing opcode was added. No zero-knowledge-proof opcode was added. No post-quantum signature opcode was added. No consensus rule was changed. The network did not need to understand Groth16, BLS12-381, or SLH-DSA as protocols.

It only needed to execute the primitive operations it already understood. That changes the way I think about Bitcoin Script. It is less interesting as a catalog of built-in features than as a **mathematical verification machine**.

---

## The Important Distinction: Computing vs. Verifying

The breakthrough came from a simple observation. Bitcoin does not necessarily have to perform every expensive computation itself. Suppose we need a modular inverse:

```text
z = a⁻¹ mod p
```

Computing that inverse inside Script would require something like an extended Euclidean algorithm or a large exponentiation. But verifying a proposed inverse requires only:

```text
a · z ≡ 1 mod p
```

So let the spender calculate `z`. Push it into the unlocking script. Then let Bitcoin verify the relationship. That changes the cost model completely.

```text
Spender
   │
   │ performs expensive computation
   ▼
Witness values
   │
   ▼
Bitcoin Script
   │
   ├── checks arithmetic identities
   ├── checks bounds
   ├── checks curve equations
   └── checks relationships
   ▼
TRUE / FALSE
```

The script does not trust the witness. It verifies it. That distinction underlies everything that follows. A locking script becomes less like a program that computes an answer and more like a program that asks:

**Can the spender demonstrate that these values satisfy the mathematical relationships I require?**

This approach is powerful, but it has a strict soundness requirement. A witness cannot merely be mathematically related to the right value. It often has to be canonical. For example, if:

```text
a · z ≡ 1 mod p
```

then both `z` and `z + p` satisfy that congruence. If a later part of the program compares values for literal equality rather than modular equality, allowing both representations becomes a bug. So every spender-controlled value has to be examined with a simple question:

> What can the spender choose, and is every choice pinned to exactly one acceptable value?
That question found several bugs in the pairing implementation, including bugs in code whose tests already passed. And once this verification model was adopted, something even stranger happened. Algorithms that are efficient on CPUs were no longer necessarily efficient in Bitcoin Script.

---

# Experiment One: Build a Pairing from Bitcoin Arithmetic

BLS12-381 is the elliptic curve used behind several important modern cryptographic constructions. It appears in:

* BLS signatures,
* threshold-signature systems,
* KZG polynomial commitments,
* Groth16 proofs,
* and other pairing-based cryptography.

At the bottom of all of those constructions is a pairing. Bitcoin Script does not have one. It does not have native extension fields. It does not have a field-inversion opcode. It certainly does not have a BLS12-381 implementation.

But after BSV's Genesis upgrade, Script supports arbitrary-precision integer arithmetic. `OP_MUL` and `OP_MOD` can operate on integers hundreds or thousands of bits wide. That is enough of a foothold. From integers, you can construct a finite field. From a finite field, extension fields.

From those fields, elliptic-curve operations. From those operations, a Miller loop. And from the Miller loop plus a final exponentiation:

```text
e(P, Q)
```

a BLS12-381 pairing. The complete pairing was executed on BSV mainnet across two inputs of one transaction. One input ran the 63-round Miller loop. The second performed the final exponentiation. The shared transaction output tied the two stages together.

The result was an 830,928-byte transaction mined on mainnet. The important result was not merely that the pairing worked. It was what building it revealed about computation under a verifier-oriented cost model.

---

## The Textbook Cost Model Reversed

Traditional elliptic-curve implementations avoid inversions whenever possible. On ordinary processors, inversion is expensive, so implementations commonly use projective coordinates: replace one inversion with several multiplications and postpone inversion until later.

That is usually the right engineering decision. It was the wrong decision here. Under witness-assisted verification, the spender can calculate the inverse off chain. Bitcoin only needs to check:

```text
a · z ≡ 1 mod p
```

So an inversion becomes roughly the cost of verifying a few multiplications and bounds. That makes inversion relatively cheap. Suddenly **affine coordinates outperform projective coordinates**. The same reversal appeared during the final exponentiation.

A compressed cyclotomic squaring technique normally pays off only after enough repeated squarings to compensate for the inversion needed to recover the full representation. But when inversions are cheap to verify, that crossover point changes.

Using that strategy reduced the final exponentiation from approximately 592 KB to approximately 473 KB. That difference was decisive because the default relay-policy limit for an individual script is 500 KB. The broader lesson was clear:

> **The best algorithm depends on the verifier's cost model.**
An optimization that is obvious on a CPU may be wrong for a system where expensive operations can be performed by the spender and cheaply verified by the chain.

---

# Computation Does Not Have to Fit in One Script

The complete pairing would occupy approximately 817 KB as one locking script. That exceeds default relay policy. But a Bitcoin transaction can have several inputs. Each input runs its own locking script. And every input sees the same transaction outputs. That creates another primitive:

**computation across scripts.**

The pairing was divided like this:

```text
Input 0:
Miller(P,Q)
     │
     ▼
     f
     │
     └────────────┐
                  ▼
            shared output

Input 1:
FinalExp(f)
     │
     ▼
     e(P,Q)
```

The Miller-loop input required the transaction output to contain its computed value `f`. The final-exponentiation input required the transaction to contain the same `f` that it was using as its input. There is only one shared output. So the two programs are forced to agree.

The transaction becomes a composition mechanism. In abstract form:

```text
large computation

F(x)
 │
 ├── Stage 1 → intermediate state s₁
 │
 ├── Stage 2 → intermediate state s₂
 │
 └── Stage n → result
```

Each individual verifier may fit within policy even when the whole computation does not. That idea turned out to be more important than the pairing itself. Because once Bitcoin can verify a pairing, the next obvious question is:

**What can we build with it?**

---

# Experiment Two: A Coin That Moves for a Zero-Knowledge Proof

The second experiment moved from mathematical machinery to an actual spending condition. The claim was simple:

> **The holder is at least 21 years old as of 2026.**
The public information was:

```text
current year = 2026
minimum age  = 21
```

The private information was:

```text
birth year
```

A Groth16 proof was generated using `snarkjs`. The birth year did not appear on chain. It was not included in the proof. Bitcoin only received enough information to verify that the private witness satisfied the circuit. The outcomes were:

```text
valid proof of "age ≥ 21"        → coin moves

proof generated from underage
witness                           → coin does not move

valid proof of a different
statement                          → coin does not move
```

That last case is particularly important. A cryptographic proof can be completely valid and still be irrelevant to the spending condition. So the statement being proven was compiled into the locking script itself. The spender could choose the proof.

The spender could not choose the claim that the coin recognized. In that sense:

> **The statement isn't attached to the proof. The statement is the coin.**
---

# Groth16 Becomes a Pairing Equation

A Groth16 proof contains three elliptic-curve elements:

```text
A
B
C
```

Verification reduces to a pairing equation of the form:

```text
e(A,B) · e(−L,γ) · e(−C,δ) = e(α,β)
```

The important security distinction is what the spender may choose. `A`, `B`, and `C` come from the proof. Values such as `γ`, `δ`, `α`, and `β` belong to the verifying key and must be fixed by the verifier.

If a spender were allowed to supply something like `γ`, the script might still verify an equation, but it would no longer necessarily verify the intended proof system. This is the same witness-soundness issue appearing at a higher level:

> A verifier is secure only when every spender-controlled value is constrained exactly where the protocol assumes it is constrained.
The complete Groth16 verifier was approximately 1.25 MB of Script, so it had to be divided into stages. The Miller loop itself had to be cut midway because three pairings sharing one loop were already too large before the final exponentiation began. This produced a three-input transaction.

Mathematically, it worked. Then the network taught us something different.

---

# Consensus Validity Is Not the Same as Network Usability

The Groth16 transaction was valid. It verified locally. A node accepted it. Then it sat there. For 128 blocks. A second explorer never saw it. When submitted to a mining pool, the rejection was:

```text
REJECTED: too-long-validation-time
```

The issue was not script correctness. It was not transaction size alone. It was not consensus. It was **validation time**. Nodes cannot spend unlimited CPU time checking arbitrary transactions arriving from strangers. That would create a trivial denial-of-service attack.

So an operator may impose a time budget on transactions arriving through peer-to-peer relay. The three-input Groth16 transaction exceeded that operational budget. Eventually the pool submitted it directly to its own node and mined it. The transaction was valid. The block containing it was valid.

But the transaction could not propagate normally. That revealed three different classes of constraint:

1. **Script-size limits** constrain individual programs.
2. **Transaction structure and unlocking-script size** constrain how those programs can carry state.
3. **Validation-time policy** constrains how much work a node will perform on a transaction received from strangers.

These are not equivalent. A transaction can be:

```text
consensus valid
       │
       ├── but rejected by relay policy
       │
       └── still mineable
```

That distinction became an architectural requirement. If the goal is permissionless propagation, the computation cannot merely fit inside consensus rules. It must fit inside the practical work budget of the network. So the architecture changed again.

---

# Computation Across Transactions

Instead of packing every stage into separate inputs of one giant transaction, the computation was spread across several transactions. The challenge was preserving state. The solution became what I think of as a **carrier coin**. The carrier contains the previous and current computation states.

A stage consumes the current state and produces the next. Conceptually:

```text
Carrier:
previous_state
current_state

Stage:
F(current_state)
        │
        ▼
next_state
```

The two scripts independently construct the same successor output. One side effectively says:

```text
successor.previous = my.current
```

The other says:

```text
successor.current = F(previous)
```

Because both scripts commit to the same transaction output, their values must agree. That transforms a transaction chain into a verified state machine. There is a cost, and it is worth stating plainly rather than discovering later. A single transaction binds its inputs atomically. A chain does not.

Each link is enforced by the two scripts inside it, but no script can tell whether the carrier beside it came from this execution or from some other run of the same computation. An outpoint does not name a script, and the carrier's transaction did not exist when the stage coins were written.

So the early links of a losing run are perfectly valid transactions, and they will confirm. What nobody reaches is the final state, because the last stage produces it only for a value that actually satisfies the equation.

The claim therefore becomes a claim about a chain rather than about a transaction, and somebody has to walk that chain to check it. That is the price of being able to send it at all.

The redesigned pairing ran as separate transactions. Then the Groth16 verifier was rebuilt the same way.

All three stages of the chained verifier were mined in block 966,988. Every transaction relayed normally. The original single-transaction verifier needed direct pool submission. The redesigned verifier did not. That difference matters. The first construction established mathematical validity.

The second established a network architecture.

---

# A New Kind of Stack Frame

The carrier mechanism suggested something broader. When intermediate values are committed into transaction outputs and authenticated by neighboring stages, the chain itself begins acting like persistent computation memory.

A serialized collection of values can be committed by hash, carried forward by a UTXO, split back into live stack elements, transformed, and committed again. Conceptually:

```text
authenticated state
       │
       ▼
deserialize
       │
       ▼
live stack values
       │
       ▼
computation
       │
       ▼
serialize
       │
       ▼
authenticated successor state
```

This is not a conventional virtual machine. There is no global mutable memory. There is no `LOAD` opcode pulling arbitrary data from storage. Instead, ownership of a UTXO carries authenticated computational state. The next transaction proves the transition.

The chain becomes a sequence of state commitments. That is a much more interesting model than simply asking how many opcodes Script contains.

---

# Experiment Three: A Post-Quantum Bitcoin Coin

The next experiment went in a different direction. Pairings and Groth16 show that Bitcoin can reconstruct sophisticated mathematics from general arithmetic. But what happens when the cryptographic protocol itself did not exist when Bitcoin Script was designed?

Bitcoin currently has a signature opcode based on ECDSA over secp256k1. A sufficiently powerful cryptographically relevant quantum computer could break that discrete-logarithm security assumption. Bitcoin Script has no built-in post-quantum signature opcode.

Adding one at the protocol level would require a consensus change. So instead of adding one, I implemented one. The scheme was:

**SLH-DSA-SHA2-128s**

SLH-DSA is the NIST-standardized descendant of SPHINCS+, specified in FIPS 205. Unlike lattice-based post-quantum schemes such as ML-DSA, the SHA2 parameter sets of SLH-DSA rely heavily on SHA-256. And Bitcoin already has:

```text
OP_SHA256
```

That makes the scheme unusually compatible with Script.

---

# Why a Hash-Based Signature Fits Bitcoin

SLH-DSA is built from layers of hash-based constructions. At a high level, verification involves:

```text
H_msg
   │
   ▼
FORS trees
   │
   ▼
WOTS+ chains
   │
   ▼
Merkle authentication paths
   │
   ▼
hypertree root
   │
   ▼
public key
```

For the tested parameter set, verification requires thousands of hashes. That sounds large. But these are native SHA-256 operations. The resulting locking script was approximately 75 KB. The unlocking script was approximately 83 KB.

Interpreter validation was around 214 milliseconds in the reported measurements—dramatically cheaper than the arbitrary-precision field arithmetic used in the pairing and Groth16 experiments. The transaction propagated normally and was mined without special intervention.

There is an important difference between verifying a signature and creating a spendable post-quantum coin, though. A script that verifies a signature over an arbitrary message is not sufficient. Someone could copy the witness from a previous spend.

The signature has to authorize **this transaction**.

---

# Binding the Signature to the Coin Spend

The construction used `OP_PUSH_TX`. The unlocking script provides the transaction's sighash preimage. The script verifies that the provided bytes correspond to the spending transaction. The digest of that preimage is then used as the message for SLH-DSA verification.

So the authorization condition becomes:

```text
This transaction
      │
      ▼
sighash preimage
      │
      ▼
SHA-256 / transaction digest
      │
      ▼
SLH-DSA verification
      │
      ▼
authorized spend
```

A valid SLH-DSA signature over some other transaction is useless. The coin moves only when the post-quantum signature authorizes the transaction actually spending it. The result is a coin whose spending authorization does not depend on a secret secp256k1 signing key.

There is a subtle implementation caveat: `OP_PUSH_TX` internally uses an `OP_CHECKSIG` operation involving a publicly known private key. Its security is not based on that key remaining secret.

The important property is that Script verifies the relationship between the supplied transaction preimage and the actual spending transaction. The SLH-DSA signature is then checked against the resulting digest.

Recovering the deliberately public helper key does not allow the attacker to produce an SLH-DSA signature for a transaction they cannot sign under the post-quantum key.

---

# Bitcoin Didn't Know SLH-DSA Existed

This is the experiment that makes the broader point clearest. Bitcoin did not contain an SLH-DSA opcode. It did not contain a SPHINCS+ opcode. Its consensus rules did not have to be updated when NIST standardized the scheme.

The network didn't need to understand hypertrees, FORS, WOTS+, or post-quantum cryptography. It only had to evaluate the constituent operations. The protocol was expressed as relationships between primitives Bitcoin already knew how to verify.

That leads to what I think is the central observation from this entire series:

> **A blockchain's cryptographic capabilities are not necessarily limited to the cryptographic algorithms named by its opcodes.**
Sometimes the primitives are enough. The network does not have to understand the protocol as a named abstraction. It only has to agree on the operations from which the protocol can be constructed. Or, in this particular case:

> **Bitcoin didn't need to understand the protocol. It only had to agree on SHA-256.**
---

# What These Experiments Actually Establish

It is important not to overstate the results. The pairing experiment does **not** mean arbitrary cryptography is cheap. The Groth16 experiment does **not** mean every SNARK system can be dropped into Bitcoin unchanged. The post-quantum experiment does **not** mean Bitcoin as a whole is quantum-safe.

What they establish is narrower and, I think, more interesting. They establish that:

### 1. Missing opcodes do not automatically imply impossible computations.

A pairing opcode is convenient. It is not mathematically necessary if the primitive arithmetic exists.

### 2. Off-chain computation plus on-chain verification radically changes the cost model.

The spender can perform expensive operations and provide witnesses. Bitcoin verifies identities rather than necessarily recomputing the full operation.

### 3. Transactions can compose computations.

Separate locking scripts can enforce agreement through shared transaction commitments.

### 4. Transaction chains can compose computations too.

Authenticated intermediate state can be carried from one transaction to the next.

### 5. Network policy is part of real protocol engineering.

A construction that is consensus-valid but cannot propagate is materially different from one that relays normally.

### 6. New cryptographic systems can sometimes be expressed using old primitives.

SLH-DSA was standardized long after Bitcoin Script's design, yet one of its standardized parameter sets maps naturally onto SHA-256.

---

# The More Interesting Project Is Becoming the Compiler

A complete pairing involved more than half a million opcodes — 538,743 of them. Nobody should write that by hand. And eventually, nobody should have to. The natural architecture is something like:

```text
Mathematical predicate
        │
        ▼
Typed intermediate representation
        │
        ▼
Witness planner
        │
        ▼
Proof obligations
        │
        ▼
Equivalent lowerings
        │
        ▼
Cost-model selection
        │
        ▼
Stack scheduler
        │
        ▼
Transaction partitioner
        │
        ▼
Bitcoin Script
```

Parts of this direction already exist in the implementation. Modules can carry explicit requirements and guarantees. If one module has already established that a number lies inside a required range, later modules should not pay to prove the same thing again.

Alternative implementations can be measured. But selecting the cheaper implementation is not enough. First, the compiler has to establish that both implementations mean the same thing on the relevant domain. Only then should it choose the cheaper one. That ordering is fundamental.

A program optimizer that benchmarks two different computations and chooses the faster one is not an optimizer. It is a bug generator. The goal therefore isn't merely:

```text
make Script smaller
```

The goal is:

```text
preserve the mathematical predicate
while minimizing the cost of proving it
under Bitcoin's actual execution model
```

That includes:

* bytes,
* opcodes,
* stack movement,
* interpreter work,
* transaction structure,
* witness size,
* relay policy,
* and state carried between transactions.

At that point, Bitcoin Script stops being the language developers directly program. It becomes a **compiler target**.

---

# From Programs to Predicates

Most programming languages are imperative. They tell a computer what to do:

```text
load this
multiply that
call this
loop here
store result
```

But the model emerging from these experiments is different. A developer should ideally describe what must be true:

```text
this proof verifies

this signature authorizes this transaction

this point belongs to this subgroup

this state transition follows this function

this output is the result of this computation
```

Then a compiler works backward. It decides:

* which values should be computed off chain,
* which relationships Bitcoin must verify,
* which range checks are necessary,
* which mathematical representation is cheapest,
* how the stack should be scheduled,
* where the computation should be split,
* and whether those stages belong in one transaction or several.

The developer specifies the **predicate**. The compiler constructs the **proof strategy**. That is a significantly different way to think about smart contracts.

---

# Bitcoin as a Verification Architecture

After these experiments, I find the usual phrase "Bitcoin Script is limited" increasingly unhelpful. Of course it is limited. Every computational environment is limited by something. The more useful questions are:

```text
What primitives exist?

What relationships can they verify?

What work can move into witnesses?

What state can be authenticated?

How cheaply can equivalent algorithms be represented?

Where can computation be partitioned?

What does relay policy tolerate?

What can be compiled from all of the above?
```

Seen that way, Script's apparent simplicity becomes less important. Primitive operations compose. Witnesses move expensive work outside the verifier. Transactions connect independent verification stages. UTXOs carry authenticated state. Hashes commit one stage to another.

And a compiler can search the design space for a representation humans would never reasonably write by hand. That does not make every computation practical. It does mean the boundary between "Bitcoin supports this" and "Bitcoin doesn't support this" is much less obvious than an opcode list suggests.

---

# Three Experiments, One Direction

The progression is useful to look at as a whole. The first experiment asked:

> **Can Bitcoin evaluate advanced mathematics?**
A BLS12-381 pairing demonstrated that it could. The second asked:

> **Can that mathematics enforce a useful privacy-preserving condition?**
A Groth16 proof allowed a coin to enforce "at least 21" without learning the holder's birth year. The third asked:

> **Can Bitcoin enforce cryptography that was standardized years after its scripting system was designed?**
SLH-DSA showed that, when the required primitives already exist, the answer can again be yes. Together they suggest a different model:

```text
Desired spending condition
          │
          ▼
Mathematical predicate
          │
          ▼
Off-chain computation
          │
          ▼
Witnesses
          │
          ▼
Verified relationships
          │
          ▼
Cost-aware decomposition
          │
          ▼
Authenticated state
          │
          ▼
Transaction graph
          │
          ▼
Bitcoin Script
          │
          ▼
TRUE / FALSE
```

The important abstraction is no longer the opcode. It is the predicate.

---

# The Point

Bitcoin Script's simplicity is not the same thing as mathematical simplicity. A missing opcode does not necessarily mean a missing capability. Sometimes it means the capability has to be constructed.

Sometimes expensive computation belongs outside the chain while its correctness is checked inside it. Sometimes one script is too small but several scripts can agree through a transaction.

Sometimes one transaction asks too much of the network but a chain of transactions can carry the same authenticated computation. And sometimes a cryptographic standard invented years after Bitcoin was designed can be expressed entirely through primitives Bitcoin already had.

The experiments here are not evidence that every desirable cryptographic system should be rebuilt in Bitcoin Script. They are evidence of something more fundamental:

**Bitcoin can act as a general mathematical verifier to a degree that is easy to underestimate when we think only in terms of its named opcodes.**

The pairing was the first clue. The zero-knowledge proof made it useful. The post-quantum signature made the broader point difficult to ignore. The next step is not to hand-write more enormous scripts. It is to build the machinery that makes doing so unnecessary.

Developers should be able to describe the statement they want Bitcoin to enforce. A compiler should determine how to prove it. And Bitcoin should only have to answer the question it has always answered:

```text
TRUE
```

---

## On chain

Every result above is a transaction anyone can fetch and check. The scripts are rebuilt from source and compared byte for byte against what the chain holds.

| | deploy | spend |
| --- | --- | --- |
| Miller loop, 63 rounds | [`10c52d6d…4d20`](https://whatsonchain.com/tx/10c52d6dfb2831ecff79fe40e827695187d1e8453af845e5ab31f17a84684d20) | [`f90cc1e3…0d40`](https://whatsonchain.com/tx/f90cc1e3d60eecfb4f1a849dc4798db601b3085ca07a4155c4ae2d0890170d40) |
| Final exponentiation | [`038dbe94…b5f4`](https://whatsonchain.com/tx/038dbe94167beee28ad273f3e2d66dcda6098a5cbe0c1613109621352088b5f4) | [`1b1d0f04…3c90`](https://whatsonchain.com/tx/1b1d0f042b863cdc9ce33cdac0893db77da9c05a3eac91bb462364073fae3c90) |
| Complete pairing, two inputs of one transaction | [`92bb3f0e…667c`](https://whatsonchain.com/tx/92bb3f0e790ace19f1afec51141f87a3d6a911f10e82e765dba5368a6765667c) | [`fd0f553e…b9e2`](https://whatsonchain.com/tx/fd0f553ee9a96b2cb48a4a9712824580910cd6056fc42f93f49eae83da2fb9e2) |
| Groth16 proof of age, three inputs of one transaction | [`025f20f1…c5f0`](https://whatsonchain.com/tx/025f20f1d4156aa354afef37b1ec67e5c461f11375bc739902845a3b985dc5f0) | [`cad6d2cc…4bb6`](https://whatsonchain.com/tx/cad6d2cca44fffb2f445009f392b668382d79d120b1c14db0fd4a8d192204bb6) |
| The same verifier, three chained transactions | [`1c0b9af1…c9ea`](https://whatsonchain.com/tx/1c0b9af1f1b39d40c3d296060a86e8847303cd5709dbd78f917ab65a2f35c9ea) | [`3b68669c…9ee7`](https://whatsonchain.com/tx/3b68669ce3bdf2e1a7dd4a12e449c0b51a4d8a7f137b5eca9c3b64726c859ee7) |
| Post-quantum coin, SLH-DSA | [`44db75c3…7de6`](https://whatsonchain.com/tx/44db75c3235ea1aa18e42284657f29cd700cdc8e9f6cfff687da042b124b7de6) | [`a2fd9e75…fd86`](https://whatsonchain.com/tx/a2fd9e753507835558e28dd0b4764cee45df33ed1b64a5db94ea2ace1482fd86) |

The three-input Groth16 transaction is the one that could not propagate: it was mined only after a pool submitted it to their own node. The chained version beneath it relayed normally, and all four of its transactions were mined in block 966,988.
