# Bitcoin Just Verified a Post-Quantum Signature

*SLH-DSA — the NIST standard built from SPHINCS+ — checked inside a Bitcoin locking script, on mainnet, with no elliptic-curve key involved in spending.*

**Bitcoin as a Mathematical Machine, Part III**

---

Bitcoin has one signature opcode and it is ECDSA over secp256k1 — precisely the kind of signature a large enough quantum computer breaks. There is no post-quantum opcode, and adding one would be a consensus change.

So I didn't add one. There is now a coin on BSV mainnet that moved for a **post-quantum signature verified entirely in Bitcoin Script**, out of the opcodes that already exist.

```text
funding  44db75c3…7de6   block 966,903
spend    a2fd9e75…fd86   block 966,903
```

The spend carries no elliptic-curve signature for its own authorisation. What unlocks it is an **SLH-DSA-SHA2-128s** signature — FIPS 205, NIST's standardised version of SPHINCS+ — over that transaction's own sighash.

## Why this scheme, of all of them

The post-quantum signature standards split into two families, and one of them is a natural fit for Script while the other is not.

**Lattice schemes** (ML-DSA, Falcon) are compact and fast. Their arithmetic — polynomials over a small prime — would actually be *easy* in Script, easier than the 381-bit field arithmetic Part I needed. But they hash with SHAKE, which is Keccak, and Script has no Keccak opcode. It would have to be rebuilt from bitwise operations, the way this repository rebuilt SHA-256 at about 49 KB per block. Several permutations per verification makes that enormous.

**Hash-based schemes** rest on nothing but a hash function. No discrete logarithm, no lattice, nothing a quantum computer is known to break beyond Grover's square-root speedup — which you answer by doubling output sizes. SLH-DSA at its SHA2 parameter sets hashes with **SHA-256**, and Script has had `OP_SHA256` since the beginning.

A pairing had to be built out of multiplications Script was never designed for. This is built out of the exact opcode the scheme was designed around, a few thousand times.

## What a verification actually is

An SLH-DSA signature is a stack of one-time signatures glued together with Merkle trees:

```text
H_msg(R, key, root, message)   →  a FORS message, a tree index, a leaf index
FORS: 14 trees of height 12    →  a "few-time" public key
7 hypertree layers, each       →  a WOTS+ public key (35 hash chains)
                                  and a Merkle path of 9
the final root                 =  the public key in the script
```

Every step is the same operation: hash a prefix, an address and some data, then keep the first 16 bytes. Verification is about **3,928 such hashes** in the worst case.

The numbers that matter for Bitcoin:

| | |
| --- | ---: |
| public key | 32 bytes, compiled into the locking script |
| signature | 7,856 bytes, a single push |
| locking script | 75,324 bytes |
| unlocking script | 83,349 bytes |

The expensive part is the hash chains. Each WOTS+ chain runs from a digit derived from the message up to 15, and a script can't loop — so each chain is unrolled as 15 guarded steps: *if the digit is ≤ j, hash with address j*. Fourteen bytes per step, 3,675 steps. That's most of the script.

Everything else is assembly. The 64-byte prefix is a constant of the public key, pushed once and copied. The 22-byte address field is built from pieces that stay constant per layer, per chain or per tree, so what changes between one hash and the next is usually a single byte.

## A coin, not just a signature check

Checking a signature over *some message* is not the same as owning a coin. A coin locked to a bare signature check is spendable by anyone who copies the witness out of the first spend and replays it.

The binding comes from OP_PUSH_TX, a technique this series used in Part I for a different purpose. The unlocking script pushes the transaction's own sighash preimage; the script proves those bytes really are this transaction; its double SHA-256 is exactly the digest `OP_CHECKSIG` would have signed — every input, every output, every amount. Then the script demands an SLH-DSA signature *of that digest*.

The result is a coin where **no elliptic-curve key is needed to spend**. A valid SLH-DSA signature over a different transaction doesn't work. Tests confirm both.

One honest caveat, because it's the obvious objection: OP_PUSH_TX does run an `OP_CHECKSIG` internally, with a private key that everybody knows. Its security doesn't rest on that key being secret. The in-script signature is *derived* from the pushed preimage, and a signature derived from bytes that aren't this transaction's preimage doesn't verify against this transaction. That's arithmetic about a fixed public key, not an assumption that someone's key is hard to recover. A quantum computer doesn't help.

## How I know it's right

An implementation of a cryptographic standard that has only ever been tested against itself is a rumour. So:

1. **A reference written from the standard.** Verification implemented algorithm by algorithm from FIPS 205, named after the document.
2. **An independent implementation.** Every signature `@noble/post-quantum` produces must verify under my reference — and a flipped byte in each region of a signature, a different message, a different key and a different context must all be refused, by noble and my code alike.
3. **The pieces.** One hypertree layer at the bottom, one at the top, and FORS, each emitted as Script and required to produce exactly the reference's value from a real signature.
4. **The whole thing.** The Script verifier accepts real signatures and refuses a forgery in every region, plus signatures one byte short and one byte long.
5. **The coin.** A spend signed over its own sighash is accepted; a valid signature over anything else is refused.

## The lesson from Part II, applied

Part II ended with a transaction that was valid, couldn't propagate, and only reached a block because a mining pool accepted it by hand. Its sin was validation time: nodes give a peer-relayed transaction roughly **one second** to validate, and it wanted more. (That verifier has since been rebuilt as three chained transactions and mined in block 966,988, every link relaying on its own — but the lesson below is the one that produced the rebuild.)

So this time I measured before spending anything:

| | interpreter time |
| --- | ---: |
| the post-quantum spend | **~214 ms** |
| the pairing spend that relayed fine (Part I) | 3,031 ms |
| the Groth16 spend that relay refused (Part II) | 4,539 ms |

Fourteen times cheaper than the transaction that relayed fine. Native SHA-256 over 100-byte inputs beats arbitrary-precision multiplication, and it shows.

It behaved accordingly: the transactions propagated normally, a mining pool's node validated and relayed them, and three blocks after broadcast both were mined — confirmed by two independent explorers. No favours required.

## What this does and doesn't prove

**It does prove** that Bitcoin's existing opcodes can verify a NIST post-quantum signature standard, at a size and validation cost that relays and mines like anything else. No consensus change, no new opcode, no permission.

**It does not prove** any of these:

- **The deployed key is a test key.** Its seed is published in the repository, so anyone can sign for that coin. The deployment shows the network runs the verification, not that the coin was safe to hold. A real one locks to a key whose seed is secret — which changes nothing about the script.
- **The coin is post-quantum; the wallet that funded it is not.** The funding transaction is ordinary P2PKH. A revealed secp256k1 public key stays exposed.
- **One parameter set.** SLH-DSA-SHA2-128s only. The 192- and 256-bit SHA2 sets hash with SHA-512, which Script doesn't have.
- **Interpreter time is not node time.** My comparison is like-for-like, but each operator sets their own budget on their own hardware.

## Why it matters before it matters

Nobody needs this today. Quantum computers capable of breaking secp256k1 don't exist, and if they arrive there will be warning.

What matters is the shape of the answer. The usual assumption is that a blockchain's cryptography is whatever its opcodes implement, and changing it means changing consensus — a protocol negotiation with everyone. This is the opposite: **the primitives were enough**. A signature scheme published in 2024 was deployed on a script language finalised years earlier, by writing it down carefully, and the chain that mined it needed no opinion about SLH-DSA at all.

Bitcoin didn't need to understand the protocol. It only had to agree on SHA-256.

---

*Series: [Part I](#) — a complete BLS12-381 pairing on mainnet. [Part II](#) — a zero-knowledge proof of age, the limit that nearly kept it off chain, and the chain of transactions that got it there without anyone's permission.*

| | deploy | spend |
| --- | --- | --- |
| post-quantum coin | [`44db75c3…7de6`](https://whatsonchain.com/tx/44db75c3235ea1aa18e42284657f29cd700cdc8e9f6cfff687da042b124b7de6) | [`a2fd9e75…fd86`](https://whatsonchain.com/tx/a2fd9e753507835558e28dd0b4764cee45df33ed1b64a5db94ea2ace1482fd86) |
