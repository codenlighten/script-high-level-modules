# A post-quantum signature in Bitcoin Script

Bitcoin Script has one signature opcode, and it is ECDSA over secp256k1 — the
kind of signature a large enough quantum computer breaks with Shor's algorithm.
There is no post-quantum opcode. This repository verifies a post-quantum
signature anyway, out of the opcodes that exist.

**The scheme is SLH-DSA** — FIPS 205, the stateless hash-based signature NIST
standardised from SPHINCS+ — at its smallest parameter set, **SLH-DSA-SHA2-128s**.
Its security rests on SHA-256 and nothing else: no discrete logarithm and no
lattice, so nothing a quantum computer is known to break beyond Grover's square
root. And Script has `OP_SHA256`. A pairing had to be built out of 381-bit
multiplications; this is built out of the opcode the scheme was designed around.

| | |
| --- | ---: |
| public key | 32 bytes, compiled into the locking script |
| signature | 7,856 bytes, one push |
| tweakable hashes, worst case | 3,928 |
| `slhdsa.verify`, a message check | 74,933 bytes of Script |
| `slhdsa.spend`, a coin | 75,324-byte locking script, 83,349-byte unlocking script |
| interpreter time, one spend | about 174 ms |

## A coin, not just a check

`slhdsa.verify(pk)` checks a signature over a message. Like every signature check
here that is not bound to a transaction, a coin locked to it alone is spendable
by whoever copies the witness out of its first spend.

`slhdsa.spend(pk)` is the coin. The unlocking script pushes the transaction's
BIP-143 preimage and a signature; OP_PUSH_TX proves the preimage belongs to this
spend under `SIGHASH_ALL|FORKID`; its double SHA-256 is exactly the digest
`OP_CHECKSIG` would have signed — every input, output and amount — and the script
requires an SLH-DSA signature of that digest. **No elliptic-curve key is needed to
spend it.**

OP_PUSH_TX does run an `OP_CHECKSIG` internally, with a private key everyone
knows. What it establishes does not depend on that key being secret: the
in-script signature is *derived* from the pushed preimage, and a signature derived
from bytes that are not this transaction's preimage does not verify against this
transaction. That is arithmetic about a fixed, public key, not an assumption that
anyone's key is hard to recover.

## How it is laid out

Every hash in SLH-DSA-SHA2-128s is `SHA-256(PK.seed ‖ 0⁴⁸ ‖ ADRSc ‖ input)`,
truncated to 16 bytes. The 64-byte prefix depends only on the public key, so it is
pushed once and picked. The 22-byte compressed address is assembled from pieces
that are constant per layer, per chain or per tree, so what changes from one hash
to the next is a byte or two.

```
H_msg(R, PK.seed, PK.root, M)     a FORS message, a tree index, a leaf index
FORS: 14 trees of height 12       a FORS public key
7 hypertree layers, each          a WOTS+ public key (35 chains)
                                  and a Merkle path of 9
the last root                     = PK.root
```

**The worst case is what the script pays for.** A WOTS+ chain runs from its digit
up to 15, and the digit comes from the message, so each chain is unrolled as 15
guarded steps — *if digit ≤ j, hash with hash address j* — at fourteen bytes a
step. That is 3,675 steps and most of the script. Tree hashes are fixed in number;
only their left-right order depends on the index, and that is one `OP_SWAP` under
an `OP_IF`.

**What the spender chooses is the signature, and nothing else.** The key, the
parameter set and the context (empty) are fixed in the script, and the
signature's length is checked before any of it is read, so no byte of the push
goes unread.

## How it is checked

1. **A reference from the standard.** `src/slhdsa.js` implements verification
   algorithm by algorithm from FIPS 205, named after it.
2. **An independent implementation.** `npm run slhdsa` requires every signature
   `@noble/post-quantum` makes to verify under the reference, and a flipped byte
   in each region of a signature, a different message, a different key and a
   different context all to be refused — by noble and the reference alike.
3. **The pieces.** One hypertree layer at the bottom and one at the top, and FORS,
   each emitted as a module and required to produce exactly the reference's
   value from a real signature.
4. **The whole.** `npm run slhdsa:script` runs the verifier on noble's signatures,
   refuses a valid signature over a different message, and refuses a forgery in
   each region of the signature and a signature one byte short and one byte long.
5. **The coin.** A spend whose signature is over its own sighash is accepted; a
   valid signature over something else is refused; forged preimages and forged
   signatures are refused.

## Validation time, measured first

A three-input Groth16 spend was valid and miners refused it with
`too-long-validation-time`. So before anything was funded this one was timed in
the same interpreter on the same machine:

| | interpreter time |
| --- | ---: |
| `slhdsa.spend` | **about 174 ms** |
| the two-input pairing spend that was mined | 2,793 ms |
| the three-input Groth16 spend miners refused | 3,924 ms |

The work is native SHA-256 over 100-byte inputs, concatenation and splitting —
not arbitrary-precision multiplication — and it shows.

## On chain

Deployed and spent on BSV mainnet, both transactions **mined in block 966,903**:

```
funding  44db75c3235ea1aa18e42284657f29cd700cdc8e9f6cfff687da042b124b7de6
spend    a2fd9e753507835558e28dd0b4764cee45df33ed1b64a5db94ea2ace1482fd86
```

Both transactions were accepted by WhatsOnChain's node, and submitted to
GorillaPool's ARC both came back `SEEN_ON_NETWORK` — a mining pool's node
validated them and relayed them, which is the step the Groth16 spend failed. Three
blocks after broadcast both were mined together, by SA100 in block 966,903, and
two independent indexers — WhatsOnChain and Bitails — report the same height.

## What this does not establish

- **The deployed key is a test key.** Its seed is published in
  `test/vectors/slhdsa-sha2-128s`, so anyone can sign for it. The deployment shows
  that the network runs the verification, not that the coin was ever safe to
  hold. A real one would lock to a key whose seed is secret.
- **One parameter set.** SLH-DSA-SHA2-128s only. The 192- and 256-bit SHA2 sets
  use SHA-512 inside, which Script does not have; the SHAKE sets need Keccak,
  which it does not have either.
- **The coin is post-quantum; the wallet that funded it is not.** The funding
  transaction is ordinary P2PKH, and a revealed secp256k1 public key stays
  exposed to anyone with a quantum computer.
- **Interpreter time is not node time.** The comparison is like for like — same
  interpreter, same machine — but a node's validation budget is its operator's
  setting, measured on its hardware.
- **Lattice signatures are not here.** ML-DSA and Falcon need SHAKE, which would
  have to be rebuilt from bitwise opcodes; their arithmetic would be the easy part.
