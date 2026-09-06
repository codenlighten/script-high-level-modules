# A Groth16 proof this repository did not make

`vk.json`, `proof.json` and `public.json` were produced by **snarkjs** over
BLS12-381 — an independent implementation, with its own trusted setup, its own
prover and its own field arithmetic. Nothing here touched them.

The circuit is `c = a · b` with `c` public: the smallest statement that is still
a statement. The witness is a = 3, b = 11, so the public signal is 33.

## Why it matters

Everything else this repository knows about Groth16 it worked out itself. The
fixture in `src/modules/groth16.js` is built from the group law — every scalar
chosen and one solved for — which establishes that the verifier checks the
intended relation and says nothing about whether that relation is the one a real
proving stack produces. This says the second thing.

Two facts fell out of checking it, neither of which was guaranteed:

- **snarkjs's coordinate encoding matches this one directly.** Its G2 points are
  `[[x₀,x₁],[y₀,y₁]]` in the same Fp2 basis, no conjugation and no swap. That was
  tested rather than assumed — the swapped reading puts the point off the twist.
- **The verification equation matches.** snarkjs checks
  `e(−A,B)·e(α,β)·e(L,γ)·e(C,δ) = 1`; this checks
  `e(A,B)·e(−L,γ)·e(−C,δ) = e(α,β)`. They are the same equation rearranged, and
  the proof satisfies it under this implementation's pairing.

## Reproducing them

`build.js` writes the `.r1cs` and `.wtns` by hand — circom is a Rust binary and
the formats are small enough not to need it — and `prove.js` runs a local
powers-of-tau, a phase-2 setup and the prover. Both need `snarkjs` installed:

```
npm install --no-save snarkjs
node test/vectors/groth16-bls12381/build.js
node test/vectors/groth16-bls12381/prove.js
```

The setup entropy is a fixed string. **This is a demonstration, not a
ceremony** — the toxic waste is in the file. It is fine for testing a verifier
and would not be fine for anything else.

One thing worth recording from writing `build.js`: the r1cs header holds the
field prime, and the first version wrote it through the same encoder used for
field elements — which reduces modulo that prime, so it wrote zero. snarkjs
reported "Division by zero", which is exactly right and took a moment to place.
