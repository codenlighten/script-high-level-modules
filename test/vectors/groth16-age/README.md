# "I am at least 21, and I am not telling you my birth year"

The circuit behind `npm run demo`. Eight constraints, and it is a claim a person
would recognise.

```
public    year = 2026, minAge = 21
private   born, and seven bits

for each bit i:   bᵢ · bᵢ = bᵢ
and:              year − born − minAge = Σ bᵢ2ⁱ
```

The bit width **is** the range proof. Σbᵢ2ⁱ lies in [0, 127], so the last
constraint says `year − born − minAge ≥ 0` — the holder is old enough. It says
nothing else: not the birth year, not the exact age.

## Two proofs

`prove.js` runs a local powers-of-tau, a phase-2 setup, and the prover twice.

| witness | born | year − born − minAge | snarkjs verifies |
| --- | ---: | ---: | --- |
| `age.wtns` | 1990 | 15 | **true** |
| `age-underage.wtns` | 2010 | −5 | **false** |

The second is the interesting one. snarkjs's prover does not check the
constraints — it computes a proof-shaped object from whatever witness it is
handed — so an underage holder **can** produce something that looks like a
proof. It does not verify, and `npm run demo` shows Bitcoin Script being the
thing that notices.

## Reproducing

```
npm install --no-save snarkjs
node test/vectors/groth16-age/build.js
node test/vectors/groth16-age/prove.js
```

The setup entropy is a fixed string. **A demonstration, not a ceremony** — the
toxic waste is in the file.
