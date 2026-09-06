// A trusted setup and two proofs: one honest, one from an underage prover.
//
// snarkjs's prover does not check the constraints — it computes a proof-shaped
// object from whatever witness it is given. That is the point of the second
// one: an underage holder CAN produce something that looks like a proof, and it
// does not verify. The demonstration is that Bitcoin is the thing that notices.
const s = require('../../../node_modules/snarkjs')
const fs = require('fs')
const path = require('path')
const D = __dirname
const at = (f) => path.join(D, f)
;(async () => {
  const curve = await s.curves.getCurveFromName('bls12381')
  await s.powersOfTau.newAccumulator(curve, 9, at('pot_0.ptau'))
  await s.powersOfTau.contribute(at('pot_0.ptau'), at('pot_1.ptau'), 'c1', 'a demonstration, not a ceremony')
  await s.powersOfTau.preparePhase2(at('pot_1.ptau'), at('pot.ptau'))
  await s.zKey.newZKey(at('age.r1cs'), at('pot.ptau'), at('age_0.zkey'))
  await s.zKey.contribute(at('age_0.zkey'), at('age.zkey'), 'c1', 'a demonstration, not a ceremony')
  const vk = await s.zKey.exportVerificationKey(at('age.zkey'))
  fs.writeFileSync(at('vk.json'), JSON.stringify(vk, null, 1))

  for (const [wtns, tag] of [['age.wtns', ''], ['age-underage.wtns', '-underage']]) {
    const { proof, publicSignals } = await s.groth16.prove(at('age.zkey'), at(wtns))
    fs.writeFileSync(at(`proof${tag}.json`), JSON.stringify(proof, null, 1))
    fs.writeFileSync(at(`public${tag}.json`), JSON.stringify(publicSignals, null, 1))
    const ok = await s.groth16.verify(vk, publicSignals, proof)
    console.log(`  ${(tag ? 'underage' : 'honest').padEnd(9)} public ${JSON.stringify(publicSignals)}  snarkjs verifies: ${ok}`)
  }
  for (const f of ['pot_0.ptau', 'pot_1.ptau', 'age_0.zkey']) fs.unlinkSync(at(f))
  await curve.terminate()
  process.exit(0)
})().catch(e => { console.log('ERR', e.message); process.exit(1) })
