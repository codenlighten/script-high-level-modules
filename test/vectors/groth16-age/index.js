'use strict'

// The proof-of-age vectors, as the verifiers take them.
//
// Read in one place because four things read them — the demo, the split tool,
// the deployment and the audit of what went on chain — and a coordinate order
// transcribed four times is a coordinate order that can be transcribed wrongly
// once.

const g1 = (p) => ({ x: BigInt(p[0]), y: BigInt(p[1]) })
const g2 = (p) => ({ x: [BigInt(p[0][0]), BigInt(p[0][1])], y: [BigInt(p[1][0]), BigInt(p[1][1])] })
const asProof = (j) => {
  const A = g1(j.pi_a); const B = g2(j.pi_b); const C = g1(j.pi_c)
  return { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }
}

const vkJson = require('./vk.json')
const vk = {
  alpha: g1(vkJson.vk_alpha_1), beta: g2(vkJson.vk_beta_2),
  gamma: g2(vkJson.vk_gamma_2), delta: g2(vkJson.vk_delta_2),
  IC: vkJson.IC.map(g1)
}

module.exports = {
  vk,
  proof: asProof(require('./proof.json')),
  underage: asProof(require('./proof-underage.json')),
  // "at least 21 years old as of 2026": the year, then the age required
  statement: [2026n, 21n],
  asProof
}
