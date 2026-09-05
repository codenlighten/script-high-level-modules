'use strict'

const https = require('https')

// WhatsOnChain, over plain HTTPS. The only network this repository touches, and
// only for four things: what the funding address holds, what a raw transaction
// is, broadcasting one, and reading a block header's time.

const HOST = 'api.whatsonchain.com'
const BASE = '/v1/bsv/main'

// A public API has a rate limit, and hitting it in the middle of a sequence of
// broadcasts leaves a deployed output unspent — which is recoverable, but only
// because the deployment was recorded before the spend was attempted. Requests
// are spaced and retried on 429 rather than relying on that.
const MIN_GAP_MS = 350
const MAX_RETRIES = 5
let lastCall = 0

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function paced (method, path, body) {
  for (let attempt = 0; ; attempt++) {
    const wait = Math.max(0, lastCall + MIN_GAP_MS - Date.now())
    if (wait) await sleep(wait)
    lastCall = Date.now()
    try {
      return await request(method, path, body)
    } catch (e) {
      const rateLimited = /\b429\b/.test(e.message)
      if (!rateLimited || attempt >= MAX_RETRIES) throw e
      const backoff = 1000 * Math.pow(2, attempt)
      await sleep(backoff)
    }
  }
}

function request (method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body)
    const req = https.request({
      host: HOST,
      path: BASE + path,
      method,
      headers: payload
        ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }
        : {}
    }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => {
        if (res.statusCode >= 400) return reject(new Error(`WhatsOnChain ${res.statusCode} on ${path}: ${data.trim().slice(0, 200)}`))
        // A txid comes back as a JSON string, quotes and all. Unwrap it, or
        // every txid this client returns carries a pair of quotes into a URL.
        const text = data.trim()
        try {
          resolve(/^[{["]/.test(text) ? JSON.parse(text) : text)
        } catch (e) { resolve(text) }
      })
    })
    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })
}

/** Confirmed and unconfirmed balance, in satoshis. */
const balance = (address) => paced('GET', `/address/${address}/balance`)
/** Spendable outputs, newest last. */
const utxos = (address) => paced('GET', `/address/${address}/unspent`)
/** The raw bytes of a transaction, hex. */
const rawTx = (txid) => paced('GET', `/tx/${txid}/hex`)
/** Broadcast. Returns the txid, or throws with the node's reason. */
const broadcast = (txhex) => paced('POST', '/tx/raw', { txhex })
/** One transaction's decoded form, for checking what actually landed. */
const tx = (txid) => paced('GET', `/tx/hash/${txid}`)
/** The chain tip, for a real-world time to lock against. */
const chainInfo = () => paced('GET', '/chain/info')

module.exports = { balance, utxos, rawTx, broadcast, tx, chainInfo, request, paced }
