'use strict'

const https = require('https')

// WhatsOnChain, over plain HTTPS. The only network this repository touches, and
// only for four things: what the funding address holds, what a raw transaction
// is, broadcasting one, and reading a block header's time.

const HOST = 'api.whatsonchain.com'
const BASE = '/v1/bsv/main'

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
        const text = data.trim()
        try { resolve(text.startsWith('{') || text.startsWith('[') ? JSON.parse(text) : text) } catch (e) { resolve(text) }
      })
    })
    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })
}

/** Confirmed and unconfirmed balance, in satoshis. */
const balance = (address) => request('GET', `/address/${address}/balance`)
/** Spendable outputs, newest last. */
const utxos = (address) => request('GET', `/address/${address}/unspent`)
/** The raw bytes of a transaction, hex. */
const rawTx = (txid) => request('GET', `/tx/${txid}/hex`)
/** Broadcast. Returns the txid, or throws with the node's reason. */
const broadcast = (txhex) => request('POST', '/tx/raw', { txhex })
/** One transaction's decoded form, for checking what actually landed. */
const tx = (txid) => request('GET', `/tx/hash/${txid}`)
/** The chain tip, for a real-world time to lock against. */
const chainInfo = () => request('GET', '/chain/info')

module.exports = { balance, utxos, rawTx, broadcast, tx, chainInfo, request }
