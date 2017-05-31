'use strict'

var prf = require('./prf')
var sodium = require('libsodium-wrappers-sumo')
var typeforce = require('typeforce')
var types = require('./types')

function randomUint256 () {
  return Buffer.from(sodium.randombytes_buf(32))
}

function randomUint252 () {
  var rand = Buffer.from(randomUint256())
  rand[0] &= 0x0F
  return rand
}

function generatePrivkey (aSk) {
  var sk = prf.PRF_addr_sk_enc(aSk)

  // Curve25519 clamping
  sk[0] &= 248
  sk[31] &= 127
  sk[31] |= 64

  return sk
}

function generatePubkey (skEnc) {
  typeforce(types.Buffer256bit, skEnc)

  return Buffer.from(sodium.crypto_scalarmult_base(skEnc))
}

module.exports = {
  generate_privkey: generatePrivkey,
  generate_pubkey: generatePubkey,
  random_uint252: randomUint252,
  random_uint256: randomUint256
}
