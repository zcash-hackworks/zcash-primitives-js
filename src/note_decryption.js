'use strict'

var sodium = require('libsodium-wrappers-sumo')
var typeforce = require('typeforce')
var types = require('./types')
var zutil = require('./util')

var KDF = require('./kdf')

function ZCNoteDecryption (skEnc) {
  typeforce(types.Buffer256bit, skEnc)

  this.sk_enc = skEnc
  this.pk_enc = zutil.generate_pubkey(skEnc)
}

ZCNoteDecryption.prototype.decrypt = function (ciphertext, epk, hSig, nonce) {
  typeforce(types.tuple(
    types.Buffer,
    types.Buffer256bit,
    types.Buffer256bit,
    types.Number
  ), arguments)

  var dhsecret = Buffer.from(sodium.crypto_scalarmult(this.sk_enc, epk))

  // Construct the symmetric key
  var K = KDF(dhsecret, epk, this.pk_enc, hSig, nonce)

  // The nonce is zero because we never reuse keys
  var cipherNonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.memzero(cipherNonce)

  return Buffer.from(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      null, ciphertext, null, cipherNonce, K))
}

module.exports = ZCNoteDecryption
