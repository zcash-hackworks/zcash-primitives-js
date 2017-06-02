'use strict'

var sodium = require('libsodium-wrappers-sumo')
var typeforce = require('typeforce')
var types = require('./types')
var zutil = require('./util')

var KDF = require('./kdf')

function ZCNoteEncryption (hSig) {
  typeforce(types.Buffer256bit, hSig)

  this.nonce = 0
  this.hSig = hSig
  this.esk = zutil.random_uint256()
  this.epk = zutil.generate_pubkey(this.esk)
}

ZCNoteEncryption.prototype.encrypt = function (pkEnc, message) {
  typeforce(types.tuple(
    types.Buffer256bit,
    types.Buffer
  ), arguments)

  var dhsecret = Buffer.from(sodium.crypto_scalarmult(this.esk, pkEnc))

  // Construct the symmetric key
  var K = KDF(dhsecret, this.epk, pkEnc, this.hSig, this.nonce)

  // Increment the number of encryptions we've performed
  this.nonce++

  // The nonce is zero because we never reuse keys
  var cipherNonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
  sodium.memzero(cipherNonce)

  return Buffer.from(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      message, null, null, cipherNonce, K))
}

module.exports = ZCNoteEncryption
