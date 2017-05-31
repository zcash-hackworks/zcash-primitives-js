'use strict'

var bufferutils = require('./bufferutils')
var zconst = require('./const')

var ZCProof = require('./proof')

function JSDescription () {
  this.nullifiers = []
  this.commitments = []
  this.ciphertexts = []
  this.macs = []
}

JSDescription.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt64 () {
    var i = bufferutils.readUInt64LE(buffer, offset)
    offset += 8
    return i
  }

  function readZCProof () {
    var proof = ZCProof.fromBuffer(buffer.slice(offset), true)
    offset += proof.byteLength()
    return proof
  }

  var jsdesc = new JSDescription()
  jsdesc.vpub_old = readUInt64()
  jsdesc.vpub_new = readUInt64()
  jsdesc.anchor = readSlice(32)

  for (var i = 0; i < zconst.ZC_NUM_JS_INPUTS; ++i) {
    jsdesc.nullifiers.push(readSlice(32))
  }

  for (i = 0; i < zconst.ZC_NUM_JS_OUTPUTS; ++i) {
    jsdesc.commitments.push(readSlice(32))
  }

  jsdesc.onetimePubKey = readSlice(32)
  jsdesc.randomSeed = readSlice(32)

  for (i = 0; i < zconst.ZC_NUM_JS_INPUTS; ++i) {
    jsdesc.macs.push(readSlice(32))
  }

  jsdesc.proof = readZCProof()

  for (i = 0; i < zconst.ZC_NUM_JS_OUTPUTS; ++i) {
    jsdesc.ciphertexts.push(readSlice(zconst.ZC_NOTECIPHERTEXT_SIZE))
  }

  if (__noStrict) return jsdesc
  if (offset !== buffer.length) throw new Error('JSDescription has unexpected data')

  return jsdesc
}

JSDescription.fromHex = function (hex) {
  return JSDescription.fromBuffer(Buffer.from(hex, 'hex'))
}

JSDescription.prototype.byteLength = function () {
  return (
    112 +
    zconst.ZC_NUM_JS_INPUTS * 64 +
    zconst.ZC_NUM_JS_OUTPUTS * (32 + zconst.ZC_NOTECIPHERTEXT_SIZE) +
    this.proof.byteLength()
  )
}

JSDescription.prototype.clone = function () {
  var newJSDesc = new JSDescription()
  newJSDesc.vpub_old = this.vpub_old
  newJSDesc.vpub_new = this.vpub_new
  newJSDesc.anchor = this.anchor

  newJSDesc.nullifiers = this.nullifiers.map(function (nullifier) {
    return nullifier
  })

  newJSDesc.commitments = this.commitments.map(function (commitment) {
    return commitment
  })

  newJSDesc.onetimePubKey = this.onetimePubKey
  newJSDesc.randomSeed = this.randomSeed

  newJSDesc.macs = this.macs.map(function (mac) {
    return mac
  })

  newJSDesc.proof = this.proof.clone()

  newJSDesc.ciphertexts = this.ciphertexts.map(function (ciphertext) {
    return ciphertext
  })

  return newJSDesc
}

JSDescription.prototype.toBuffer = function () {
  var buffer = Buffer.alloc(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  function writeUInt64 (i) {
    bufferutils.writeUInt64LE(buffer, i, offset)
    offset += 8
  }

  writeUInt64(this.vpub_old)
  writeUInt64(this.vpub_new)
  writeSlice(this.anchor)

  this.nullifiers.forEach(function (nullifier) {
    writeSlice(nullifier)
  })

  this.commitments.forEach(function (commitment) {
    writeSlice(commitment)
  })

  writeSlice(this.onetimePubKey)
  writeSlice(this.randomSeed)

  this.macs.forEach(function (mac) {
    writeSlice(mac)
  })

  writeSlice(this.proof.toBuffer())

  this.ciphertexts.forEach(function (ciphertext) {
    writeSlice(ciphertext)
  })

  return buffer
}

JSDescription.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

module.exports = JSDescription
