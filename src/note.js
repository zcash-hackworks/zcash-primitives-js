'use strict'

var bufferutils = require('./bufferutils')
var crypto = require('./crypto')
var prf = require('./prf')
var typeforce = require('typeforce')
var types = require('./types')
var zutil = require('./util')

function Note (aPk, value, rho, r) {
  typeforce(types.tuple(
    types.Buffer256bit,
    types.Zatoshi,
    types.Buffer256bit,
    types.Buffer256bit
  ), arguments)

  this.a_pk = aPk
  this.value = value
  this.rho = rho
  this.r = r
}

Note.dummy = function (aPk) {
  return new Note(
    aPk,
    0,
    zutil.random_uint256(),
    zutil.random_uint256()
  )
}

Note.fromBuffer = function (buffer, __noStrict) {
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

  var aPk = readSlice(32)
  var value = readUInt64()
  var rho = readSlice(32)
  var r = readSlice(32)
  var note = new Note(aPk, value, rho, r)

  if (__noStrict) return note
  if (offset !== buffer.length) throw new Error('Note has unexpected data')

  return note
}

Note.prototype.byteLength = function () {
  return 104
}

Note.prototype.toBuffer = function () {
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

  writeSlice(this.a_pk)
  writeUInt64(this.value)
  writeSlice(this.rho)
  writeSlice(this.r)

  return buffer
}

Note.prototype.cm = function () {
  var buffer = Buffer.alloc(1)
  buffer.writeUInt8(0xb0)
  return crypto.sha256(Buffer.concat([buffer, this.toBuffer()]))
}

Note.prototype.nullifier = function (key) {
  typeforce(types.SpendingKey, key)

  return prf.PRF_nf(key.a_sk, this.rho)
}

module.exports = Note
