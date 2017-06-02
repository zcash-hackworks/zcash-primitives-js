'use strict'

var bufferutils = require('./bufferutils')
var prf = require('./prf')
var typeforce = require('typeforce')
var types = require('./types')
var zaddr = require('./address')
var zconst = require('./const')

var Note = require('./note')

function JSOutput (addr, value, memo) {
  typeforce(types.tuple(
    types.PaymentAddress,
    types.Zatoshi,
    types.maybe(types.Buffer)
  ), arguments)

  if (!memo) {
    memo = Buffer.alloc(zconst.ZC_MEMO_SIZE)
    memo.fill(0)
    memo[0] = 0xF6 // 0xF6 is invalid UTF8 as per spec
  }

  this.addr = addr
  this.value = value
  this.memo = memo
}

JSOutput.dummy = function () {
  var aSk = zaddr.SpendingKey.random()
  return new JSOutput(aSk.address(), 0)
}

JSOutput.fromBuffer = function (buffer) {
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

  function readPaymentAddress () {
    var addr = zaddr.PaymentAddress.fromBuffer(buffer.slice(offset), true)
    offset += addr.byteLength()
    return addr
  }

  var addr = readPaymentAddress()
  var value = readUInt64()
  var memo = readSlice(zconst.ZC_MEMO_SIZE)
  var output = new JSOutput(addr, value, memo)

  return output
}

JSOutput.prototype.toBuffer = function () {
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

  writeSlice(this.addr.toBuffer())
  writeUInt64(this.value)
  writeSlice(this.memo)

  return buffer
}

JSOutput.prototype.note = function (phi, r, i, hSig) {
  typeforce(types.tuple(
    types.Buffer252bit,
    types.Buffer256bit,
    types.Number,
    types.Buffer256bit
  ), arguments)

  var rho = prf.PRF_rho(phi, i, hSig)
  return new Note(this.addr.a_pk, this.value, rho, r)
}

module.exports = JSOutput
