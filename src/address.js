'use strict'

var bs58check = require('bs58check')
var prf = require('./prf')
var typeforce = require('typeforce')
var types = require('./types')
var util = require('./util')

function fromBase58Check (address) {
  var payload = bs58check.decode(address)
  var version = payload.readUInt16BE(0)
  var data = payload.slice(2)

  return { data: data, version: version }
}

function toBase58Check (data, version) {
  typeforce(types.tuple(types.Buffer, types.UInt16), arguments)

  var payload = Buffer.alloc(data.length + 2)
  payload.writeUInt16BE(version, 0)
  data.copy(payload, 2)

  return bs58check.encode(payload)
}

function PaymentAddress (aPk, pkEnc) {
  typeforce(types.tuple(types.Buffer256bit, types.Buffer256bit), arguments)
  this.a_pk = aPk
  this.pk_enc = pkEnc
}

PaymentAddress.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  var aPk = readSlice(32)
  var pkEnc = readSlice(32)
  var addr = new PaymentAddress(aPk, pkEnc)

  if (__noStrict) return addr
  if (offset !== buffer.length) throw new Error('PaymentAddress has unexpected data')

  return addr
}

PaymentAddress.prototype.byteLength = function () {
  return 64
}

PaymentAddress.prototype.toBuffer = function () {
  var buffer = Buffer.alloc(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  writeSlice(this.a_pk)
  writeSlice(this.pk_enc)

  return buffer
}

PaymentAddress.prototype.toZAddress = function (version) {
  return toBase58Check(this.toBuffer(), version)
}

function SpendingKey (aSk) {
  typeforce(types.Buffer252bit, aSk)
  this.a_sk = aSk
}

SpendingKey.random = function () {
  return new SpendingKey(util.random_uint252())
}

SpendingKey.fromBuffer = function (buffer, __noStrict) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  var aSk = readSlice(32)
  var sk = new SpendingKey(aSk)

  if (__noStrict) return sk
  if (offset !== buffer.length) throw new Error('SpendingKey has unexpected data')

  return sk
}

SpendingKey.prototype.byteLength = function () {
  return 32
}

SpendingKey.prototype.toBuffer = function () {
  var buffer = Buffer.alloc(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  writeSlice(this.a_sk)

  return buffer
}

SpendingKey.prototype.toZKey = function (version) {
  return toBase58Check(this.toBuffer(), version)
}

SpendingKey.prototype.address = function () {
  return new PaymentAddress(
    prf.PRF_addr_a_pk(this.a_sk),
    util.generate_pubkey(util.generate_privkey(this.a_sk))
  )
}

function fromZAddress (address, versionMap) {
  var decode = fromBase58Check(address)
  if (decode.version in versionMap) return versionMap[decode.version].fromBuffer(decode.data)
  throw new Error(address + ' has no matching z-address')
}

function fromZKey (key, versionMap) {
  var decode = fromBase58Check(key)
  if (decode.version in versionMap) return versionMap[decode.version].fromBuffer(decode.data)
  throw new Error(key + ' has no matching z-key')
}

module.exports = {
  PaymentAddress: PaymentAddress,
  SpendingKey: SpendingKey,
  fromZAddress: fromZAddress,
  fromZKey: fromZKey
}
