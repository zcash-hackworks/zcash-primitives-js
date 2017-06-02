'use strict'

var bufferutils = require('./bufferutils')
var zconst = require('./const')

var Note = require('./note')

function NotePlaintext (note, memo) {
  if (note) {
    this.value = note.value
    this.rho = note.rho
    this.r = note.r
    this.memo = memo
  }
}

NotePlaintext.fromBuffer = function (buffer, __noStrict) {
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

  function readUInt8 () {
    var i = buffer.readUInt8(offset)
    offset += 1
    return i
  }

  if (readUInt8() !== 0x00) throw new Error('lead byte of NotePlaintext is not recognized')

  var pt = new NotePlaintext()
  pt.value = readUInt64()
  pt.rho = readSlice(32)
  pt.r = readSlice(32)
  pt.memo = readSlice(zconst.ZC_MEMO_SIZE)

  if (__noStrict && offset <= buffer.length) return pt
  if (offset !== buffer.length) throw new Error('NotePlaintext has unexpected data')

  return pt
}

NotePlaintext.prototype.byteLength = function () {
  return 73 + zconst.ZC_MEMO_SIZE
}

NotePlaintext.prototype.toBuffer = function () {
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

  function writeUInt8 (i) {
    buffer.writeUInt8(i, offset)
    offset += 1
  }

  writeUInt8(0x00)
  writeUInt64(this.value)
  writeSlice(this.rho)
  writeSlice(this.r)
  writeSlice(this.memo)

  return buffer
}

NotePlaintext.prototype.note = function (aPk) {
  return new Note(aPk, this.value, this.rho, this.r)
}

module.exports = NotePlaintext
