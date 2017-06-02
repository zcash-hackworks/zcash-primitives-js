'use strict'

var bufferutils = require('./bufferutils')
var typeforce = require('typeforce')
var types = require('./types')
var zconst = require('./const')

var JSInput = require('./jsinput')
var Note = require('./note')

function JSProofWitness (phi, rt, hSig, inputs, notes, vpubOld, vpubNew) {
  typeforce(types.tuple(
    types.Buffer252bit,
    types.Buffer256bit,
    types.Buffer256bit,
    [types.JSInput],
    [types.Note],
    types.Zatoshi,
    types.Zatoshi
  ), arguments)

  this.phi = phi
  this.rt = rt
  this.hSig = hSig
  this.inputs = inputs
  this.notes = notes
  this.vpub_old = vpubOld
  this.vpub_new = vpubNew
}

JSProofWitness.fromBuffer = function (buffer, __noStrict) {
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

  function readJSInput () {
    var input = JSInput.fromBuffer(buffer.slice(offset), true)
    offset += input.byteLength()
    return input
  }

  function readNote () {
    var proof = Note.fromBuffer(buffer.slice(offset), true)
    offset += proof.byteLength()
    return proof
  }

  var phi = readSlice(32)
  var rt = readSlice(32)
  var hSig = readSlice(32)

  var inputs = []
  for (var i = 0; i < zconst.ZC_NUM_JS_INPUTS; ++i) {
    inputs.push(readJSInput())
  }

  var notes = []
  for (i = 0; i < zconst.ZC_NUM_JS_OUTPUTS; ++i) {
    notes.push(readNote())
  }

  var vpubOld = readUInt64()
  var vpubNew = readUInt64()
  var witness = new JSProofWitness(phi, rt, hSig, inputs, notes, vpubOld, vpubNew)

  if (__noStrict) return witness
  if (offset !== buffer.length) throw new Error('JSProofWitness has unexpected data')

  return witness
}

JSProofWitness.fromHex = function (hex) {
  return JSProofWitness.fromBuffer(Buffer.from(hex, 'hex'))
}

JSProofWitness.prototype.byteLength = function () {
  return (
    112 +
    this.inputs.reduce(function (sum, input) { return sum + input.byteLength() }, 0) +
    this.notes.reduce(function (sum, note) { return sum + note.byteLength() }, 0)
  )
}

JSProofWitness.prototype.toBuffer = function () {
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

  writeSlice(this.phi)
  writeSlice(this.rt)
  writeSlice(this.hSig)

  this.inputs.forEach(function (input) {
    writeSlice(input.toBuffer())
  })

  this.notes.forEach(function (note) {
    writeSlice(note.toBuffer())
  })

  writeUInt64(this.vpub_old)
  writeUInt64(this.vpub_new)

  return buffer
}

JSProofWitness.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

module.exports = JSProofWitness
