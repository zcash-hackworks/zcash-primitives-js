'use strict'

var typeforce = require('typeforce')
var types = require('./types')
var zaddr = require('./address')

var Note = require('./note')
var ZCIncrementalMerkleTree = require('./incremental_merkle_tree')
var ZCIncrementalWitness = require('./incremental_witness')

function JSInput (witness, note, key) {
  typeforce(types.tuple(
    types.ZCIncrementalWitness,
    types.Note,
    types.SpendingKey
  ), arguments)

  this.witness = witness
  this.note = note
  this.key = key
}

JSInput.dummy = function () {
  var key = zaddr.SpendingKey.random()
  var note = Note.dummy(key.address().a_pk)
  var dummyTree = new ZCIncrementalMerkleTree()
  dummyTree.append(note.cm())
  return new JSInput(ZCIncrementalWitness.fromTree(dummyTree), note, key)
}

JSInput.fromBuffer = function (buffer) {
  var offset = 0
  function readZCIncrementalWitness () {
    var witness = ZCIncrementalWitness.fromBuffer(buffer.slice(offset), true)
    offset += witness.byteLength()
    return witness
  }

  function readNote () {
    var proof = Note.fromBuffer(buffer.slice(offset), true)
    offset += proof.byteLength()
    return proof
  }

  function readSpendingKey () {
    var sk = zaddr.SpendingKey.fromBuffer(buffer.slice(offset), true)
    offset += sk.byteLength()
    return sk
  }

  var witness = readZCIncrementalWitness()
  var note = readNote()
  var key = readSpendingKey()
  var input = new JSInput(witness, note, key)

  return input
}

JSInput.prototype.byteLength = function () {
  return (
    this.witness.byteLength() +
    this.note.byteLength() +
    this.key.byteLength()
  )
}

JSInput.prototype.toBuffer = function () {
  var buffer = Buffer.alloc(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  writeSlice(this.witness.toBuffer())
  writeSlice(this.note.toBuffer())
  writeSlice(this.key.toBuffer())

  return buffer
}

JSInput.prototype.nullifier = function () {
  return this.note.nullifier(this.key)
}

module.exports = JSInput
