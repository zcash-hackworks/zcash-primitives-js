'use strict'

var varuint = require('varuint-bitcoin')

var ZCIncrementalMerkleTree = require('./incremental_merkle_tree')

function ZCIncrementalWitness () {
  this.tree = new ZCIncrementalMerkleTree()
  this.filled = []
  this.cursor = null
  this.cursor_depth = 0
}

ZCIncrementalWitness.fromTree = function (tree) {
  var witness = new ZCIncrementalWitness()
  witness.tree = tree.clone()
  return witness
}

ZCIncrementalWitness.fromBuffer = function (buffer, __noStrict, __depth) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readUInt8 () {
    var i = buffer.readUInt8(offset)
    offset += 1
    return i
  }

  function readVarInt () {
    var vi = varuint.decode(buffer, offset)
    offset += varuint.decode.bytes
    return vi
  }

  function readOptional (func) {
    var i = readUInt8()
    if (i === 1) {
      return func()
    } else if (i === 0) {
      return null
    } else {
      throw new Error('Invalid optional')
    }
  }

  function readZCIncrementalMerkleTree () {
    var tree = ZCIncrementalMerkleTree.fromBuffer(buffer.slice(offset), true, __depth)
    offset += tree.byteLength()
    return tree
  }

  var witness = new ZCIncrementalWitness()
  witness.tree = readZCIncrementalMerkleTree()

  var filledLen = readVarInt()
  for (var i = 0; i < filledLen; ++i) {
    witness.filled.push(readSlice(32))
  }

  witness.cursor = readOptional(readZCIncrementalMerkleTree)

  if (__noStrict && offset <= buffer.length) return witness
  if (offset !== buffer.length) throw new Error('ZCIncrementalWitness has unexpected data')

  return witness
}

ZCIncrementalWitness.prototype.byteLength = function () {
  return (
    this.tree.byteLength() +
    varuint.encodingLength(this.filled.length) +
    this.filled.length * 32 +
    (this.cursor ? this.cursor.byteLength() + 1 : 1)
  )
}

ZCIncrementalWitness.prototype.toBuffer = function () {
  var buffer = Buffer.alloc(this.byteLength())

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  function writeUInt8 (i) {
    buffer.writeUInt8(i, offset)
    offset += 1
  }

  function writeVarInt (i) {
    varuint.encode(i, buffer, offset)
    offset += varuint.encode.bytes
  }

  function writeOptional (val, func) {
    if (val) {
      writeUInt8(1)
      func(val)
    } else {
      writeUInt8(0)
    }
  }

  function writeZCIncrementalMerkleTree (tree) {
    writeSlice(tree.toBuffer())
  }

  writeSlice(this.tree.toBuffer())

  writeVarInt(this.filled.length)
  this.filled.forEach(function (hash) {
    writeSlice(hash)
  })

  writeOptional(this.cursor, writeZCIncrementalMerkleTree)

  return buffer
}

ZCIncrementalWitness.prototype.root = function () {
  return this.tree.root(this.tree.depth, this.partial_path())
}

ZCIncrementalWitness.prototype.partial_path = function () {
  var uncles = this.filled.map(function (entry) {
    return entry
  })

  if (this.cursor) {
    uncles.push(this.cursor.root(this.cursor_depth))
  }

  return uncles
}

ZCIncrementalWitness.prototype.append = function (obj) {
  if (this.cursor) {
    this.cursor.append(obj)

    if (this.cursor.is_complete(this.cursor_depth)) {
      this.filled.push(this.cursor.root(this.cursor_depth))
      this.cursor = null
    }
  } else {
    this.cursor_depth = this.tree.next_depth(this.filled.length)

    if (this.cursor_depth >= this.tree.depth) {
      throw new Error('tree is full')
    }

    if (this.cursor_depth === 0) {
      this.filled.push(obj)
    } else {
      this.cursor = new ZCIncrementalMerkleTree(this.tree.depth)
      this.cursor.append(obj)
    }
  }
}

module.exports = ZCIncrementalWitness
