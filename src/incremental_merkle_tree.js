'use strict'

var varuint = require('varuint-bitcoin')

var SHA256Compress = require('./sha256compress')

var INCREMENTAL_MERKLE_TREE_DEPTH = 29

function combine (left, right) {
  var blob = Buffer.alloc(64)
  left.copy(blob, 0)
  right.copy(blob, 32)

  var hasher = new SHA256Compress()
  hasher.update(blob)
  return hasher.hash()
}

function ZCIncrementalMerkleTree (depth) {
  this.depth = depth || INCREMENTAL_MERKLE_TREE_DEPTH
  this.emptyRoots = ZCIncrementalMerkleTree._generateEmptyRoots(this.depth + 1)
  this.left = null
  this.right = null
  this.parents = []
}

// Private, exposed for testing
ZCIncrementalMerkleTree._generateEmptyRoots = function (depth) {
  var roots = []
  roots.push(Buffer.alloc(32))
  while (roots.length <= depth) {
    roots.push(combine(roots[roots.length - 1], roots[roots.length - 1]))
  }
  return roots
}

ZCIncrementalMerkleTree.fromBuffer = function (buffer, __noStrict, __depth) {
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

  function readOptionalSlice (n) {
    var i = readUInt8()
    if (i === 1) {
      return readSlice(n)
    } else if (i === 0) {
      return null
    } else {
      throw new Error('Invalid optional')
    }
  }

  var tree = new ZCIncrementalMerkleTree(__depth)
  tree.left = readOptionalSlice(32)
  tree.right = readOptionalSlice(32)

  var parentsLen = readVarInt()
  for (var i = 0; i < parentsLen; ++i) {
    tree.parents.push(readOptionalSlice(32))
  }

  tree.wfcheck()

  if (__noStrict && offset <= buffer.length) return tree
  if (offset !== buffer.length) throw new Error('ZCIncrementalMerkleTree has unexpected data')

  return tree
}

ZCIncrementalMerkleTree.prototype.wfcheck = function () {
  if (this.parents.length >= this.depth) {
    throw new Error('tree has too many parents')
  }

  // The last parent cannot be null.
  if (this.parents.length > 0 && !(this.parents[this.parents.length - 1])) {
    throw new Error('tree has non-canonical representation of parent')
  }

  // Left cannot be empty when right exists.
  if (!this.left && this.right) {
    throw new Error('tree has non-canonical representation; right should not exist')
  }

  // Left cannot be empty when parents is nonempty.
  if (!this.left && this.parents.length > 0) {
    throw new Error('tree has non-canonical representation; parents should not be unempty')
  }
}

ZCIncrementalMerkleTree.prototype.byteLength = function () {
  return (
    (this.left ? 33 : 1) +
    (this.right ? 33 : 1) +
    varuint.encodingLength(this.parents.length) +
    this.parents.reduce(function (sum, hash) { return sum + (hash ? 33 : 1) }, 0)
  )
}

ZCIncrementalMerkleTree.prototype.clone = function () {
  var newTree = new ZCIncrementalMerkleTree(this.depth)
  newTree.left = this.left
  newTree.right = this.right

  newTree.parents = this.parents.map(function (parent) {
    return parent
  })

  return newTree
}

ZCIncrementalMerkleTree.prototype.toBuffer = function () {
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

  function writeOptionalSlice (val) {
    if (val) {
      writeUInt8(1)
      writeSlice(val)
    } else {
      writeUInt8(0)
    }
  }

  writeOptionalSlice(this.left)
  writeOptionalSlice(this.right)

  writeVarInt(this.parents.length)
  this.parents.forEach(function (hash) {
    writeOptionalSlice(hash)
  })

  return buffer
}

ZCIncrementalMerkleTree.prototype.last = function () {
  if (this.right) {
    return this.right
  } else if (this.left) {
    return this.left
  } else {
    throw new Error('tree has no cursor')
  }
}

ZCIncrementalMerkleTree.prototype.size = function () {
  var ret = 0
  if (this.left) {
    ret++
  }
  if (this.right) {
    ret++
  }
  // Treat occupation of parents array as a binary number
  // (right-shifted by 1)
  this.parents.forEach(function (parent, i) {
    if (parent) {
      ret += (1 << (i + 1))
    }
  })
  return ret
}

ZCIncrementalMerkleTree.prototype.append = function (obj) {
  if (this.is_complete(this.depth)) {
    throw new Error('tree is full')
  }

  if (!this.left) {
    // Set the left leaf
    this.left = obj
  } else if (!this.right) {
    // Set the right leaf
    this.right = obj
  } else {
    // Combine the leaves and propagate it up the tree
    var combined = combine(this.left, this.right)

    // Set the "left" leaf to the object and make the "right" leaf null
    this.left = obj
    this.right = null

    for (var i = 0; i < this.depth; i++) {
      if (i < this.parents.length) {
        if (this.parents[i]) {
          combined = combine(this.parents[i], combined)
          this.parents[i] = null
        } else {
          this.parents[i] = combined
          break
        }
      } else {
        this.parents.push(combined)
        break
      }
    }
  }
}

// This is for allowing the witness to determine if a subtree has filled
// to a particular depth, or for append() to ensure we're not appending
// to a full tree.
ZCIncrementalMerkleTree.prototype.is_complete = function (depth) {
  if (!this.left || !this.right) {
    return false
  }

  if (this.parents.length !== (depth - 1)) {
    return false
  }

  if (!this.parents.every(function (parent) { return parent })) {
    return false
  }

  return true
}

// This finds the next "depth" of an unfilled subtree, given that we've filled
// `skip` uncles/subtrees.
ZCIncrementalMerkleTree.prototype.next_depth = function (skip) {
  if (!this.left) {
    if (skip) {
      skip--
    } else {
      return 0
    }
  }

  if (!this.right) {
    if (skip) {
      skip--
    } else {
      return 0
    }
  }

  var d = 1

  // Use every() for its side-effect of executing a function on every element
  // up to and including the first element that returns false.
  if (!this.parents.every(function (parent) {
    if (!parent) {
      if (skip) {
        skip--
      } else {
        return false
      }
    }
    d++
    return true
  })) {
    return d
  }

  return d + skip
}

// This calculates the root of the tree.
ZCIncrementalMerkleTree.prototype.root = function (depth, fillerHashes) {
  depth = depth || this.depth

  var self = this
  var nextFilled = function (d) {
    if (fillerHashes && fillerHashes.length > 0) {
      return fillerHashes.shift()
    } else {
      return self.emptyRoots[d]
    }
  }

  var combineLeft = this.left ? this.left : nextFilled(0)
  var combineRight = this.right ? this.right : nextFilled(0)
  var root = combine(combineLeft, combineRight)

  var d = 1

  this.parents.forEach(function (parent) {
    if (parent) {
      root = combine(parent, root)
    } else {
      root = combine(root, nextFilled(d))
    }
    d++
  })

  while (d < depth) {
    root = combine(root, nextFilled(d))
    d++
  }

  return root
}

ZCIncrementalMerkleTree.prototype.empty_root = function () {
  return this.emptyRoots[this.depth]
}

module.exports = ZCIncrementalMerkleTree
