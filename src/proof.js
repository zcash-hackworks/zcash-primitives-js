'use strict'

var G1_PREFIX_MASK = 0x02
var G2_PREFIX_MASK = 0x0a

function ZCProof () {
}

ZCProof.fromBuffer = function (buffer, __noStrict) {
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

  function readCompressedG1 () {
    var leadingByte = readUInt8()
    if ((leadingByte & (~1)) !== G1_PREFIX_MASK) {
      throw new Error('lead byte of G1 point not recognized')
    }
    return {
      y_lsb: leadingByte & 1,
      x: readSlice(32)
    }
  }

  function readCompressedG2 () {
    var leadingByte = readUInt8()
    if ((leadingByte & (~1)) !== G2_PREFIX_MASK) {
      throw new Error('lead byte of G2 point not recognized')
    }
    return {
      y_gt: leadingByte & 1,
      x: readSlice(64)
    }
  }

  var proof = new ZCProof()
  proof.g_A = readCompressedG1()
  proof.g_A_prime = readCompressedG1()
  proof.g_B = readCompressedG2()
  proof.g_B_prime = readCompressedG1()
  proof.g_C = readCompressedG1()
  proof.g_C_prime = readCompressedG1()
  proof.g_K = readCompressedG1()
  proof.g_H = readCompressedG1()

  if (__noStrict) return proof
  if (offset !== buffer.length) throw new Error('ZCProof has unexpected data')

  return proof
}

ZCProof.fromHex = function (hex) {
  return ZCProof.fromBuffer(Buffer.from(hex, 'hex'))
}

ZCProof.prototype.byteLength = function () {
  return 296
}

ZCProof.prototype.clone = function () {
  var newProof = new ZCProof()
  newProof.g_A = this.g_A
  newProof.g_A_prime = this.g_A_prime
  newProof.g_B = this.g_B
  newProof.g_B_prime = this.g_B_prime
  newProof.g_C = this.g_C
  newProof.g_C_prime = this.g_C_prime
  newProof.g_K = this.g_K
  newProof.g_H = this.g_H

  return newProof
}

ZCProof.prototype.toBuffer = function () {
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

  function writeCompressedG1 (p) {
    writeUInt8(G1_PREFIX_MASK | p.y_lsb)
    writeSlice(p.x)
  }

  function writeCompressedG2 (p) {
    writeUInt8(G2_PREFIX_MASK | p.y_gt)
    writeSlice(p.x)
  }

  writeCompressedG1(this.g_A)
  writeCompressedG1(this.g_A_prime)
  writeCompressedG2(this.g_B)
  writeCompressedG1(this.g_B_prime)
  writeCompressedG1(this.g_C)
  writeCompressedG1(this.g_C_prime)
  writeCompressedG1(this.g_K)
  writeCompressedG1(this.g_H)

  return buffer
}

ZCProof.prototype.toHex = function () {
  return this.toBuffer().toString('hex')
}

module.exports = ZCProof
