'use strict'

var blake2b = require('./blake2b')
var bufferutils = require('./bufferutils')
var prf = require('./prf')
var typeforce = require('typeforce')
var types = require('./types')
var util = require('./util')
var zconst = require('./const')

var JSProofWitness = require('./proof_witness')
var NotePlaintext = require('./note_plaintext')
var ZCNoteEncryption = require('./note_encryption')
var ZCProof = require('./proof')

function hSig (randomSeed, nullifiers, pubKeyHash) {
  typeforce(types.tuple(
    types.Buffer256bit,
    types.arrayOf(types.Buffer256bit),
    types.Buffer256bit
  ), arguments)

  return Buffer.from(blake2b.crypto_generichash_blake2b_salt_personal(
    32,
    Buffer.concat([randomSeed].concat(nullifiers).concat([pubKeyHash])),
    undefined, // No key.
    undefined, // No salt.
    'ZcashComputehSig'))
}

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

JSDescription.prototype.h_sig = function (joinSplitPubKey) {
  return hSig(this.randomSeed, this.nullifiers, joinSplitPubKey)
}

JSDescription.withWitness = function (inputs, outputs, pubKeyHash, vpubOld, vpubNew, rt) {
  typeforce(types.tuple(
    types.arrayOf(types.JSInput),
    types.arrayOf(types.JSOutput),
    types.Buffer256bit,
    types.Zatoshi,
    types.Zatoshi,
    types.Buffer256bit
  ), arguments)

  if (inputs.length !== zconst.ZC_NUM_JS_INPUTS) {
    throw new Error(`invalid number of inputs (found ${inputs.length}, expected ${zconst.ZC_NUM_JS_INPUTS}`)
  }
  if (outputs.length !== zconst.ZC_NUM_JS_OUTPUTS) {
    throw new Error(`invalid number of inputs (found ${outputs.length}, expected ${zconst.ZC_NUM_JS_OUTPUTS}`)
  }

  var jsdesc = new JSDescription()
  jsdesc.vpub_old = vpubOld
  jsdesc.vpub_new = vpubNew
  jsdesc.anchor = rt

  var lhsValue = vpubOld
  var rhsValue = vpubNew

  inputs.forEach(function (input) {
    // Sanity checks of input

    // If note has nonzero value
    if (input.note.value !== 0) {
      // The witness root must equal the input root.
      if (input.witness.root() !== rt) {
        throw new Error('joinsplit not anchored to the correct root')
      }

      // The tree must witness the correct element
      if (input.note.cm() !== input.witness.element()) {
        throw new Error('witness of wrong element for joinsplit input')
      }
    }

    // Ensure we have the key to this note.
    if (input.note.a_pk.toString('hex') !== input.key.address().a_pk.toString('hex')) {
      throw new Error('input note not authorized to spend with given key')
    }

    // Balance must be sensical
    typeforce(types.Zatoshi, input.note.value)
    lhsValue += input.note.value
    typeforce(types.Zatoshi, lhsValue)

    // Compute nullifier of input
    jsdesc.nullifiers.push(input.nullifier())
  })

  // Sample randomSeed
  jsdesc.randomSeed = util.random_uint256()

  // Compute h_sig
  var hSig = jsdesc.h_sig(pubKeyHash)

  // Sample phi
  var phi = util.random_uint252()

  // Compute notes for outputs
  var notes = []
  outputs.forEach(function (output, i) {
    // Sanity checks of output
    typeforce(types.Zatoshi, output.value)
    rhsValue += output.value
    typeforce(types.Zatoshi, rhsValue)

    // Sample r
    var r = util.random_uint256()

    notes.push(output.note(phi, r, i, hSig))
  })

  if (lhsValue !== rhsValue) {
    throw new Error('invalid joinsplit balance')
  }

  // Compute the output commitments
  notes.forEach(function (note) {
    jsdesc.commitments.push(note.cm())
  })

  // Encrypt the ciphertexts containing the note
  // plaintexts to the recipients of the value.
  var encryptor = new ZCNoteEncryption(hSig)

  notes.forEach(function (note, i) {
    var pt = new NotePlaintext(note, outputs[i].memo)

    jsdesc.ciphertexts.push(pt.encrypt(encryptor, outputs[i].addr.pk_enc))
  })

  jsdesc.ephemeralKey = encryptor.epk

  // Authenticate hSig with each of the input
  // spending keys, producing macs which protect
  // against malleability.
  inputs.forEach(function (input, i) {
    jsdesc.macs.push(prf.PRF_pk(inputs[i].key.a_sk, i, hSig))
  })

  jsdesc.witness = new JSProofWitness(phi, rt, hSig, inputs, notes, vpubOld, vpubNew)

  return jsdesc
}

module.exports = JSDescription
