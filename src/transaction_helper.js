var sodium = require('libsodium-wrappers-sumo')
var typeforce = require('typeforce')
var types = require('./types')
var varuint = require('varuint-bitcoin')
var zmq = require('zeromq')

var JSDescription = require('./jsdescription')
var JSInput = require('./jsinput')
var JSOutput = require('./jsoutput')
var ZCProof = require('./proof')

// Common constants across implementations
var NOT_AN_INPUT = 65535
var SIGHASH_ALL = 0x01

function TransactionHelper () {
  this.jss = []

  this._jsouts = []
}

TransactionHelper.fromTransactionBuffer = function (version, buffer) {
  var offset = 0
  function readSlice (n) {
    offset += n
    return buffer.slice(offset - n, offset)
  }

  function readVarInt () {
    var vi = varuint.decode(buffer, offset)
    offset += varuint.decode.bytes
    return vi
  }

  function readJSDescription () {
    var jsdesc = JSDescription.fromBuffer(buffer.slice(offset), true)
    offset += jsdesc.byteLength()
    return jsdesc
  }

  var helper = new TransactionHelper()

  if (version >= 2) {
    var vjoinsplitLen = readVarInt()
    for (var i = 0; i < vjoinsplitLen; ++i) {
      var jsdesc = readJSDescription()
      helper.jss.push(jsdesc)
    }
    if (vjoinsplitLen > 0) {
      helper.joinSplitPubKey = readSlice(32)
      helper.joinSplitSig = readSlice(64)
    }
  }

  return helper
}

TransactionHelper.prototype.byteLength = function (version) {
  var jsLen = 0
  if (version >= 2) {
    jsLen = (
      varuint.encodingLength(this.jss.length) +
      this.jss.reduce(function (sum, jsdesc) { return sum + jsdesc.byteLength() }, 0) +
      (this.jss.length > 0 ? 12 : 0)
    )
  }

  return jsLen
}

TransactionHelper.prototype.clone = function () {
  var newHelper = new TransactionHelper()

  newHelper.jss = this.jss.map(function (jsdesc) {
    return jsdesc.clone()
  })
  if (this.jss.length > 0) {
    newHelper.joinSplitPubKey = this.joinSplitPubKey
    newHelper.joinSplitSig = this.joinSplitSig
  }

  return newHelper
}

TransactionHelper.prototype.toBuffer = function (version) {
  var buffer = Buffer.alloc(this.byteLength(version))

  var offset = 0
  function writeSlice (slice) {
    slice.copy(buffer, offset)
    offset += slice.length
  }

  function writeVarInt (i) {
    varuint.encode(i, buffer, offset)
    offset += varuint.encode.bytes
  }

  if (version >= 2) {
    writeVarInt(this.jss.length)
    this.jss.forEach(function (jsdesc) {
      writeSlice(jsdesc.toBuffer())
    })
    if (this.jss.length > 0) {
      writeSlice(this.joinSplitPubKey)
      writeSlice(this.joinSplitSig)
    }
  }

  return buffer
}

TransactionHelper.prototype.numJoinSplits = function (version) {
  if (version >= 2) {
    if (this._jsouts.length) {
      return Math.ceil(this._jsouts.length / 2)
    } else {
      return Math.ceil(this.jss.length / 2)
    }
  } else {
    return 0
  }
}

TransactionHelper.prototype.addShieldedOutput = function (addr, value, memo) {
  typeforce(types.tuple(
    types.PaymentAddress,
    types.Zatoshi,
    types.maybe(types.Buffer)
  ), arguments)

  // Add the JSOutput and return the JSOutput's index
  return (this._jsouts.push(new JSOutput(addr, value, memo)) - 1)
}

TransactionHelper.prototype.setAnchor = function (anchor) {
  typeforce(types.Buffer256bit, anchor)

  this._anchor = anchor
}

TransactionHelper.prototype.getProofs = function (provingServiceUri, callbackfn) {
  if (!this._anchor) throw new Error('Must call setAnchor() before getProofs()')

  var keyPair = sodium.crypto_sign_keypair()
  this.joinSplitPubKey = Buffer.from(keyPair.publicKey)
  this._joinSplitPrivKey = Buffer.from(keyPair.privateKey)

  for (var i = 0; i < this._jsouts.length; i += 2) {
    var inputs = [
      JSInput.dummy(),
      JSInput.dummy()
    ]

    var outputs = [
      this._jsouts[i],
      this._jsouts[i + 1] || JSOutput.dummy()
    ]

    var value = outputs.reduce(function (sum, output) { return sum + output.value }, 0)
    this.jss.push(JSDescription.withWitness(inputs, outputs, this.joinSplitPubKey, value, 0, this._anchor))
  }

  var request = Buffer.alloc(
    varuint.encodingLength(this.jss.length) +
    this.jss.reduce(function (sum, jsdesc) { return sum + jsdesc.witness.byteLength() }, 0)
  )
  var offset = 0
  function writeSlice (slice) {
    slice.copy(request, offset)
    offset += slice.length
  }

  function writeVarInt (i) {
    varuint.encode(i, request, offset)
    offset += varuint.encode.bytes
  }

  writeVarInt(this.jss.length)
  this.jss.forEach(function (jsdesc) {
    writeSlice(jsdesc.witness.toBuffer())
  })

  var sock = zmq.socket('req')
  sock.connect(provingServiceUri)
  sock.send(request)

  sock.on('message', function (msg) {
    var offset = 0
    function readVarInt () {
      var vi = varuint.decode(msg, offset)
      offset += varuint.decode.bytes
      return vi
    }

    function readZCProof () {
      var proof = ZCProof.fromBuffer(msg.slice(offset), true)
      offset += proof.byteLength()
      return proof
    }

    var proofsLen = readVarInt()
    for (var i = 0; i < proofsLen; ++i) {
      this.jss[i].proof = readZCProof()
    }

    sock.close()
    callbackfn()
  }.bind(this))
}

TransactionHelper.prototype.signShielded = function (signatureHashFn) {
  // Empty output script
  var scriptCode = Buffer.alloc(0)
  var dataToBeSigned = signatureHashFn(NOT_AN_INPUT, scriptCode, SIGHASH_ALL)

  // Add the signature
  this.joinSplitSig = Buffer.from(sodium.crypto_sign_detached(dataToBeSigned, this._joinSplitPrivKey))

  // Sanity check
  sodium.crypto_sign_verify_detached(this.joinSplitSig, dataToBeSigned, this.joinSplitPubKey)
}

module.exports = TransactionHelper
