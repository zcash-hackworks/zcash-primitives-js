var varuint = require('varuint-bitcoin')

var JSDescription = require('./jsdescription')

function TransactionHelper () {
  this.jss = []
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

module.exports = TransactionHelper
