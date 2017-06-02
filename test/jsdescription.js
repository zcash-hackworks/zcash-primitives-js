/* global describe, it, beforeEach */

var assert = require('assert')

var JSDescription = require('../src/jsdescription')
var ZCProof = require('../src/proof')

var fixtures = require('./fixtures/jsdescription')
var hSigFixtures = require('./fixtures/hsig')

describe('JSDescription', function () {
  function fromRaw (raw) {
    var jsdesc = new JSDescription()
    jsdesc.vpub_old = raw.vpub_old
    jsdesc.vpub_new = raw.vpub_new
    jsdesc.anchor = [].reverse.call(Buffer.from(raw.anchor, 'hex'))

    raw.nullifiers.forEach(function (nullifier) {
      jsdesc.nullifiers.push([].reverse.call(Buffer.from(nullifier, 'hex')))
    })

    raw.commitments.forEach(function (commitment) {
      jsdesc.commitments.push([].reverse.call(Buffer.from(commitment, 'hex')))
    })

    jsdesc.onetimePubKey = [].reverse.call(Buffer.from(raw.onetimePubKey, 'hex'))
    jsdesc.randomSeed = [].reverse.call(Buffer.from(raw.randomSeed, 'hex'))

    raw.macs.forEach(function (mac) {
      jsdesc.macs.push([].reverse.call(Buffer.from(mac, 'hex')))
    })

    jsdesc.proof = ZCProof.fromHex(raw.proof)

    raw.ciphertexts.forEach(function (ciphertext) {
      jsdesc.ciphertexts.push(Buffer.from(ciphertext, 'hex'))
    })

    return jsdesc
  }

  describe('fromBuffer/fromHex', function () {
    fixtures.valid.forEach(function (f) {
      it('imports ' + f.description, function () {
        var actual = JSDescription.fromHex(f.hex)

        assert.strictEqual(actual.toHex(), f.hex, actual.toHex())
      })
    })

    fixtures.invalid.fromBufferStrict.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          JSDescription.fromHex(f.hex)
        }, new RegExp(f.exception))
      })

      it('passes with __noStrict = true on ' + f.exception, function () {
        assert.doesNotThrow(function () {
          JSDescription.fromBuffer(Buffer.from(f.hex, 'hex'), true)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('toBuffer/toHex', function () {
    fixtures.valid.forEach(function (f) {
      it('exports ' + f.description, function () {
        var actual = fromRaw(f.raw)

        assert.strictEqual(actual.toHex(), f.hex, actual.toHex())
      })
    })
  })

  describe('clone', function () {
    fixtures.valid.forEach(function (f) {
      var actual, expected

      beforeEach(function () {
        expected = JSDescription.fromHex(f.hex)
        actual = expected.clone()
      })

      it('should have value equality', function () {
        assert.deepEqual(actual, expected)
      })

      it('should not have reference equality', function () {
        assert.notEqual(actual, expected)
      })
    })
  })

  describe('hSig', function () {
    hSigFixtures.valid.forEach(function (f) {
      it('equals ' + f.hex, function () {
        var jsdesc = new JSDescription()
        jsdesc.randomSeed = [].reverse.call(Buffer.from(f.randomSeed, 'hex'))
        f.nullifiers.forEach(function (nullifier) {
          jsdesc.nullifiers.push([].reverse.call(Buffer.from(nullifier, 'hex')))
        })

        var actual = jsdesc.h_sig([].reverse.call(Buffer.from(f.pubKeyHash, 'hex')))
        var expected = [].reverse.call(Buffer.from(f.hex, 'hex'))
        assert.strictEqual(Buffer.from(actual).toString('hex'), expected.toString('hex'))
      })
    })
  })
})
