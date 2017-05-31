/* global describe, it, beforeEach */

var assert = require('assert')

var ZCProof = require('../src/proof')

var fixtures = require('./fixtures/proof')

describe('ZCProof', function () {
  function fromRawG1 (raw) {
    return {
      y_lsb: raw.y_lsb,
      x: Buffer.from(raw.x, 'hex')
    }
  }

  function fromRawG2 (raw) {
    return {
      y_gt: raw.y_gt,
      x: Buffer.from(raw.x, 'hex')
    }
  }

  function fromRaw (raw) {
    var proof = new ZCProof()
    proof.g_A = fromRawG1(raw.g_A)
    proof.g_A_prime = fromRawG1(raw.g_A_prime)
    proof.g_B = fromRawG2(raw.g_B)
    proof.g_B_prime = fromRawG1(raw.g_B_prime)
    proof.g_C = fromRawG1(raw.g_C)
    proof.g_C_prime = fromRawG1(raw.g_C_prime)
    proof.g_K = fromRawG1(raw.g_K)
    proof.g_H = fromRawG1(raw.g_H)

    return proof
  }

  describe('fromBuffer/fromHex', function () {
    fixtures.valid.forEach(function (f) {
      it('imports ' + f.description, function () {
        var actual = ZCProof.fromHex(f.hex)

        assert.strictEqual(actual.toHex(), f.hex, actual.toHex())
      })
    })

    fixtures.invalid.fromBuffer.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          ZCProof.fromHex(f.hex)
        }, new RegExp(f.exception))
      })

      it('throws with __noStrict = true on ' + f.exception, function () {
        assert.throws(function () {
          ZCProof.fromBuffer(Buffer.from(f.hex, 'hex'), true)
        }, new RegExp(f.exception))
      })
    })

    fixtures.invalid.fromBufferStrict.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          ZCProof.fromHex(f.hex)
        }, new RegExp(f.exception))
      })

      it('passes with __noStrict = true on ' + f.exception, function () {
        assert.doesNotThrow(function () {
          ZCProof.fromBuffer(Buffer.from(f.hex, 'hex'), true)
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
        expected = ZCProof.fromHex(f.hex)
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
})
