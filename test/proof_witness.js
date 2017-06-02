/* global describe, it */
'use strict'

var assert = require('assert')

var JSProofWitness = require('../src/proof_witness')

var fixtures = require('./fixtures/proof_witness')

describe('JSProofWitness', function () {
  describe('fromBuffer/fromHex', function () {
    fixtures.valid.forEach(function (f, i) {
      it('imports random proof witness ' + i, function () {
        var actual = JSProofWitness.fromHex(f.hex)

        assert.strictEqual(actual.toHex(), f.hex, actual.toHex())
      })
    })

    fixtures.invalid.fromBufferStrict.forEach(function (f) {
      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          JSProofWitness.fromHex(f.hex)
        }, new RegExp(f.exception))
      })

      it('passes with __noStrict = true on ' + f.exception, function () {
        assert.doesNotThrow(function () {
          JSProofWitness.fromBuffer(Buffer.from(f.hex, 'hex'), true)
        }, new RegExp(f.exception))
      })
    })
  })
})
