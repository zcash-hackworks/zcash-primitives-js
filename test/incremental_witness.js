/* global describe, it */

var assert = require('assert')

var ZCIncrementalWitness = require('../src/incremental_witness')

var INCREMENTAL_MERKLE_TREE_DEPTH_TESTING = 4

describe('ZCIncrementalWitness', function () {
  describe('fromBuffer/toBuffer', function () {
    it('is unchanged by import and export', function () {
      // From merkle_witness_serialization.json
      var hex = '01be3f6c181f162824191ecf1f78cae3ffb0ddfda671bb93277ce6ebc9201a091200030001ec4b1458a3cf805199803a1231e906ba095f969a5775ca4ac73348473e70f625016cbbfc183a1017859c6a088838ae487be84321274a039773a35b434b7610a806011880967fc8226380a849c63532bba67990f7d0a10e9c90b848f58d634957c6e900'
      var witness = ZCIncrementalWitness.fromBuffer(Buffer.from(hex, 'hex'), false, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)
      assert.strictEqual(witness.toBuffer().toString('hex'), hex)
    })
  })

  describe('fromBuffer', function () {
    describe('invalid optional', function () {
      // From merkle_witness_serialization.json
      var data = Buffer.from('0000000162fdad9bfbf17c38ea626a9c9b8af8a748e6b4367c8494caf0ca592999e8b6ba02', 'hex')

      it('throws', function () {
        assert.throws(function () {
          ZCIncrementalWitness.fromBuffer(data, false, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)
        }, new RegExp('Invalid optional'))
      })

      it('throws with __noStrict = true', function () {
        assert.throws(function () {
          ZCIncrementalWitness.fromBuffer(data, true, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)
        }, new RegExp('Invalid optional'))
      })
    })

    describe('insufficient data', function () {
      // From merkle_witness_serialization.json
      var data = Buffer.from('01be3f6c181f162824191ecf1f78cae3ffb0ddfda671bb93277ce6ebc9201a091200030001ec4b1458a3cf805199803a1231e906ba095f969a5775ca4ac73348473e70f625016cbbfc183a1017859c6a088838ae487be84321274a039773a35b434b7610a806011880967fc8226380a849c63532bba67990f7d0a10e9c90b848f58d634957c6e9', 'hex')

      it('throws', function () {
        assert.throws(function () {
          ZCIncrementalWitness.fromBuffer(data, false, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)
        }, new RegExp('Index out of range'))
      })

      it('throws with __noStrict = true', function () {
        assert.throws(function () {
          ZCIncrementalWitness.fromBuffer(data, true, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)
        }, new RegExp('Index out of range'))
      })
    })

    describe('excess data', function () {
      // From merkle_witness_serialization.json
      var data = Buffer.from('01be3f6c181f162824191ecf1f78cae3ffb0ddfda671bb93277ce6ebc9201a091200030001ec4b1458a3cf805199803a1231e906ba095f969a5775ca4ac73348473e70f625016cbbfc183a1017859c6a088838ae487be84321274a039773a35b434b7610a806011880967fc8226380a849c63532bba67990f7d0a10e9c90b848f58d634957c6e900ff', 'hex')

      it('throws', function () {
        assert.throws(function () {
          ZCIncrementalWitness.fromBuffer(data, false, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)
        }, new RegExp('ZCIncrementalWitness has unexpected data'))
      })

      it('passes with __noStrict = true', function () {
        assert.doesNotThrow(function () {
          ZCIncrementalWitness.fromBuffer(data, true, INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)
        }, new RegExp('ZCIncrementalWitness has unexpected data'))
      })
    })
  })
})
