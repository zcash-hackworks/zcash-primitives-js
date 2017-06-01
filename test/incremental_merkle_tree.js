/* global describe, it */

var assert = require('assert')

var ZCIncrementalMerkleTree = require('../src/incremental_merkle_tree')
var ZCIncrementalWitness = require('../src/incremental_witness')

var merkleCommitments = require('./fixtures/zcash/merkle_commitments')
var merkleRoots = require('./fixtures/zcash/merkle_roots')
var merkleRootsEmpty = require('./fixtures/zcash/merkle_roots_empty')
var merkleSerialization = require('./fixtures/zcash/merkle_serialization')
var merkleWitnessSerialization = require('./fixtures/zcash/merkle_witness_serialization')

var INCREMENTAL_MERKLE_TREE_DEPTH_TESTING = 4

describe('ZCIncrementalMerkleTree', function () {
  it('correctly constructs a tree', function () {
    var witnessSerIndex = 0
    var tree = new ZCIncrementalMerkleTree(INCREMENTAL_MERKLE_TREE_DEPTH_TESTING)

    // The root of the tree at this point is expected to be the root of the
    // empty tree.
    assert.strictEqual(
      tree.root().toString('hex'),
      tree.empty_root().toString('hex'),
        'Tree root inconsistent for empty tree'
    )

    // The tree doesn't have a 'last' element added since it's blank.
    assert.throws(function () {
      tree.last()
    }, new RegExp('tree has no cursor'))

    // The tree is empty.
    assert.strictEqual(tree.size(), 0)

    // We need to witness at every single point in the tree, so
    // that the consistency of the tree and the merkle paths can
    // be checked.
    var witnesses = []

    merkleCommitments.forEach(function (commitment, i) {
      var testCommitment = [].reverse.call(Buffer.from(commitment, 'hex'))

      // Witness here
      witnesses.push(ZCIncrementalWitness.fromTree(tree))

      // Now append a commitment to the tree
      tree.append(testCommitment)

      // Size incremented by one
      assert.strictEqual(
        tree.size(), i + 1,
        'Invalid tree size for commitment ' + i
      )

      // Last element added to the tree was `testCommitment`
      assert.strictEqual(
        tree.last().toString('hex'), testCommitment.toString('hex'),
        'Invalid last element for commitment ' + i
      )

      // Check tree root consistency
      assert.strictEqual(
        tree.root().toString('hex'), merkleRoots[i],
        'Tree root inconsistent for commitment ' + i
      )

      // Check serialization of tree
      assert.strictEqual(
        tree.toBuffer().toString('hex'), merkleSerialization[i],
        'Tree serialization inconsistent for commitment ' + i
      )

      witnesses.forEach(function (witness, j) {
        // Append the same commitment to all the witnesses
        witness.append(testCommitment)

        // Can't do path checks without libsnark

        // Check witness serialization
        assert.strictEqual(
          witness.toBuffer().toString('hex'), merkleWitnessSerialization[witnessSerIndex++],
          'Witness ' + j + ' serialization inconsistent for commitment ' + i
        )

        // Check witness root is same as tree root
        assert.strictEqual(
          witness.root().toString('hex'), tree.root().toString('hex'),
          'Witness ' + j + ' root inconsistent for commitment ' + i
        )
      })
    })

    // Tree should be full now
    assert.throws(function () {
      tree.append(Buffer.alloc(32))
    })

    witnesses.forEach(function (witness) {
      assert.throws(function () {
        witness.append(Buffer.alloc(32))
      })
    })
  })

  it('has the correct empty root', function () {
    assert.strictEqual(
      new ZCIncrementalMerkleTree().empty_root().toString('hex'),
      'd7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259',
      'Invalid empty root'
    )
  })

  describe('_generateEmptyRoots', function () {
    var emptyRoots = ZCIncrementalMerkleTree._generateEmptyRoots(64)

    emptyRoots.forEach(function (root, d) {
      it('generates the correct empty root for depth ' + d, function () {
        assert.strictEqual(root.toString('hex'), merkleRootsEmpty[d])
      })
    })
  })

  describe('fromBuffer', function () {
    it('throws when the most ancestral parent is empty', function () {
      assert.throws(function () {
        ZCIncrementalMerkleTree.fromBuffer(
          Buffer.from('0155b852781b9995a44c939b64e441ae2724b96f99c8f4fb9a141cfc9842c4b0e3000100', 'hex')
        )
      }, new RegExp('tree has non-canonical representation of parent'))
    })

    it('throws when left doesn\'t exists but right does', function () {
      assert.throws(function () {
        ZCIncrementalMerkleTree.fromBuffer(
          Buffer.from('000155b852781b9995a44c939b64e441ae2724b96f99c8f4fb9a141cfc9842c4b0e300', 'hex')
        )
      }, new RegExp('tree has non-canonical representation; right should not exist'))
    })

    it('throws when left doesn\'t exists but a parent does', function () {
      assert.throws(function () {
        ZCIncrementalMerkleTree.fromBuffer(
          Buffer.from('000001018695873d63ec0bceeadb5bf4ccc6723ac803c1826fc7cfb34fc76180305ae27d', 'hex')
        )
      }, new RegExp('tree has non-canonical representation; parents should not be unempty'))
    })

    describe('invalid optional', function () {
      var data = Buffer.from('0262fdad9bfbf17c38ea626a9c9b8af8a748e6b4367c8494caf0ca592999e8b6ba0000', 'hex')

      it('throws', function () {
        assert.throws(function () {
          ZCIncrementalMerkleTree.fromBuffer(data)
        }, new RegExp('Invalid optional'))
      })

      it('throws with __noStrict = true', function () {
        assert.throws(function () {
          ZCIncrementalMerkleTree.fromBuffer(data, true)
        }, new RegExp('Invalid optional'))
      })
    })

    describe('insufficient data', function () {
      var data = Buffer.from('0162fdad9bfbf17c38ea626a9c9b8af8a748e6b4367c8494caf0ca592999e8b6ba00', 'hex')

      it('throws', function () {
        assert.throws(function () {
          ZCIncrementalMerkleTree.fromBuffer(data)
        }, new RegExp('Index out of range'))
      })

      it('throws with __noStrict = true', function () {
        assert.throws(function () {
          ZCIncrementalMerkleTree.fromBuffer(data, true)
        }, new RegExp('Index out of range'))
      })
    })

    describe('excess data', function () {
      var data = Buffer.from('0162fdad9bfbf17c38ea626a9c9b8af8a748e6b4367c8494caf0ca592999e8b6ba0000ff', 'hex')

      it('throws', function () {
        assert.throws(function () {
          ZCIncrementalMerkleTree.fromBuffer(data)
        }, new RegExp('ZCIncrementalMerkleTree has unexpected data'))
      })

      it('passes with __noStrict = true', function () {
        assert.doesNotThrow(function () {
          ZCIncrementalMerkleTree.fromBuffer(data, true)
        }, new RegExp('ZCIncrementalMerkleTree has unexpected data'))
      })
    })
  })
})
