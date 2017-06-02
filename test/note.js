/* global describe, it */

var assert = require('assert')
var address = require('../src/address')

var Note = require('../src/note')

describe('Note', function () {
  var key = address.SpendingKey.random()
  var note = Note.dummy(key.address().a_pk)

  describe('toBuffer/fromBuffer', function () {
    it('is unchanged by export and import', function () {
      var note2 = Note.fromBuffer(note.toBuffer())
      assert.strictEqual(
        note.cm().toString('hex'),
        note2.cm().toString('hex'),
        'Commitments do not match')
      assert.strictEqual(
        note.nullifier(key).toString('hex'),
        note2.nullifier(key).toString('hex'),
        'Nullifiers do not match')
    })

    describe('insufficient data', function () {
      var data = note.toBuffer().slice(0, note.byteLength() - 1)

      it('throws', function () {
        assert.throws(function () {
          Note.fromBuffer(data)
        }, 'Expected property "3" of type Buffer(Length: 32), got Buffer(Length: 31)')
      })

      it('throws with __noStrict = true', function () {
        assert.throws(function () {
          Note.fromBuffer(data, true)
        }, 'Expected property "3" of type Buffer(Length: 32), got Buffer(Length: 31)')
      })
    })

    describe('excess data', function () {
      var data = Buffer.alloc(note.byteLength() + 1)
      note.toBuffer().copy(data)

      it('throws', function () {
        assert.throws(function () {
          Note.fromBuffer(data)
        }, new RegExp('Note has unexpected data'))
      })

      it('passes with __noStrict = true', function () {
        assert.doesNotThrow(function () {
          Note.fromBuffer(data, true)
        }, new RegExp('Note has unexpected data'))
      })
    })
  })
})
