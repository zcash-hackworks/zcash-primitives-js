/* global describe, it */

var assert = require('assert')
var address = require('../src/address')

var Note = require('../src/note')
var NotePlaintext = require('../src/note_plaintext')

describe('NotePlaintext', function () {
  var key = address.SpendingKey.random()
  var note = Note.dummy(key.address().a_pk)
  var notePt = new NotePlaintext(note, Buffer.from('Dummy plaintext'))

  describe('toBuffer/fromBuffer', function () {
    it('is unchanged by export and import', function () {
      var notePt2 = NotePlaintext.fromBuffer(notePt.toBuffer())
      assert.strictEqual(
        notePt.toBuffer().toString('hex'),
        notePt2.toBuffer().toString('hex'),
        'NotePlaintexts do not match')
    })

    describe('invalid lead byte', function () {
      var data = notePt.toBuffer()
      data[0] = 1

      it('throws', function () {
        assert.throws(function () {
          NotePlaintext.fromBuffer(data)
        }, new RegExp('lead byte of NotePlaintext is not recognized'))
      })

      it('throws with __noStrict = true', function () {
        assert.throws(function () {
          NotePlaintext.fromBuffer(data, true)
        }, new RegExp('lead byte of NotePlaintext is not recognized'))
      })
    })

    describe('insufficient data', function () {
      var data = notePt.toBuffer().slice(0, notePt.byteLength() - 1)

      it('throws', function () {
        assert.throws(function () {
          NotePlaintext.fromBuffer(data)
        }, new RegExp('NotePlaintext has unexpected data'))
      })

      it('throws with __noStrict = true', function () {
        assert.throws(function () {
          NotePlaintext.fromBuffer(data, true)
        }, new RegExp('NotePlaintext has unexpected data'))
      })
    })

    describe('excess data', function () {
      var data = Buffer.alloc(notePt.byteLength() + 1)
      notePt.toBuffer().copy(data)

      it('throws', function () {
        assert.throws(function () {
          NotePlaintext.fromBuffer(data)
        }, new RegExp('NotePlaintext has unexpected data'))
      })

      it('passes with __noStrict = true', function () {
        assert.doesNotThrow(function () {
          NotePlaintext.fromBuffer(data, true)
        }, new RegExp('NotePlaintext has unexpected data'))
      })
    })
  })

  describe('note', function () {
    it('generates the correct note', function () {
      var note2 = notePt.note(key.address().a_pk)
      assert.strictEqual(
        note.cm().toString('hex'),
        note2.cm().toString('hex'),
        'Commitments do not match')
      assert.strictEqual(
        note.nullifier(key).toString('hex'),
        note2.nullifier(key).toString('hex'),
        'Nullifiers do not match')
    })
  })
})
