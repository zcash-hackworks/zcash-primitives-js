/* global describe, it */

var assert = require('assert')

var address = require('../src/address')

var fixtures = require('./fixtures/address')

describe('PaymentAddress', function () {
  function fromRaw (raw) {
    var aPk = Buffer.from(raw.a_pk, 'hex')
    var pkEnc = Buffer.from(raw.pk_enc, 'hex')
    return new address.PaymentAddress(aPk, pkEnc)
  }

  describe('fromZAddress', function () {
    fixtures.valid.forEach(function (f) {
      var versionMap = {}
      versionMap[f.addressVersion] = address.PaymentAddress

      it('imports ' + f.address, function () {
        var actual = address.fromZAddress(f.address, versionMap)
        assert.strictEqual(
          actual.toZAddress(f.addressVersion),
          f.address,
          actual.toZAddress(f.addressVersion))
      })
    })

    fixtures.invalid.fromZAddress.forEach(function (f) {
      var versionMap = {}
      versionMap[f.addressVersion] = address.PaymentAddress

      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          address.fromZAddress(f.address, versionMap)
        }, f.exception)
      })
    })
  })

  describe('toZAddress', function () {
    fixtures.valid.forEach(function (f) {
      it('exports ' + f.address, function () {
        var actual = fromRaw(f.raw)
        assert.strictEqual(
          actual.toZAddress(f.addressVersion),
          f.address,
          actual.toZAddress(f.addressVersion))
      })
    })
  })
})

describe('SpendingKey', function () {
  function fromRaw (raw) {
    var aSk = Buffer.from(raw.a_sk, 'hex')
    return new address.SpendingKey(aSk)
  }

  describe('fromZKey', function () {
    fixtures.valid.forEach(function (f) {
      var versionMap = {}
      versionMap[f.keyVersion] = address.SpendingKey

      it('imports ' + f.key, function () {
        var actual = address.fromZKey(f.key, versionMap)
        assert.strictEqual(
          actual.toZKey(f.keyVersion),
          f.key,
          actual.toZKey(f.keyVersion))
      })
    })

    fixtures.invalid.fromZKey.forEach(function (f) {
      var versionMap = {}
      versionMap[f.keyVersion] = address.SpendingKey

      it('throws on ' + f.exception, function () {
        assert.throws(function () {
          address.fromZKey(f.key, versionMap)
        }, f.exception)
      })
    })
  })

  describe('toZKey', function () {
    fixtures.valid.forEach(function (f) {
      it('exports ' + f.key, function () {
        var actual = fromRaw(f.raw)
        assert.strictEqual(
          actual.toZKey(f.keyVersion),
          f.key,
          actual.toZKey(f.keyVersion))
      })
    })
  })

  describe('address', function () {
    fixtures.valid.forEach(function (f) {
      var versionMap = {}
      versionMap[f.keyVersion] = address.SpendingKey

      it('correctly derives for ' + f.key, function () {
        var key = address.fromZKey(f.key, versionMap)
        var actual = key.address()
        assert.strictEqual(
          actual.toZAddress(f.addressVersion),
          f.address,
          actual.toZAddress(f.addressVersion))
      })
    })
  })
})
