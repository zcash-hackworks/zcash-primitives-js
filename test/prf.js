/* global describe, it */
'use strict'

var assert = require('assert')

var prf = require('../src/prf')

var fixtures = require('./fixtures/prf')

describe('PRF', function () {
  describe('PRF_addr_a_pk', function () {
    fixtures.PRF_addr_a_pk.forEach(function (f) {
      it('calculates ' + f.hex + ' correctly', function () {
        var aSk = Buffer.from(f.a_sk, 'hex')
        assert.strictEqual(prf.PRF_addr_a_pk(aSk).toString('hex'), f.hex)
      })
    })
  })

  describe('PRF_addr_sk_enc', function () {
    fixtures.PRF_addr_sk_enc.forEach(function (f) {
      it('calculates ' + f.hex + ' correctly', function () {
        var aSk = Buffer.from(f.a_sk, 'hex')
        assert.strictEqual(prf.PRF_addr_sk_enc(aSk).toString('hex'), f.hex)
      })
    })
  })

  describe('PRF_nf', function () {
    fixtures.PRF_nf.forEach(function (f) {
      it('calculates ' + f.hex + ' correctly', function () {
        var aSk = Buffer.from(f.a_sk, 'hex')
        var rho = Buffer.from(f.rho, 'hex')
        assert.strictEqual(prf.PRF_nf(aSk, rho).toString('hex'), f.hex)
      })
    })
  })

  describe('PRF_pk', function () {
    fixtures.PRF_pk.forEach(function (f) {
      describe('a_sk [' + f.a_sk + ']', function () {
        var aSk = Buffer.from(f.a_sk, 'hex')
        var hSig = Buffer.from(f.hSig, 'hex')
        f.hex.forEach(function (f, i) {
          it('calculates ' + i + ' correctly', function () {
            assert.strictEqual(prf.PRF_pk(aSk, i, hSig).toString('hex'), f)
          })
        })
      })
    })

    it('throws on out-of-bounds index', function () {
      assert.throws(function () {
        prf.PRF_pk(Buffer.alloc(32), 2, Buffer.alloc(32))
      }, new RegExp('PRF_pk invoked with index out of bounds'))
    })
  })

  describe('PRF_rho', function () {
    fixtures.PRF_rho.forEach(function (f) {
      describe('phi [' + f.phi + ']', function () {
        var phi = Buffer.from(f.phi, 'hex')
        var hSig = Buffer.from(f.hSig, 'hex')
        f.hex.forEach(function (f, i) {
          it('calculates ' + i + ' correctly', function () {
            assert.strictEqual(prf.PRF_rho(phi, i, hSig).toString('hex'), f)
          })
        })
      })
    })

    it('throws on out-of-bounds index', function () {
      assert.throws(function () {
        prf.PRF_rho(Buffer.alloc(32), 2, Buffer.alloc(32))
      }, new RegExp('PRF_rho invoked with index out of bounds'))
    })
  })
})
