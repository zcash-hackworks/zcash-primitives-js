var typeforce = require('typeforce')

function Buffer252bit (value) {
  return typeforce.BufferN(32)(value) && (value[0] & 0x0f) === value[0]
}

var ZATOSHI_MAX = 21 * 1e14
function Zatoshi (value) {
  return typeforce.UInt53(value) && value <= ZATOSHI_MAX
}

function BoolNum (value) {
  return typeforce.Number(value) &&
    value >= 0 &&
    value <= 1
}

// exposed, external API
var Note = typeforce.compile({
  a_pk: typeforce.BufferN(32),
  value: Zatoshi,
  rho: typeforce.BufferN(32),
  r: typeforce.BufferN(32)
})
var PaymentAddress = typeforce.compile({
  a_pk: typeforce.BufferN(32),
  pk_enc: typeforce.BufferN(32)
})
var SpendingKey = typeforce.compile({
  a_sk: Buffer252bit
})

// extend typeforce types with ours
var types = {
  BoolNum: BoolNum,
  Buffer252bit: Buffer252bit,
  Buffer256bit: typeforce.BufferN(32),
  Note: Note,
  PaymentAddress: PaymentAddress,
  SpendingKey: SpendingKey,
  Zatoshi: Zatoshi
}

for (var typeName in typeforce) {
  types[typeName] = typeforce[typeName]
}

module.exports = types
