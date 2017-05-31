var typeforce = require('typeforce')

function Buffer252bit (value) {
  return typeforce.BufferN(32)(value) && (value[0] & 0x0f) === value[0]
}

function BoolNum (value) {
  return typeforce.Number(value) &&
    value >= 0 &&
    value <= 1
}

// exposed, external API
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
  PaymentAddress: PaymentAddress,
  SpendingKey: SpendingKey
}

for (var typeName in typeforce) {
  types[typeName] = typeforce[typeName]
}

module.exports = types
