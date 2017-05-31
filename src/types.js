var typeforce = require('typeforce')

function Buffer252bit (value) {
  return typeforce.BufferN(32)(value) && (value[0] & 0x0f) === value[0]
}

function BoolNum (value) {
  return typeforce.Number(value) &&
    value >= 0 &&
    value <= 1
}

// extend typeforce types with ours
var types = {
  BoolNum: BoolNum,
  Buffer252bit: Buffer252bit,
  Buffer256bit: typeforce.BufferN(32)
}

for (var typeName in typeforce) {
  types[typeName] = typeforce[typeName]
}

module.exports = types
