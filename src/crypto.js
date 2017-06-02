var createHash = require('create-hash')

function sha256 (buffer) {
  return createHash('sha256').update(buffer).digest()
}

module.exports = {
  sha256: sha256
}
