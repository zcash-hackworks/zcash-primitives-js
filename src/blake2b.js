var libsodium = require('libsodium-sumo')
var sodium = require('libsodium-wrappers-sumo')

var output_format = 'uint8array'

function _format_output (output, optionalOutputFormat) {
  var selectedOutputFormat = optionalOutputFormat || output_format
  if (!_is_output_format(selectedOutputFormat)) {
    throw new Error(selectedOutputFormat + ' output format is not available')
  }
  if (output instanceof AllocatedBuf) {
    if (selectedOutputFormat === 'uint8array') {
      return output.to_Uint8Array()
    } else if (selectedOutputFormat === 'text') {
      return sodium.to_string(output.to_Uint8Array())
    } else if (selectedOutputFormat === 'hex') {
      return sodium.to_hex(output.to_Uint8Array())
    } else if (selectedOutputFormat === 'base64') {
      return sodium.to_base64(output.to_Uint8Array())
    } else {
      throw new Error('What is output format \"' + selectedOutputFormat + '\"?')
    }
  } else if (typeof output === 'object') { // Composed output. Example : key pairs
    var props = Object.keys(output)
    var formattedOutput = {}
    for (var i = 0; i < props.length; i++) {
      formattedOutput[props[i]] = _format_output(output[props[i]], selectedOutputFormat)
    }
    return formattedOutput
  } else if (typeof output === 'string') {
    return output
  } else {
    throw new TypeError('Cannot format output')
  }
}

function _is_output_format (format) {
  var formats = sodium.output_formats()
  for (var i = 0; i < formats.length; i++) {
    if (formats[i] === format) {
      return true
    }
  }
  return false
}

function _check_output_format (format) {
  if (!format) {
    return
  } else if (typeof format !== 'string') {
    throw new TypeError('When defined, the output format must be a string')
  } else if (!_is_output_format(format)) {
    throw new Error(format + ' is not a supported output format')
  }
}

// --------------------------------------------------------------------------
// Memory management
//
// AllocatedBuf: address allocated using _malloc() + length
function AllocatedBuf (length) {
  this.length = length
  this.address = _malloc(length)
}

// Copy the content of a AllocatedBuf (_malloc()'d memory) into a Uint8Array
AllocatedBuf.prototype.to_Uint8Array = function () {
  var result = new Uint8Array(this.length)
  result.set(libsodium.HEAPU8.subarray(this.address, this.address + this.length))
  return result
}

// _malloc() a region and initialize it with the content of a Uint8Array
function _to_allocated_buf_address (bytes) {
  var address = _malloc(bytes.length)
  libsodium.HEAPU8.set(bytes, address)
  return address
}

function _malloc (length) {
  var result = libsodium._malloc(length)
  if (result === 0) {
    var err = {
      message: '_malloc() failed',
      length: length
    }
    throw err
  }
  return result
}

function _free (address) {
  libsodium._free(address)
}

function _free_all (addresses) {
  for (var i = 0; i < addresses.length; i++) {
    _free(addresses[i])
  }
}

function _free_and_throw_error (address_pool, err) {
  _free_all(address_pool)
  throw new Error(err)
}

function _free_and_throw_type_error (address_pool, err) {
  _free_all(address_pool)
  throw new TypeError(err)
}

function _require_defined (address_pool, varValue, varName) {
  if (varValue === undefined) {
    _free_and_throw_type_error(address_pool, varName + ' cannot be null or undefined')
  }
}

function _any_to_Uint8Array (address_pool, varValue, varName) {
  _require_defined(address_pool, varValue, varName)
  if (varValue instanceof Uint8Array) {
    return varValue
  } else if (typeof varValue === 'string') {
    return sodium.from_string(varValue)
  }
  _free_and_throw_type_error(address_pool, 'unsupported input type for ' + varName)
}

function crypto_generichash_blake2b_salt_personal (hash_length, message, key, salt, personal, outputFormat) {
  var address_pool = []
  _check_output_format(outputFormat)

  // ---------- input: hash_length (uint)

  _require_defined(address_pool, hash_length, 'hash_length')

  if (!(typeof hash_length === 'number' && (hash_length | 0) === hash_length) && (hash_length | 0) > 0) {
    _free_and_throw_type_error(address_pool, 'hash_length must be an unsigned integer')
  }

  // ---------- input: message (unsized_buf)

  message = _any_to_Uint8Array(address_pool, message, 'message')
  var message_address = _to_allocated_buf_address(message)
  var message_length = message.length
  address_pool.push(message_address)

  // ---------- input: key (unsized_buf_optional)

  var key_address = null
  var key_length = 0
  if (key !== undefined) {
    key = _any_to_Uint8Array(address_pool, key, 'key')
    key_address = _to_allocated_buf_address(key)
    key_length = key.length
    address_pool.push(key_address)
  }

  // ---------- input: salt (buf_optional)

  var salt_address = null
  if (salt !== undefined) {
    salt = _any_to_Uint8Array(address_pool, salt, 'salt')
    var salt_length = (libsodium._crypto_generichash_blake2b_saltbytes()) | 0
    if (key.length !== salt_length) {
      _free_and_throw_type_error(address_pool, 'invalid salt length')
    }
    salt_address = _to_allocated_buf_address(salt)
    address_pool.push(salt_address)
  }

  // ---------- input: personal (buf_optional)

  var personal_address = null
  if (personal !== undefined) {
    personal = _any_to_Uint8Array(address_pool, personal, 'personal')
    var personal_length = (libsodium._crypto_generichash_blake2b_personalbytes()) | 0
    if (personal.length !== personal_length) {
      _free_and_throw_type_error(address_pool, 'invalid personal length')
    }
    personal_address = _to_allocated_buf_address(personal)
    address_pool.push(personal_address)
  }

  // ---------- output hash (buf)

  hash_length = (hash_length) | 0
  var hash = new AllocatedBuf(hash_length)
  var hash_address = hash.address

  address_pool.push(hash_address)

  if ((libsodium._crypto_generichash_blake2b_salt_personal(hash_address, hash_length, message_address, message_length, 0, key_address, key_length, salt_address, personal_address) | 0) === 0) {
    var ret = _format_output(hash, outputFormat)
    _free_all(address_pool)
    return ret
  }
  _free_and_throw_error(address_pool)
}

module.exports = {
  crypto_generichash_blake2b_salt_personal: crypto_generichash_blake2b_salt_personal
}
