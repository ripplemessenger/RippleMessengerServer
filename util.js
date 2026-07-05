import rippleKeyPairs from "ripple-keypairs"
import crypto from 'crypto'
import fs from 'fs'
import { NonceMax } from './const.js'

const ConsoleColors = {
  'bright': '\x1B[1m%s\x1B[0m',
  'grey': '\x1B[2m%s\x1B[0m',
  'italic': '\x1B[3m%s\x1B[0m',
  'underline': '\x1B[4m%s\x1B[0m',
  'reverse': '\x1B[7m%s\x1B[0m',
  'hidden': '\x1B[8m%s\x1B[0m',
  'black': '\x1B[30m%s\x1B[0m',
  'red': '\x1B[31m%s\x1B[0m',
  'green': '\x1B[32m%s\x1B[0m',
  'yellow': '\x1B[33m%s\x1B[0m',
  'blue': '\x1B[34m%s\x1B[0m',
  'magenta': '\x1B[35m%s\x1B[0m',
  'cyan': '\x1B[36m%s\x1B[0m',
  'white': '\x1B[37m%s\x1B[0m',
  'blackBG': '\x1B[40m%s\x1B[0m',
  'redBG': '\x1B[41m%s\x1B[0m',
  'greenBG': '\x1B[42m%s\x1B[0m',
  'yellowBG': '\x1B[43m%s\x1B[0m',
  'blueBG': '\x1B[44m%s\x1B[0m',
  'magentaBG': '\x1B[45m%s\x1B[0m',
  'cyanBG': '\x1B[46m%s\x1B[0m',
  'whiteBG': '\x1B[47m%s\x1B[0m'
}

/**
 * Log an informational message in green.
 * @param {string} str - Message to log
 */
function ConsoleInfo(str) {
  console.log(ConsoleColors.green, str)
}

/**
 * Log a warning message in yellow.
 * @param {string} str - Message to log
 */
function ConsoleWarn(str) {
  console.log(ConsoleColors.yellow, str)
}

/**
 * Log an error message in red.
 * @param {string} str - Message to log
 */
function ConsoleError(str) {
  console.log(ConsoleColors.red, str)
}

/**
 * Log a debug message with red background.
 * @param {string} str - Message to log
 */
function ConsoleDebug(str) {
  console.log(ConsoleColors.redBG, str)
}

/**
 * Sleep for the specified number of milliseconds.
 * @param {number} ms - Milliseconds to delay
 * @returns {Promise<void>}
 */
async function DelayExec(ms) {
  return new Promise(resolve => {
    setTimeout(resolve, ms)
  })
}

// server url
const url_regex = /^wss:\/\/(?!-)([a-zA-Z0-9-]+)(?<!-)\.(?!-)([a-zA-Z0-9-]+)(?<!-)\.([a-zA-Z]{2,6})$/

/**
 * Validate a WebSocket server URL against the expected wss:// pattern.
 * @param {string} url - The URL to validate
 * @returns {boolean} True if the URL matches the expected format
 */
function CheckServerURL(url) {
  return url_regex.test(url)
}

// json
/**
 * Deep-clone a JSON-compatible object using structuredClone.
 * @param {*} json - The object to clone
 * @returns {*} A deep copy of the input object
 */
function CloneJson(json) {
  return structuredClone(json)
}

/**
 * Remove duplicate elements from an array. For objects, uses JSON.stringify as the key.
 * @param {Array} arr - Input array possibly containing duplicates
 * @returns {Array} Array with duplicates removed (first occurrence preserved)
 */
function UniqArray(arr) {
  const seen = new Set()
  return arr.filter(item => {
    const key = typeof item === 'object' ? JSON.stringify(item) : item
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

/**
 * Convert an array of strings to a comma-separated quoted string.
 * Elements are appended in reverse order (last element first).
 * @param {string[]} array - Array of strings to join
 * @returns {string} Comma-separated double-quoted string
 */
function Array2Str(array) {
  let tmpArray = []
  for (let i = array.length - 1; i >= 0; i--) {
    tmpArray.push(`"${array[i]}"`)
  }
  return tmpArray.join(',')
}

// crypto
/**
 * Compute the full SHA-512 hash of a string.
 * @param {string} str - Input string to hash
 * @returns {string} 128-character lowercase hex digest
 */
function HasherSHA512(str) {
  let sha512 = crypto.createHash("sha512")
  sha512.update(str)
  return sha512.digest('hex')
}

/**
 * Compute the first 64 hex characters (half) of a SHA-512 hash, uppercase.
 * @param {string} str - Input string to hash
 * @returns {string} 64-character uppercase hex string
 */
function HalfSHA512(str) {
  return HasherSHA512(str).toUpperCase().substring(0, 64)
}

/**
 * Compute the first 32 hex characters (quarter) of a SHA-512 hash, uppercase.
 * @param {string} str - Input string to hash
 * @returns {string} 32-character uppercase hex string
 */
function QuarterSHA512(str) {
  return HasherSHA512(str).toUpperCase().substring(0, 32)
}

/**
 * Compute the first 32 hex characters (quarter) of a SHA-512 hash on the
 * JSON-stringified representation of any value. Used for message hashing.
 * @param {string|object} data - String or object to hash
 * @returns {string} 32-character uppercase hex string
 */
function QuarterSHA512Message(data) {
  const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data)
  return HasherSHA512(dataStr).toUpperCase().substring(0, 32)
}

/**
 * Convert a string to its uppercase hex representation.
 * Each character is converted to its 2-digit hex code point.
 * @param {string} str - Input string
 * @returns {string} Uppercase hex string
 */
function StrToHex(str) {
  let arr = []
  let length = str.length
  for (let i = 0; i < length; i++) {
    arr[i] = (str.charCodeAt(i).toString(16))
  }
  return arr.join('').toUpperCase()
}

/**
 * Read a file from disk and compute its quarter-SHA-512 hash.
 * @param {string} file_path - Absolute or relative path to the file
 * @returns {string|null} 32-character hex hash, or null on read error
 */
function FileReadHash(file_path) {
  let file_content
  try {
    file_content = fs.readFileSync(file_path)
  } catch (err) {
    ConsoleError(err)
    return null
  }
  return QuarterSHA512(file_content)
}

/**
 * Compute the quarter-SHA-512 hash of a Buffer or Uint8Array.
 * @param {Buffer|Uint8Array} buffer - Binary data to hash
 * @returns {string} 32-character uppercase hex hash
 */
function FileBufferHash(buffer) {
  const hash = QuarterSHA512(buffer)
  return hash
}

/**
 * Generate an EdDSA/Ed25519 signature for a string using the XRPL keypairs library.
 * The string is first converted to hex, then signed with the given secret key.
 * @param {string} str - Plain text to sign
 * @param {string} sk - Secret key (hex-encoded)
 * @returns {string} Hex-encoded signature
 */
function GenSignature(str, sk) {
  let strHex = StrToHex(str)
  let sig = rippleKeyPairs.sign(strHex, sk)
  return sig
}

/**
 * Sign a JSON object by computing its quarter-SHA-512 message hash, signing it,
 * and attaching the Signature field. The original object is not mutated.
 * @param {object} json - Object to sign
 * @param {string} sk - Secret key (hex-encoded)
 * @returns {object} New object with all original fields plus a Signature field
 */
function SignJson(json, sk) {
  const json_hash = QuarterSHA512Message(json)
  let sig = rippleKeyPairs.sign(json_hash, sk)
  const signed = { ...json, Signature: sig }
  return signed
}

/**
 * Verify an EdDSA signature on a JSON object. Computes the quarter-SHA-512 hash
 * of the object (excluding the Signature field), then verifies against the
 * PublicKey and Signature fields.
 * @param {object} json - Object with Signature, PublicKey, and arbitrary data fields
 * @returns {boolean} True if the signature is valid for the public key
 */
function VerifyJsonSignature(json) {
  const sig = json.Signature
  const verifyCopy = { ...json }
  delete verifyCopy.Signature
  const json_hash = QuarterSHA512Message(verifyCopy)
  if (rippleKeyPairs.verify(json_hash, sig, json.PublicKey)) {
    return true
  } else {
    ConsoleWarn('json signature invalid...')
    ConsoleWarn(`[SignatureVerify] PublicKey: ${json.PublicKey || 'MISSING'}, Error: signature mismatch`)
    return false
  }
}

/**
 * Generate a random integer in the inclusive range [min, max].
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (inclusive)
 * @returns {number} Random integer between min and max
 */
function GenRandomInt(min, max) {
  min = Math.ceil(min)
  max = Math.floor(max)
  return Math.floor(Math.random() * (max - min + 1)) + min
}

/**
 * Generate a cryptographically random 32-bit nonce in [0, NonceMax].
 * @returns {number} Random unsigned 32-bit integer
 */
function genNonce() {
  return crypto.randomInt(0, NonceMax + 1)
}

/**
 * Calculate the total number of pages given a total count and page size.
 * Rounds up to the next integer.
 * @param {number} total - Total number of items
 * @param {number} page_size - Number of items per page
 * @returns {number} Total number of pages (minimum 0)
 */
function calcTotalPage(total, page_size) {
  let total_page = Math.floor(total / page_size)
  if (total_page !== total / page_size) {
    total_page = total_page + 1
  }
  return total_page
}

/**
 * Convert a 32-bit unsigned integer to a 4-byte Buffer.
 * @param {number} num - Unsigned 32-bit integer (0-4294967295)
 * @param {boolean} [isBigEndian=true] - If true, use big-endian byte order
 * @returns {Buffer|false} 4-byte buffer, or false if num is out of range
 */
function Uint32ToBuffer(num, isBigEndian = true) {
  if (num < 0 || num > 4294967295) {
    return false
  }
  const buf = Buffer.alloc(4)
  if (isBigEndian) {
    buf.writeUInt32BE(num, 0)
  } else {
    buf.writeUInt32LE(num, 0)
  }
  return buf
}

/**
 * Read a 32-bit unsigned integer from a Buffer or Uint8Array.
 * @param {Buffer|Uint8Array} buf - At least 4 bytes of data
 * @param {boolean} [isBigEndian=true] - If true, use big-endian byte order
 * @returns {number} Unsigned 32-bit integer
 */
function BufferToUint32(buf, isBigEndian = true) {
  return isBigEndian
    ? buf.readUInt32BE(0)
    : buf.readUInt32LE(0)
}

/**
 * Shuffle an array using the Fisher-Yates algorithm. Returns a new array,
 * does not mutate the original.
 * @param {Array} arr - Input array to shuffle
 * @returns {Array} New array with elements in random order
 */
function shuffleArray(arr) {
  const newArr = [...arr]
  let len = newArr.length
  while (len > 1) {
    const randomIdx = Math.floor(Math.random() * len)
    len--
    [newArr[len], newArr[randomIdx]] = [newArr[randomIdx], newArr[len]]
  }
  return newArr
}

export {
  ConsoleInfo,
  ConsoleWarn,
  ConsoleError,
  ConsoleDebug,

  GenSignature,
  SignJson,
  VerifyJsonSignature,

  DelayExec,

  CloneJson,
  UniqArray,
  Array2Str,
  CheckServerURL,

  HalfSHA512,
  QuarterSHA512Message,
  StrToHex,
  FileReadHash,
  FileBufferHash,

  genNonce,
  calcTotalPage,
  Uint32ToBuffer,
  BufferToUint32,
  shuffleArray
}
