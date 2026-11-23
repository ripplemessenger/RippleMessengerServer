import rippleKeyPairs from "ripple-keypairs"
import crypto from 'crypto'
import fs from 'fs'
import { NonceMax } from './const.js'

// 日志时间戳：HH:MM:SS.mmm（本地时区），用于量每条 bulletin 的间隔。
function ts(): string {
  const d = new Date()
  const p = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
}

const ConsoleColors: Record<string, string> = {
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
 */
function ConsoleInfo(str: unknown) {
  console.log(ConsoleColors.green, `[${ts()}]`, str)
}

/**
 * Log a warning message in yellow.
 */
function ConsoleWarn(str: unknown) {
  console.log(ConsoleColors.yellow, `[${ts()}]`, str)
}

/**
 * Log an error message in red.
 */
function ConsoleError(str: unknown) {
  console.log(ConsoleColors.red, `[${ts()}]`, str)
}

/**
 * Log a debug message with red background.
 *
 * Debug output is off by default: the node-sync workload produced ~11k
 * `[sendTo]` lines per 10 minutes, and console I/O is synchronous, so it
 * measurably slowed message handling. Set `RMS_DEBUG=1` to turn it back on.
 */
function ConsoleDebug(str: unknown) {
  if (!process.env.RMS_DEBUG) return
  console.log(ConsoleColors.redBG, `[${ts()}]`, str)
}

/**
 * Sleep for the specified number of milliseconds.
 */
async function DelayExec(ms: number): Promise<void> {
  return new Promise(resolve => {
    setTimeout(resolve, ms)
  })
}

// server url
const url_regex = /^wss:\/\/(?!-)([a-zA-Z0-9-]+)(?<!-)\.(?!-)([a-zA-Z0-9-]+)(?<!-)\.([a-zA-Z]{2,6})$/

/**
 * Validate a WebSocket server URL against the expected wss:// pattern.
 */
function CheckServerURL(url: string): boolean {
  return url_regex.test(url)
}

// json
/**
 * Deep-clone a JSON-compatible object using structuredClone.
 */
function CloneJson<T>(json: T): T {
  return structuredClone(json)
}

/**
 * Remove duplicate elements from an array. For objects, uses JSON.stringify as the key.
 */
function UniqArray(arr: unknown[]): unknown[] {
  const seen = new Set<unknown>()
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
 */
function Array2Str(array: string[]): string {
  let tmpArray = []
  for (let i = array.length - 1; i >= 0; i--) {
    tmpArray.push(`"${array[i]}"`)
  }
  return tmpArray.join(',')
}

// crypto
/**
 * Compute the full SHA-512 hash of a string.
 */
function HasherSHA512(str: string | Buffer | Uint8Array): string {
  let sha512 = crypto.createHash("sha512")
  sha512.update(str)
  return sha512.digest('hex')
}

/**
 * Compute the first 64 hex characters (half) of a SHA-512 hash, uppercase.
 */
function HalfSHA512(str: string | Buffer | Uint8Array): string {
  return HasherSHA512(str).toUpperCase().substring(0, 64)
}

/**
 * Compute the first 32 hex characters (quarter) of a SHA-512 hash, uppercase.
 */
function QuarterSHA512(str: string | Buffer | Uint8Array): string {
  return HasherSHA512(str).toUpperCase().substring(0, 32)
}

/**
 * Compute the first 32 hex characters (quarter) of a SHA-512 hash on the
 * JSON-stringified representation of any value. Used for message hashing.
 */
function QuarterSHA512Message(data: string | Record<string, unknown>): string {
  const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data)
  return HasherSHA512(dataStr).toUpperCase().substring(0, 32)
}

/**
 * Read a file from disk and compute its quarter-SHA-512 hash.
 *
 * Streams the file instead of using fs.readFileSync: this runs on the Node
 * event loop shared by every WebSocket connection, so a synchronous read of a
 * large attachment would stall all client traffic (and spike memory) for the
 * duration of the read + hash.
 */
function FileReadHash(file_path: string): Promise<string | null> {
  return new Promise((resolve) => {
    const hasher = crypto.createHash('sha512')
    const stream = fs.createReadStream(file_path)
    stream.on('error', (err) => {
      ConsoleError(err)
      resolve(null)
    })
    stream.on('data', (chunk) => hasher.update(chunk))
    stream.on('end', () => resolve(hasher.digest('hex').toUpperCase().substring(0, 32)))
  })
}

/**
 * Compute the quarter-SHA-512 hash of a Buffer or Uint8Array.
 */
function FileBufferHash(buffer: Buffer | Uint8Array): string {
  const hash = QuarterSHA512(buffer)
  return hash
}

/**
 * Sign a JSON object by computing its quarter-SHA-512 message hash, signing it,
 * and attaching the Signature field. The original object is not mutated.
 */
function SignJson(json: Record<string, unknown>, sk: string): Record<string, unknown> {
  const json_hash = QuarterSHA512Message(json)
  let sig = rippleKeyPairs.sign(json_hash, sk)
  const signed = { ...json, Signature: sig }
  return signed
}

/**
 * Verify an EdDSA signature on a JSON object. Computes the quarter-SHA-512 hash
 * of the object (excluding the Signature field), then verifies against the
 * PublicKey and Signature fields.
 */
function VerifyJsonSignature(json: Record<string, unknown>): boolean {
  const sig = json.Signature
  const verifyCopy = { ...json }
  delete verifyCopy.Signature
  const json_hash = QuarterSHA512Message(verifyCopy)
  if (rippleKeyPairs.verify(json_hash, sig as string, json.PublicKey as string)) {
    return true
  } else {
    ConsoleWarn('json signature invalid...')
    ConsoleWarn(`[SignatureVerify] PublicKey: ${json.PublicKey || 'MISSING'}, Error: signature mismatch`)
    return false
  }
}

/**
 * Generate a cryptographically random 32-bit nonce in [0, NonceMax].
 */
function genNonce(): number {
  return crypto.randomInt(0, NonceMax + 1)
}

/**
 * Calculate the total number of pages given a total count and page size.
 * Rounds up to the next integer.
 */
function calcTotalPage(total: number, page_size: number): number {
  let total_page = Math.floor(total / page_size)
  if (total_page !== total / page_size) {
    total_page = total_page + 1
  }
  return total_page
}

/**
 * Convert a 32-bit unsigned integer to a 4-byte Buffer.
 */
function Uint32ToBuffer(num: number, isBigEndian = true): Buffer | false {
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
 * The runtime value at the sole call site is a Buffer (V8's TypedArray.slice
 * preserves the constructor), so readUInt32BE/LE are available.
 */
function BufferToUint32(buf: Buffer | Uint8Array, isBigEndian = true): number {
  return isBigEndian
    ? (buf as Buffer).readUInt32BE(0)
    : (buf as Buffer).readUInt32LE(0)
}

/**
 * Shuffle an array using the Fisher-Yates algorithm. Returns a new array,
 * does not mutate the original.
 */
function shuffleArray(arr: unknown[]): unknown[] {
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

  SignJson,
  VerifyJsonSignature,

  DelayExec,

  CloneJson,
  UniqArray,
  Array2Str,
  CheckServerURL,

  HalfSHA512,
  QuarterSHA512Message,
  FileReadHash,
  FileBufferHash,

  genNonce,
  calcTotalPage,
  Uint32ToBuffer,
  BufferToUint32,
  shuffleArray
}
