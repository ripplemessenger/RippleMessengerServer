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

function ConsoleInfo(str) {
  console.log(ConsoleColors.green, str)
}

function ConsoleWarn(str) {
  console.log(ConsoleColors.yellow, str)
}

function ConsoleError(str) {
  console.log(ConsoleColors.red, str)
}

function ConsoleDebug(str) {
  console.log(ConsoleColors.redBG, str)
}

async function DelayExec(ms) {
  return new Promise(resolve => {
    setTimeout(resolve, ms)
  })
}

// server url
const url_regex = /^wss:\/\/(?!-)([a-zA-Z0-9-]+)(?<!-)\.(?!-)([a-zA-Z0-9-]+)(?<!-)\.([a-zA-Z]{2,6})$/

function CheckServerURL(url) {
  return url_regex.test(url)
}

// json
function CloneJson(json) {
  return JSON.parse(JSON.stringify(json))
}

function UniqArray(arr) {
  return Array.from(new Set(arr))
}

function Array2Str(array) {
  let tmpArray = []
  for (let i = array.length - 1; i >= 0; i--) {
    tmpArray.push(`"${array[i]}"`)
  }
  return tmpArray.join(',')
}

// crypto
function HasherSHA512(str) {
  let sha512 = crypto.createHash("sha512")
  sha512.update(str)
  return sha512.digest('hex')
}

function HalfSHA512(str) {
  return HasherSHA512(str).toUpperCase().substring(0, 64)
}

function QuarterSHA512(str) {
  return HasherSHA512(str).toUpperCase().substring(0, 32)
}

function QuarterSHA512Message(data) {
  const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data)
  return HasherSHA512(dataStr).toUpperCase().substring(0, 32)
}

function StrToHex(str) {
  let arr = []
  let length = str.length
  for (let i = 0; i < length; i++) {
    arr[i] = (str.charCodeAt(i).toString(16))
  }
  return arr.join('').toUpperCase()
}

function FileReadHash(file_path) {
  let file_content
  try {
    file_content = fs.readFileSync(file_path)
  } catch (err) {
    console.error(err)
    return null
  }
  return QuarterSHA512(file_content)
}

function FileBufferHash(buffer) {
  const hash = QuarterSHA512(buffer)
  return hash
}

function GenSignature(str, sk) {
  let strHex = StrToHex(str)
  let sig = rippleKeyPairs.sign(strHex, sk)
  return sig
}

function SignJson(json, sk) {
  const json_hash = QuarterSHA512Message(json)
  let sig = rippleKeyPairs.sign(json_hash, sk)
  json.Signature = sig
  return json
}

function VerifyJsonSignature(json) {
  const sig = json.Signature
  delete json.Signature
  const json_hash = QuarterSHA512Message(json)
  if (rippleKeyPairs.verify(json_hash, sig, json.PublicKey)) {
    json.Signature = sig
    return true
  } else {
    ConsoleWarn('json signature invalid...')
    console.log(json)
    return false
  }
}

function genRandomInt(min, max) {
  min = Math.ceil(min)
  max = Math.floor(max)
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function genNonce() {
  return genRandomInt(0, NonceMax)
}

function calcTotalPage(total, page_size) {
  let total_page = Math.floor(total / page_size)
  if (total_page !== total / page_size) {
    total_page = total_page + 1
  }
  return total_page
}

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
  return buf;
}

function BufferToUint32(buf, isBigEndian = true) {
  return isBigEndian
    ? buf.readUInt32BE(0)
    : buf.readUInt32LE(0)
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
  BufferToUint32
}