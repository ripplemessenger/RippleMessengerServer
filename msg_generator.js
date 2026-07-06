import { ActionCode, MessageCode, ObjectType } from './msg_const.js'
import { SignJson } from './util.js'

function GenDeclare(pk, sk, url) {
  let json = {
    Action: ActionCode.Declare,
    URL: url,
    Timestamp: Date.now(),
    PublicKey: pk
  }
  return JSON.stringify(SignJson(json, sk))
}

function GenFileRequest(type, hash, nonce, chunk_cursor, pk, sk) {
  let json = {
    Action: ActionCode.FileRequest,
    FileType: type,
    Hash: hash,
    Nonce: nonce,
    ChunkCursor: chunk_cursor,
    Timestamp: Date.now(),
    PublicKey: pk
  }
  return JSON.stringify(SignJson(json, sk))
}

// ***Avatar***
function GenAvatarRequest(list, pk, sk) {
  let json = {
    Action: ActionCode.AvatarRequest,
    List: list,
    Timestamp: Date.now(),
    PublicKey: pk
  }
  return JSON.stringify(SignJson(json, sk))
}

function GenBulletinRequest(address, sequence, to, pk, sk) {
  let json = {
    Action: ActionCode.BulletinRequest,
    Address: address,
    Sequence: sequence,
    To: to,
    Timestamp: Date.now(),
    PublicKey: pk
  }
  return JSON.stringify(SignJson(json, sk))
}

function GenBulletinRequestByHash(hash, to, pk, sk) {
  let json = {
    Action: ActionCode.BulletinRequest,
    Hash: hash,
    To: to,
    Timestamp: Date.now(),
    PublicKey: pk
  }
  return JSON.stringify(SignJson(json, sk))
}

function GenServerAddressListRequest(page, pk, sk) {
  let json = {
    Action: ActionCode.ServerAddressRequest,
    Page: page,
    Timestamp: Date.now(),
    PublicKey: pk
  }
  return JSON.stringify(SignJson(json, sk))
}

function GenServerAddressList(page, total_page, address_list) {
  let json = {
    ObjectType: ObjectType.ServerAddressList,
    Page: page,
    TotalPage: total_page,
    List: address_list
  }
  return JSON.stringify(json)
}

function GenReplyBulletinList(hash, page, total_page, bulletin_list) {
  let json = {
    ObjectType: ObjectType.ReplyBulletinList,
    Hash: hash,
    Page: page,
    TotalPage: total_page,
    List: bulletin_list
  }
  return JSON.stringify(json)
}

function GenTagBulletinList(tag, page, total_page, bulletin_list) {
  let json = {
    ObjectType: ObjectType.TagBulletinList,
    Tag: tag,
    Page: page,
    TotalPage: total_page,
    List: bulletin_list
  }
  return JSON.stringify(json)
}

function GenRandomBulletinList(bulletin_list) {
  let json = {
    ObjectType: ObjectType.RandomBulletinList,
    List: bulletin_list
  }
  return JSON.stringify(json)
}

// ***Private***
function GenPrivateMessageSync(pair_address, self_sequence, pair_sequence, pk, sk) {
  let json = {
    Action: ActionCode.PrivateMessageSync,
    To: pair_address,
    SelfSequence: self_sequence,
    PairSequence: pair_sequence,
    Timestamp: Date.now(),
    PublicKey: pk,
  }
  return JSON.stringify(SignJson(json, sk))
}

// ***Group***
function GenGroupSync(pk, sk) {
  let json = {
    Action: ActionCode.GroupSync,
    Timestamp: Date.now(),
    PublicKey: pk,
  }
  return JSON.stringify(SignJson(json, sk))
}

// === Control-Plane Generators (unsigned) ===
/**
 * Generate error notification message
 * @param {number} code - MessageCode error code (701-704)
 * @param {string} message - Human-readable error description
 * @returns {string} JSON string
 */
function GenServerNotifyError(code, message) {
  return JSON.stringify({
    ActionCode: ActionCode.ServerNotify,
    MessageCode: code,
    ErrorMessage: message
  })
}

/**
 * Generate info notification message (KickedByNewConn, ServerShutdown, SyncComplete)
 * @param {number} code - MessageCode notification code (710-712)
 * @param {string} [message] - Optional description
 * @returns {string} JSON string
 */
function GenServerNotifyInfo(code, message) {
  let msg = {
    ActionCode: ActionCode.ServerNotify,
    MessageCode: code
  }
  if (message) msg.ErrorMessage = message
  return JSON.stringify(msg)
}

/**
 * Generate cache success confirmation
 * @param {number} code - MessageCode cache code (720/721/723)
 * @returns {string} JSON string
 */
function GenServerNotifyCache(code) {
  return JSON.stringify({
    ActionCode: ActionCode.ServerNotify,
    MessageCode: code
  })
}

/**
 * Generate file transfer progress notification
 * @param {number} code - MessageCode file code (730-732)
 * @param {string} hash - File hash identifier
 * @param {object} [progress] - Optional {ReceivedBytes, TotalBytes}
 * @returns {string} JSON string
 */
function GenServerNotifyFileProgress(code, hash, progress) {
  let msg = {
    ActionCode: ActionCode.ServerNotify,
    MessageCode: code,
    Hash: hash
  }
  if (progress) msg.ProgressInfo = progress
  return JSON.stringify(msg)
}

export {
  GenDeclare,
  GenFileRequest,

  GenAvatarRequest,

  GenBulletinRequest,
  GenBulletinRequestByHash,
  GenServerAddressListRequest,
  GenServerAddressList,
  GenReplyBulletinList,
  GenTagBulletinList,
  GenRandomBulletinList,

  GenPrivateMessageSync,

  GenGroupSync,

  // Control-Plane
  GenServerNotifyError,
  GenServerNotifyInfo,
  GenServerNotifyCache,
  GenServerNotifyFileProgress,
}