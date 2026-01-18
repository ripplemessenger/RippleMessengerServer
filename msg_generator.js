import { ActionCode, ObjectType } from './msg_const.js'
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

function GenBulletinAddressListRequest(page, pk, sk) {
  let json = {
    Action: ActionCode.BulletinAddressListRequest,
    Page: page,
    Timestamp: Date.now(),
    PublicKey: pk
  }
  return JSON.stringify(SignJson(json, sk))
}

function GenBulletinAddressList(page, total_page, address_list) {
  let json = {
    ObjectType: ObjectType.BulletinAddressList,
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

// ***Private***
function GenPrivateMessageSync(pair_address, current_sequence, pk, sk) {
  let json = {
    Action: ActionCode.ChatMessageSyncFromServer,
    PairAddress: pair_address,
    CurrentSequence: current_sequence,
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

export {
  GenDeclare,
  GenFileRequest,

  GenAvatarRequest,

  GenBulletinRequest,
  GenBulletinAddressListRequest,
  GenBulletinAddressList,
  GenReplyBulletinList,
  GenTagBulletinList,

  GenPrivateMessageSync,

  GenGroupSync,
}