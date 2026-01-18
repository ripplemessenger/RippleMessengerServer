import Ajv from 'ajv'
import { DeclareSchema, BulletinSchema, BulletinRandomRequestSchema, BulletinRequestSchema, BulletinAddressRequestSchema, BulletinAddressListSchema, ReplyBulletinRequestSchema, ECDHHandshakeSchema, PrivateMessageSchema, PrivateMessageSyncSchema, FileRequestSchema, AvatarRequestSchema, GroupMessageSyncSchema, AvatarListSchema, GroupListSchema, GroupSyncSchema, GroupMessageListSchema, BulletinSubscribeSchema, ReplyBulletinListSchema, TagBulletinListSchema, TagBulletinRequestSchema } from './msg_schema.js'
import { ConsoleWarn } from './util.js'
import { ActionCode, ObjectType } from './msg_const.js'

const ajv = new Ajv({ allErrors: true })

const vDeclareSchema = ajv.compile(DeclareSchema)
function checkDeclareSchema(json) {
  try {
    if (vDeclareSchema(json)) {
      return json
    } else {
      ConsoleWarn(`DeclareSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}
const vFileRequestSchema = ajv.compile(FileRequestSchema)
function checkFileRequestSchema(json) {
  try {
    if (vFileRequestSchema(json)) {
      return json
    } else {
      ConsoleWarn(`FileRequestSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

// Avatar
const vAvatarRequestSchema = ajv.compile(AvatarRequestSchema)
function checkAvatarRequestSchema(json) {
  try {
    if (vAvatarRequestSchema(json)) {
      return json
    } else {
      ConsoleWarn(`AvatarRequestSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vAvatarListSchema = ajv.compile(AvatarListSchema)
function checkAvatarListSchema(json) {
  try {
    if (vAvatarListSchema(json)) {
      return json
    } else {
      ConsoleWarn(`AvatarListSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

// Bulletin
const vBulletinSchema = ajv.compile(BulletinSchema)
function checkBulletinSchema(json) {
  try {
    if (vBulletinSchema(json)) {
      return json
    } else {
      ConsoleWarn(`BulletinSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vBulletinSubscribeSchema = ajv.compile(BulletinSubscribeSchema)
function checkBulletinSubscribeSchema(json) {
  try {
    if (vBulletinSubscribeSchema(json)) {
      return json
    } else {
      ConsoleWarn(`BulletinSubscribeSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vBulletinRequestSchema = ajv.compile(BulletinRequestSchema)
function checkBulletinRequestSchema(json) {
  try {
    if (vBulletinRequestSchema(json)) {
      return json
    } else {
      ConsoleWarn(`BulletinRequestSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vBulletinAddressRequestSchema = ajv.compile(BulletinAddressRequestSchema)
function checkBulletinAddressRequestSchema(json) {
  try {
    if (vBulletinAddressRequestSchema(json)) {
      return json
    } else {
      ConsoleWarn(`BulletinAddressRequestSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}
const vBulletinAddressListSchema = ajv.compile(BulletinAddressListSchema)
function checkBulletinAddressListSchema(json) {
  try {
    if (vBulletinAddressListSchema(json)) {
      return json
    } else {
      ConsoleWarn(`BulletinAddressListSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vReplyBulletinRequestSchema = ajv.compile(ReplyBulletinRequestSchema)
function checkReplyBulletinRequestSchema(json) {
  try {
    if (vReplyBulletinRequestSchema(json)) {
      return json
    } else {
      ConsoleWarn(`ReplyBulletinRequestSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}
const vReplyBulletinListSchema = ajv.compile(ReplyBulletinListSchema)
function checkReplyBulletinListSchema(json) {
  try {
    if (vReplyBulletinListSchema(json)) {
      return json
    } else {
      ConsoleWarn(`ReplyBulletinListSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vTagBulletinRequestSchema = ajv.compile(TagBulletinRequestSchema)
function checkTagBulletinRequestSchema(json) {
  try {
    if (vTagBulletinRequestSchema(json)) {
      return json
    } else {
      ConsoleWarn(`TagBulletinRequestSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}
const vTagBulletinListSchema = ajv.compile(TagBulletinListSchema)
function checkTagBulletinListSchema(json) {
  try {
    if (vTagBulletinListSchema(json)) {
      return json
    } else {
      ConsoleWarn(`TagBulletinListSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vBulletinRandomRequestSchema = ajv.compile(BulletinRandomRequestSchema)
function checkBulletinRandomRequestSchema(json) {
  try {
    if (vBulletinRandomRequestSchema(json)) {
      return json
    } else {
      ConsoleWarn(`BulletinRandomRequestSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

// Chat Handshake
const vECDHHandshakeSchema = ajv.compile(ECDHHandshakeSchema)
function checkECDHHandshakeSchema(json) {
  try {
    if (vECDHHandshakeSchema(json)) {
      return json
    } else {
      ConsoleWarn(`ECDHHandshakeSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

// Private
const vPrivateMessageSchema = ajv.compile(PrivateMessageSchema)
function checkPrivateMessageSchema(json) {
  try {
    if (vPrivateMessageSchema(json)) {
      return json
    } else {
      ConsoleWarn(`PrivateMessageSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vPrivateMessageSyncSchema = ajv.compile(PrivateMessageSyncSchema)

// Group
const vGroupSyncSchema = ajv.compile(GroupSyncSchema)
function checkGroupSyncSchema(json) {
  try {
    if (vGroupSyncSchema(json)) {
      return json
    } else {
      ConsoleWarn(`GroupSyncSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

const vGroupListSchema = ajv.compile(GroupListSchema)
function checkGroupListSchema(json) {
  try {
    if (vGroupListSchema(json)) {
      return json
    } else {
      ConsoleWarn(`GroupListSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}
const vGroupMessageSyncSchema = ajv.compile(GroupMessageSyncSchema)
const vGroupMessageListSchema = ajv.compile(GroupMessageListSchema)
function checkGroupMessageListSchema(json) {
  try {
    if (vGroupMessageListSchema(json)) {
      return json
    } else {
      ConsoleWarn(`GroupMessageListSchema invalid...`)
      console.log(json)
      return false
    }
  } catch (e) {
    return false
  }
}

function deriveJson(str) {
  try {
    let json = JSON.parse(str)
    return json
  } catch (e) {
    console.log(`not a json...`)
    return false
  }
}

function MsgValidate(strJson) {
  const json = deriveJson(strJson)
  if (json) {
    if (json.Action) {
      switch (json.Action) {
        case ActionCode.Declare:
          return checkDeclareSchema(json)
        case ActionCode.FileRequest:
          return checkFileRequestSchema(json)
        case ActionCode.AvatarRequest:
          return checkAvatarRequestSchema(json)
        case ActionCode.BulletinRequest:
          return checkBulletinRequestSchema(json)
        case ActionCode.BulletinSubscribe:
          return checkBulletinSubscribeSchema(json)
        case ActionCode.BulletinAddressRequest:
          return checkBulletinAddressRequestSchema(json)
        case ActionCode.ReplyBulletinRequest:
          return checkReplyBulletinRequestSchema(json)
        case ActionCode.TagBulletinRequest:
          return checkTagBulletinRequestSchema(json)
        case ActionCode.BulletinRandomRequest:
          return checkBulletinRandomRequestSchema(json)
        case ActionCode.GroupSync:
          return checkGroupSyncSchema(json)
        default:
          ConsoleWarn(`json schema invalid...`)
          console.log(json)
          return false
      }
    } else if (json.ObjectType) {
      switch (json.ObjectType) {
        case ObjectType.AvatarList:
          return checkAvatarListSchema(json)
        case ObjectType.Bulletin:
          return checkBulletinSchema(json)
        case ObjectType.BulletinAddressList:
          return checkBulletinAddressListSchema(json)
        case ObjectType.ReplyBulletinList:
          return checkReplyBulletinListSchema(json)
        case ObjectType.TagBulletinList:
          return checkTagBulletinListSchema(json)
        case ObjectType.ECDH:
          return checkECDHHandshakeSchema(json)
        case ObjectType.PrivateMessage:
          return checkPrivateMessageSchema(json)
        case ObjectType.GroupList:
          return checkGroupListSchema(json)
        case ObjectType.GroupMessageList:
          return checkGroupMessageListSchema(json)
        default:
          ConsoleWarn(`json schema invalid...`)
          console.log(json)
          return false
      }
    }
  } else {
    return false
  }
}

export {
  MsgValidate
}