//1000*60*60*24=86400000
//const Epoch = Date.parse('2011-11-11 11:11:11')
const Epoch = 1320981071000

const GenesisAddress = 'rBTC99bat6K8LAMWoxSvBxWw3HtVpSQLAV'
//const GenesisHash = QuarterSHA512Message('rBTC99bat6K8LAMWoxSvBxWw3HtVpSQLAV')
const GenesisHash = '44F8764BCACFF5424D4044B784549A1B'

const ActionCode = {
  // common
  Declare: 100,

  // avatar
  AvatarRequest: 200,

  // file
  FileRequest: 300,

  // bulletin
  BulletinRequest: 400,
  BulletinSubscribe: 401,
  RandomBulletinRequest: 402,
  ServerAddressRequest: 403,
  ReplyBulletinRequest: 404,
  TagBulletinRequest: 405,

  // private
  FriendRequest: 500,
  PrivateMessageSync: 501,

  // group
  GroupSync: 600,
  GroupMessageSync: 601
}

const ObjectType = {
  // common
  Nothing: 100,
  ECDH: 101,

  // avatar
  Avatar: 200,
  AvatarList: 201,

  // bulletin
  Bulletin: 400,
  // 401
  // 402
  ServerAddressList: 403,
  ReplyBulletinList: 404,
  TagBulletinList: 405,
  RandomBulletinList: 406,

  // private
  PrivateMessage: 500,

  // group
  GroupCreate: 600,
  GroupDelete: 601,
  GroupList: 602,
  GroupMessage: 603,
  GroupMessageList: 604
}

const FileRequestType = {
  Avatar: 100,
  File: 101,
  PrivateChatFile: 102,
  GroupChatFile: 103
}

const MessageObjectType = {
  NotObject: 100,
  Bulletin: 101,
  PrivateChatFile: 102,
  GroupChatFile: 103
}

// Control-plane: MessageCode (7xx) — server->client, unsigned
const MessageCode = {
  // Error codes (informs reason -> may disconnect): 701-704
  JsonSchemaInvalid: 701,
  SignatureInvalid: 702,
  TimestampInvalid: 703,
  AddressMismatch: 704,

  // Notification codes (informational, no disconnect): 710-712
  KickedByNewConn: 710,
  ServerShutdown: 711,
  SyncComplete: 712,

  // Cache success codes (server local operation confirmation): 720-723
  BulletinCached: 720,
  PrivateMsgCached: 721,
  HandshakeCached: 723,

  // File transfer progress: 730-732
  FileChunkReceived: 730,
  FileTransferComplete: 731,
  FileTransferFailed: 732
}

// Control-plane ActionCode extensions (8xx) — unsigned, server-initiated or client ack
ActionCode.ServerNotify = 800
ActionCode.ServerNotifyAckReq = 801
ActionCode.ClientAck = 810

export {
  Epoch,
  GenesisAddress,
  GenesisHash,

  ActionCode,
  ObjectType,
  FileRequestType,
  MessageObjectType,
  MessageCode
}