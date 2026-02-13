// config
const ConfigPath = './config.json'
// config_json =
// {
//   "SelfURL": "",
//   "NodeList": [
//     {
//       "URL": "wss://jp.ripplemessenger.com"
//     }
//   ]
// }

const NonceMax = 2 ** 32 - 1
const FileChunkSize = 1024 * 1024
const FileMaxSize = 1024 * 1024 * 1024
const BulletinFileExtRegex = /jpg|png|jpeg|txt|md/i

const PageSize = 20

const FileDir = 'file'
const AvatarDir = 'avatar'

const MessageCode = {
  JsonSchemaInvalid: 0, //json schema invalid...
  SignatureInvalid: 1, //signature invalid...
  TimestampInvalid: 2, //timestamp invalid...
  BalanceInsufficient: 3, //balance insufficient...
  NewConnectionOpening: 4, //address changed...
  AddressChanged: 5, //new connection with same address is opening...
  ToSelfIsForbidden: 6, //To self is forbidden...
  ToNotExist: 7, //To not exist...

  GatewayDeclareSuccess: 1000 //gateway declare success...
}

export {
  ConfigPath,
  NonceMax,
  FileChunkSize,
  FileMaxSize,
  BulletinFileExtRegex,
  PageSize,
  FileDir,
  AvatarDir,
  MessageCode
}