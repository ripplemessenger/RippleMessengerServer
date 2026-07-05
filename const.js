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

// Timing constants
const FILE_REQUEST_TTL_MS = 120 * 1000        // 2 min file request expiry
const AVATAR_UPDATE_THROTTLE_MS = 60 * 1000   // 1 min avatar throttle
const DECLARE_TIMESTAMP_TOLERANCE_MS = 60 * 1000  // 1 min clock skew tolerance
const NODE_RECONNECT_INTERVAL_MS = 5000       // 5s node reconnect
const NODE_SYNC_INTERVAL_MS = 5 * 60 * 1000   // 5 min node sync
const FILE_PURGE_INTERVAL_MS = 60 * 1000       // 1 min file request purge timer

export {
  ConfigPath,
  NonceMax,
  FileChunkSize,
  FileMaxSize,
  BulletinFileExtRegex,
  PageSize,
  FileDir,
  AvatarDir,
  FILE_REQUEST_TTL_MS,
  AVATAR_UPDATE_THROTTLE_MS,
  DECLARE_TIMESTAMP_TOLERANCE_MS,
  NODE_RECONNECT_INTERVAL_MS,
  NODE_SYNC_INTERVAL_MS,
  FILE_PURGE_INTERVAL_MS
}