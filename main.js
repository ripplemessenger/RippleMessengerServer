import fs from 'fs'
import path from 'path'
import { WebSocket, WebSocketServer } from 'ws'
import rippleKeyPairs from "ripple-keypairs"
import { PrismaClient } from "@prisma/client"
const prisma = new PrismaClient()

import { ConsoleInfo, ConsoleWarn, ConsoleError, ConsoleDebug, DelayExec, FileReadHash, QuarterSHA512Message, UniqArray, CheckServerURL, genNonce, FileBufferHash, BufferToUint32, Uint32ToBuffer, VerifyJsonSignature, calcTotalPage } from './util.js'
import { ActionCode, ObjectType, GenesisHash, FileRequestType, Epoch } from './msg_const.js'
import { ConfigPath, FileChunkSize, PageSize } from './const.js'
import { GenDeclare, GenBulletinAddressListRequest, GenBulletinRequest, GenPrivateMessageSync, GenFileRequest, GenAvatarRequest, GenGroupSync, GenBulletinAddressList, GenReplyBulletinList, GenTagBulletinList } from './msg_generator.js'
import { MsgValidate } from './msg_validator.js'

let SelfURL = undefined
let SelfAddress
let SelfPublicKey
let SelfPrivateKey

let NodeList = []
// client server daemon
let ServerDaemon = null
// client and node connection
let Conns = {}
// node conn
let jobNodeConn = null
let jobNodeSync = null
let NodeConns = {}

let FileRequestList = []
let ChatFileRequestList = []

let GroupMap = {}
let SubscribeMap = {}

// keep alive
process.on("uncaughtException", function (err) {
  ConsoleError(err)
  ConsoleError(err.stack)
})

// TODO: server msg
// function sendServerMessage(ws, msgCode) {
//   ws.send(strServerMessage(msgCode))
// }

function fetchConnAddress(ws) {
  for (let address in Conns) {
    if (Conns[address] === ws) {
      return address
    }
  }
  return null
}

function fetchNodeConnURL(ws) {
  for (let url in NodeConns) {
    if (NodeConns[url] === ws) {
      return url
    }
  }
  return null
}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//client listener
function teminateConn(ws) {
  ws.close()
  let connAddress = fetchConnAddress(ws)
  if (connAddress != null) {
    ConsoleWarn(`###################LOG################### client disconnect... <${connAddress}>`)
    delete Conns[connAddress]
  }

  let url = fetchNodeConnURL(ws)
  if (url != null) {
    ConsoleWarn(`###################LOG################### server disconnect... <${connAddress}>`)
    delete NodeConns[url]
  }
}

// file

function genFileNonce() {
  let nonce = genNonce()
  for (let i = 0; i < FileRequestList.length; i++) {
    const r = FileRequestList[i];
    if (r.Nonce === nonce) {
      return genFileNonce()
    }
  }
  return nonce
}

function fetchAvatarFile(from, address, hash) {
  let nonce = genFileNonce()
  let tmp = {
    Type: FileRequestType.Avatar,
    Nonce: nonce,
    Hash: hash,
    Address: address,
    Timestamp: Date.now()
  }
  FileRequestList.push(tmp)
  let msg = GenFileRequest(FileRequestType.Avatar, hash, nonce, 1, SelfPublicKey, SelfPrivateKey)
  SendMessage(from, msg)
}

function fetchFile(from, address, hash, chunk_cursor) {
  let nonce = genFileNonce()
  let tmp = {
    Type: FileRequestType.File,
    Nonce: nonce,
    Hash: hash,
    ChunkCursor: chunk_cursor,
    Address: address,
    Timestamp: Date.now()
  }
  let prev_request = FileRequestList.filter(r => r.Hash === hash)
  if (prev_request.length === 0) {
    FileRequestList.push(tmp)
    let msg = GenFileRequest(FileRequestType.File, hash, nonce, chunk_cursor, SelfPublicKey, SelfPrivateKey)
    SendMessage(from, msg)
  }
}

function fetchChatFile(from, json) {
  let tmp = {
    Type: FileRequestType.ChatFile,
    Nonce: json.Nonce,
    From: from,
    // To: json.To,
    Hash: json.Hash,
    // ChunkCursor: json.ChunkCursor,
    Timestamp: json.Timestamp
  }
  let prev_request = FileRequestList.filter(r => r.Hash === json.Hash)
  if (prev_request.length === 0) {
    FileRequestList.push(tmp)
  } else if (json.Timestamp > prev_request[0].Timestamp) {
    FileRequestList = FileRequestList.filter(r => r.Hash !== json.Hash)
    FileRequestList.push(tmp)
  }
}

async function saveBufferFile(request, content) {
  switch (request.Type) {
    case FileRequestType.Avatar:
      const content_hash = FileBufferHash(content)
      if (request.Hash === content_hash) {
        let avatar_dir = `./AvatarFile/${request.Address.substring(1, 4)}/${request.Address.substring(4, 7)}`
        fs.mkdirSync(path.resolve(avatar_dir), { recursive: true })
        let avatar_path = `${avatar_dir}/${request.Address}.png`
        fs.writeFile(avatar_path, content, async (err) => {
          if (err) {
            console.log(err.message)
            return
          }
          console.log(FileRequestList)
          FileRequestList = FileRequestList.filter(r => r.Nonce !== request.Nonce)
          console.log(FileRequestList)
          await prisma.Avatar.update({
            where: {
              address: request.Address
            },
            data: {
              is_saved: true
            }
          })
        })
      }
      break
    case FileRequestType.File:
      console.log(request)
      let file_dir = `./File/${request.Hash.substring(0, 3)}/${request.Hash.substring(3, 6)}`
      fs.mkdirSync(path.resolve(file_dir), { recursive: true })
      let file_path = `${file_dir}/${request.Hash}`
      let file = await prisma.File.findFirst({
        where: {
          AND: {
            hash: request.Hash,
            is_saved: false
          }
        },
        select: {
          size: true,
          chunk_length: true,
          chunk_cursor: true,
          is_saved: true
        }
      })
      if (file !== null) {
        if (file.chunk_cursor === file.chunk_length) {
          console.log(file)
          fs.rmSync(path.resolve(file_path))
          await prisma.File.update({
            where: {
              hash: request.Hash
            },
            data: {
              chunk_cursor: 0
            }
          })
          fetchFile(request.Address, request.Address, request.Hash, 1)
        } else if (file.chunk_cursor < file.chunk_length && file.chunk_cursor + 1 === request.ChunkCursor) {
          fs.appendFile(file_path, content, async (err) => {
            if (err) {
              console.log(err.message)
              return
            }
            FileRequestList = FileRequestList.filter(r => r.Nonce !== request.Nonce)
            let current_chunk_cursor = file.chunk_cursor + 1
            await prisma.File.update({
              where: {
                hash: request.Hash
              },
              data: {
                chunk_cursor: current_chunk_cursor,
                updated_at: Date.now()
              }
            })
            if (current_chunk_cursor < file.chunk_length) {
              fetchFile(request.Address, request.Address, request.Hash, current_chunk_cursor + 1)
            } else {
              let hash = FileReadHash(path.resolve(file_path))
              if (hash !== request.Hash) {
                fs.rmSync(path.resolve(file_path))
                await prisma.File.update({
                  where: {
                    hash: request.Hash
                  },
                  data: {
                    chunk_cursor: 0
                  }
                })
                fetchFile(request.Address, request.Address, request.Hash, 1)
              } else {
                await prisma.File.update({
                  where: {
                    hash: request.Hash
                  },
                  data: {
                    is_saved: true
                  }
                })
              }
            }
          })
        }
      }
      break
    default:
      break
  }
}

async function HandelFileRequest(request, from) {
  // send cache file
  switch (request.FileType) {
    case FileRequestType.Avatar:
      let avatar = await prisma.Avatar.findFirst({
        where: {
          hash: request.Hash
        },
        select: {
          address: true
        }
      })
      let avatar_file_path = path.resolve(`./AvatarFile/${avatar.address.substring(1, 4)}/${avatar.address.substring(4, 7)}/${avatar.address}.png`)
      let buffer = fs.readFileSync(avatar_file_path)
      const nonce = Uint32ToBuffer(request.Nonce)
      SendMessage(from, Buffer.concat([nonce, buffer]))
      break;
    case FileRequestType.File:
      let file = await prisma.File.findFirst({
        where: {
          AND: {
            hash: request.Hash,
            is_saved: true
          }
        },
        select: {
          size: true,
          chunk_length: true,
          chunk_cursor: true
        }
      })
      if (file !== null && file.chunk_cursor === file.chunk_length) {
        let start = (request.ChunkCursor - 1) * FileChunkSize
        let file_left = file.size - start
        let length = Math.min(FileChunkSize, file_left)
        let file_path = path.resolve(`./File/${request.Hash.substring(0, 3)}/${request.Hash.substring(3, 6)}/${request.Hash}`)
        fs.open(file_path, 'r', async (err, fd) => {
          if (err) return console.error(err)
          const buffer = Buffer.alloc(length)
          fs.read(fd, buffer, 0, length, start, (err, bytesRead, readBuffer) => {
            if (err) {
              console.error(err)
              return
            }
            if (bytesRead > 0) {
              const chunk = Uint8Array.prototype.slice.call(readBuffer, 0, bytesRead)
              // const chunk = readBuffer.slice(0, bytesRead)
              const nonce = Uint32ToBuffer(request.Nonce)
              SendMessage(from, Buffer.concat([nonce, chunk]))
            }
            fs.close(fd, (err) => {
              if (err) return console.error(err)
            })
          })
        })
      }
      break
    case FileRequestType.ChatFile:
      // already forword, save relay info
      fetchChatFile(from, request)
      break
    default:
      break
  }
}

// avatar
async function CacheAvatar(from, avatar) {
  let timestamp = Date.now()
  let avatar_address = rippleKeyPairs.deriveAddress(avatar.PublicKey)
  if (avatar.Hash !== GenesisHash) {
    fetchAvatarFile(from, avatar_address, avatar.Hash)
  }

  let db_a = await prisma.Avatar.findFirst({
    where: {
      address: avatar_address
    }
  })
  if (db_a === null) {
    let result = await prisma.Avatar.create({
      data: {
        address: avatar_address,
        hash: avatar.Hash,
        size: avatar.Size,
        signed_at: avatar.Timestamp,
        json: JSON.stringify(avatar),
        is_saved: false
      }
    })

    // if (result) {
    //   //Brocdcast to NodeList
    //   for (let i in NodeList) {
    //     let msg = GenObjectResponse(avatar, NodeList[i].Address, SelfPublicKey, SelfPrivateKey)
    //     SendMessage(NodeList[i].Address, msg)
    //   }
    // }
  } else if (avatar.Timestamp > db_a.signed_at && db_a.signed_at < timestamp - 60 * 1000 && avatar.Hash !== db_a.hash) {
    let result = await prisma.Avatar.update({
      where: {
        address: avatar_address
      },
      data: {
        hash: avatar.Hash,
        size: avatar.Size,
        signed_at: avatar.Timestamp,
        json: JSON.stringify(avatar),
        is_saved: false
      }
    })
  } else {
    // update too fast, do nothing
  }
}

async function HandelAvatarReqeust(request, from) {
  let new_list = []
  let old_list = []
  for (let i = 0; i < request.List.length; i++) {
    const avatar = request.List[i]
    let db_avatar = await prisma.Avatar.findFirst({
      where: {
        address: avatar.Address
      },
      select: {
        signed_at: true,
        json: true
      }
    })

    if (db_avatar !== null) {
      if (db_avatar.signed_at > avatar.SignedAt) {
        new_list.push(JSON.parse(db_avatar.json))
      } else if (db_avatar.signed_at < avatar.SignedAt) {
        old_list.push({ Address: avatar.Address, SignedAt: db_avatar.signed_at })
      }
    } else if (avatar.SignedAt !== Epoch) {
      old_list.push({ Address: avatar.Address, SignedAt: Epoch })
    }
  }
  if (new_list.length > 0) {
    let avatar_response = {
      ObjectType: ObjectType.AvatarList,
      List: new_list
    }
    SendMessage(from, JSON.stringify(avatar_response))
  }
  if (old_list.length > 0) {
    let msg = GenAvatarRequest(old_list, SelfPublicKey, SelfPrivateKey)
    SendMessage(from, msg)
  }
}

async function BindBulletinTag(bulletin_hash, tags) {
  return await prisma.Bulletin.update({
    where: { hash: bulletin_hash },
    data: {
      tags: {
        connectOrCreate: tags.map(name => ({
          where: { name: name },
          create: { name: name }
        }))
      }
    },
    include: { tags: true }
  })
}

async function BindBulletinFile(bulletin_hash, files) {
  let result = await prisma.Bulletin.update({
    where: { hash: bulletin_hash },
    data: {
      files: {
        connectOrCreate: files.map(file => ({
          where: { hash: file.Hash },
          create: {
            hash: file.Hash,
            size: file.Size,
            chunk_length: Math.ceil(file.Size / FileChunkSize),
            chunk_cursor: 0,
            updated_at: Date.now(),
            is_saved: false
          }
        }))
      }
    },
    include: { files: true }
  })
  if (result.files.length > 0) {
    return result.files
  } else {
    return []
  }
}

// bulletin
async function CacheBulletin(from, bulletin) {
  let timestamp = Date.now()
  let hash = QuarterSHA512Message(bulletin)
  let bulletin_address = rippleKeyPairs.deriveAddress(bulletin.PublicKey)

  let b = await prisma.Bulletin.findFirst({
    where: {
      address: bulletin_address,
      sequence: bulletin.Sequence
    }
  })
  if (b === null) {
    let result = await prisma.Bulletin.create({
      data: {
        hash: hash,
        pre_hash: bulletin.PreHash,
        address: bulletin_address,
        sequence: bulletin.Sequence,
        content: bulletin.Content,
        json: JSON.stringify(bulletin),
        signed_at: bulletin.Timestamp,
        created_at: timestamp
      }
    })
    if (result) {
      if (result.sequence !== 1) {
        try {
          //update pre_bulletin's next_hash
          result = await prisma.Bulletin.update({
            where: {
              hash: bulletin.PreHash
            },
            data: {
              next_hash: hash
            }
          })
        } catch (error) {
          console.log(error)
        }
      }

      // create tag
      if (bulletin.Tag) {
        result = await BindBulletinTag(hash, bulletin.Tag)
      }

      // create quote
      if (bulletin.Quote) {
        bulletin.Quote.forEach(async quote => {
          result = await prisma.Reply.findFirst({
            where: {
              post_hash: quote.Hash,
              reply_hash: hash
            }
          })
          if (!result) {
            result = await prisma.Reply.create({
              data: {
                post_hash: quote.Hash,
                reply_hash: hash,
                signed_at: bulletin.Timestamp
              }
            })
          }
        })
      }

      // create file
      if (bulletin.File) {
        let files_to_fetch = await BindBulletinFile(hash, bulletin.File)
        files_to_fetch.forEach(file => {
          fetchFile(from, bulletin_address, file.hash, file.chunk_cursor + 1)
        })
      }

      // send to subscribers
      if (SubscribeMap[from] && SubscribeMap[from].length > 0) {
        for (let i = 0; i < SubscribeMap[from].length; i++) {
          const subscriber = SubscribeMap[from][i]
          SendMessage(subscriber, JSON.stringify(bulletin))
        }
      }

      //Brocdcast to NodeList
      // for (let i in NodeList) {
      //   let msg = GenObjectResponse(bulletin, NodeList[i].Address, SelfPublicKey, SelfPrivateKey)
      //   SendMessage(NodeList[i].Address, msg)
      // }
    }
  }
}

function HandelBulletinSubscribe(request, from) {
  Object.entries(SubscribeMap).forEach(([key, value]) => {
    let new_value = value.filter(a => a !== from)
    SubscribeMap[key] = new_value
  })
  for (let i = 0; i < request.List.length; i++) {
    const subscribe_address = request.List[i]
    if (subscribe_address !== from) {
      let new_value = []
      if (SubscribeMap[subscribe_address] !== undefined) {
        new_value = SubscribeMap[subscribe_address]
      }
      new_value.push(from)
      SubscribeMap[subscribe_address] = new_value
    }
  }
}

// ecdh
async function CacheECDH(json) {
  let address1 = ""
  let address2 = ""
  let json1 = ""
  let json2 = ""
  let sour_address = rippleKeyPairs.deriveAddress(json.PublicKey)
  let dest_address = json.To
  if (sour_address > dest_address) {
    address1 = sour_address
    address2 = dest_address
    json1 = JSON.stringify(json)
  } else {
    address1 = dest_address
    address2 = sour_address
    json2 = JSON.stringify(json)
  }

  let dh = await prisma.ECDH.findFirst({
    where: {
      address1: address1,
      address2: address2,
      partition: json.Partition,
      sequence: json.Sequence
    }
  })
  if (dh === null) {
    if (json1 != "") {
      await prisma.ECDH.create({
        data: {
          address1: address1,
          address2: address2,
          partition: json.Partition,
          sequence: json.Sequence,
          json1: json1,
          json2: ""
        }
      })
    } else if (json2 != "") {
      await prisma.ECDH.create({
        data: {
          address1: address1,
          address2: address2,
          partition: json.Partition,
          sequence: json.Sequence,
          json1: "",
          json2: json2
        }
      })
    }
  } else {
    if (json1 != "") {
      if (dh.json1 != "") {
        let old_json1 = JSON.parse(dh.json1)
        if (json.Timestamp >= old_json1.Timestamp) {
          return
        }
      }
      await prisma.ECDH.update({
        where: {
          address1_address2_partition_sequence: {
            address1: address1,
            address2: address2,
            partition: json.Partition,
            sequence: json.Sequence
          }
        },
        data: {
          json1: json1
        }
      })
    } else if (json2 != "") {
      if (dh.json2 != "") {
        let old_json2 = JSON.parse(dh.json2)
        if (json.Timestamp >= old_json2.Timestamp) {
          return
        }
      }
      await prisma.ECDH.update({
        where: {
          address1_address2_partition_sequence: {
            address1: address1,
            address2: address2,
            partition: json.Partition,
            sequence: json.Sequence
          }
        },
        data: {
          json2: json2
        }
      })
    }
  }
}

async function HandelECDHSync(json) {
  let address1 = ""
  let address2 = ""
  let sour_address = rippleKeyPairs.deriveAddress(json.PublicKey)
  let dest_address = json.To
  if (sour_address > dest_address) {
    address1 = sour_address
    address2 = dest_address
  } else {
    address1 = dest_address
    address2 = sour_address
  }

  let dh = await prisma.ECDH.findFirst({
    where: {
      address1: address1,
      address2: address2,
      partition: json.Partition,
      sequence: json.Sequence
    },
    select: {
      json1: true,
      json2: true
    }
  })
  if (dh != null && json.Pair === "") {
    if (address1 === sour_address && dh.json2 != "") {
      SendMessage(sour_address, dh.json2)
    } else if (address2 === sour_address && dh.json1 != "") {
      SendMessage(sour_address, dh.json1)
    }
  }
}

// private
async function CachePrivateMessage(json) {
  let str_json = JSON.stringify(json)
  let hash = QuarterSHA512(json)
  let sour_address = rippleKeyPairs.deriveAddress(json.PublicKey)
  let dest_address = json.To
  let msg_list = await prisma.PrivateMessage.findMany({
    where: {
      sour_address: sour_address,
      dest_address: dest_address,
      sequence: {
        lt: json.Sequence
      }
    },
    orderBy: {
      sequence: "asc"
    },
    select: {
      sequence: true,
      hash: true
    }
  })
  let msg_list_length = msg_list.length
  if ((msg_list_length === 0 && json.Sequence === 1 && json.PreHash === GenesisHash) || (msg_list_length != 0 && msg_list_length === msg_list[msg_list_length - 1].sequence && json.Sequence === msg_list_length + 1 && json.PreHash === msg_list[msg_list_length - 1].hash)) {
    await prisma.PrivateMessage.create({
      data: {
        hash: hash,
        sour_address: sour_address,
        dest_address: dest_address,
        sequence: json.Sequence,
        signed_at: json.Timestamp,
        json: str_json
      }
    })
  } else {
    let current_sequence = 0
    if (msg_list_length != 0) {
      current_sequence = msg_list_length
    }
    let msg = GenPrivateMessageSync(dest_address, current_sequence, SelfPublicKey, SelfPrivateKey)
    SendMessage(sour_address, msg)
  }
}

async function HandelPrivateMessageSync(json) {
  let from_address = rippleKeyPairs.deriveAddress(json.PublicKey)
  let msg_list = await prisma.PrivateMessage.findMany({
    where: {
      OR: [
        {
          sour_address: from_address,
          dest_address: json.To,
          sequence: {
            gt: json.SelfSequence
          }
        },
        {
          sour_address: json.To,
          dest_address: from_address,
          sequence: {
            gt: json.PairSequence
          }
        }
      ]
    },
    select: {
      json: true
    },
    orderBy: {
      sequence: "asc"
    }
  })
  let msg_list_length = msg_list.length
  for (let i = 0; i < msg_list_length; i++) {
    await DelayExec(1000)
    SendMessage(from_address, msg_list[i].json)
  }
}

// group
async function HandelGroupSync(from) {
  let group_hash_list = []
  Object.entries(GroupMap).forEach(([hash, member]) => {
    if (member.includes(from)) {
      group_hash_list.push(hash)
    }
  })
  if (group_hash_list.length > 0) {
    let group_list = await prisma.Group.findMany({
      where: {
        hash: {
          in: group_hash_list
        }
      },
      select: {
        create_json: true,
        delete_json: true
      }
    })
    let group_create_json_list = []
    for (let i = 0; i < group_list.length; i++) {
      const group = group_list[i]
      if (group.delete_json !== null) {
        group_create_json_list.push(JSON.parse(group.delete_json))
      } else {
        group_create_json_list.push(JSON.parse(group.create_json))
      }
    }
    let group_response = {
      ObjectType: ObjectType.GroupList,
      List: group_create_json_list
    }
    SendMessage(from, JSON.stringify(group_response))
  }
}

async function CacheGroup(group) {
  let address = rippleKeyPairs.deriveAddress(group.PublicKey)

  let db_g = await prisma.Group.findFirst({
    where: {
      hash: group.Hash
    }
  })

  if (group.ObjectType === ObjectType.GroupDelete) {
    if (db_g !== null && db_g.deleted_at === null) {
      let result = await prisma.Group.update({
        where: {
          hash: group.Hash
        },
        data: {
          deleted_at: group.Timestamp,
          delete_json: JSON.stringify(group)
        }
      })
      if (result > 0) {
        delete GroupMap[group.Hash]
      }
    }
  } else if (group.ObjectType === ObjectType.GroupCreate) {
    if (db_g === null) {
      let result = await prisma.Group.create({
        data: {
          hash: group.Hash,
          created_by: address,
          member: JSON.stringify(group.Member),
          created_at: group.Timestamp,
          create_json: JSON.stringify(group)
        }
      })

      if (result) {
        let members = group.Member
        members.push(address)
        GroupMap[group.Hash] = members
      }
    }
  }
}

// send
function SendMessage(address, message) {
  // ConsoleInfo(`###################LOG################### Send Message:`)
  // ConsoleWarn(message)
  if (Conns[address] != null && Conns[address].readyState === WebSocket.OPEN) {
    Conns[address].send(message)
  }
}

// handle Object
async function handleObject(from, message, json) {
  if (json.To != null) {
    // forward message
    SendMessage(json.To, message)
  }

  switch (json.ObjectType) {
    case ObjectType.Bulletin:
      if (VerifyJsonSignature(json)) {
        CacheBulletin(from, json)
        //fetch more bulletin
        let address = rippleKeyPairs.deriveAddress(json.PublicKey)
        let next_bulletin = await prisma.Bulletin.findFirst({
          where: {
            address: address,
            sequence: json.Sequence + 1
          }
        })
        if (next_bulletin === null) {
          let msg = GenBulletinRequest(address, json.Sequence + 1, address, SelfPublicKey, SelfPrivateKey)
          SendMessage(from, msg)
        }
      }
      break
    case ObjectType.BulletinAddressList:
      // >>>>>>>>>>>>>>>>
      // Node Interaction
      // pull step 2: fetch account latest bulletin
      let items = json.List
      for (let i = 0; i < items.length; i++) {
        await DelayExec(1000)
        const item = items[i]
        let bulletin = await prisma.Bulletin.findFirst({
          where: {
            address: item.Address
          },
          select: {
            sequence: true
          },
          orderBy: {
            sequence: "desc"
          }
        })
        let next_sequence = 1
        if (bulletin) {
          next_sequence = bulletin.sequence + 1
          if (bulletin.sequence < item.Count) {
            let bulletin_req = GenBulletinRequest(item.Address, next_sequence, from, SelfPublicKey, SelfPrivateKey)
            SendMessage(from, bulletin_req)
          } else if (bulletin.sequence > item.Count) {
            bulletin = await prisma.Bulletin.findFirst({
              where: {
                AND: {
                  address: item.Address,
                  sequence: item.Count + 1
                }
              },
              select: {
                json: true
              }
            })
            if (bulletin) {
              SendMessage(from, bulletin.json)
            }
          }
        } else {
          let bulletin_req = GenBulletinRequest(item.Address, next_sequence, from, SelfPublicKey, SelfPrivateKey)
          SendMessage(from, bulletin_req)
        }
      }
      if (json.Page !== json.TotalPage) {
        let msg = GenBulletinAddressListRequest(json.Page + 1, SelfPublicKey, SelfPrivateKey)
        SendMessage(from, msg)
      }
      // <<<<<<<<<<<<<<<<
      break
    case ObjectType.PrivateMessage:
      if (VerifyJsonSignature(json)) {
        CachePrivateMessage(json)
        SendMessage(json.To, message)
      }
      break
    case ObjectType.ECDH:
      if (VerifyJsonSignature(json)) {
        CacheECDH(json)
        HandelECDHSync(json)
        SendMessage(json.To, message)
      }
      break
    case ObjectType.AvatarList:
      for (let i = 0; i < json.List.length; i++) {
        const avatar = json.List[i]
        if (VerifyJsonSignature(avatar)) {
          CacheAvatar(from, avatar)
        }
      }
      break
    // group
    case ObjectType.GroupList:
      for (let i = 0; i < json.List.length; i++) {
        const group = json.List[i]
        if (VerifyJsonSignature(group)) {
          CacheGroup(group)
        }
      }
      break
    case ObjectType.GroupMessageList:
      let db_g = await prisma.Group.findFirst({
        where: {
          hash: json.Hash
        }
      })
      if (db_g !== null) {
        let member = JSON.parse(db_g.member)
        member.push(db_g.created_by)
        if (member.includes(from) && member.includes(json.To)) {
          SendMessage(json.To, message)
        }
      }
      break
    default:
      break
  }
}

// handle Action
async function handleAction(from, message, json) {
  if (json.To != null) {
    // forward message
    SendMessage(json.To, message)
  }

  if (!VerifyJsonSignature(json)) {
    return
  }

  if (json.Action === ActionCode.BulletinRequest) {
    //send cache bulletin
    if (json.Hash) {
      let bulletin = await prisma.Bulletin.findFirst({
        where: {
          hash: json.Hash
        },
        select: {
          json: true
        }
      })
      if (bulletin != null) {
        SendMessage(from, bulletin.json)
      }
    } else if (json.Address && json.Sequence) {
      let bulletin = await prisma.Bulletin.findFirst({
        where: {
          address: json.Address,
          sequence: json.Sequence
        },
        select: {
          json: true
        }
      })
      if (bulletin != null) {
        SendMessage(from, bulletin.json)
      }
    }
  } else if (json.Action === ActionCode.BulletinSubscribe) {
    HandelBulletinSubscribe(json)
  } else if (json.Action === ActionCode.BulletinAddressRequest && json.Page > 0) {
    let result = await prisma.Bulletin.groupBy({
      by: "address",
      _count: {
        address: true,
      },
      orderBy: {
        _count: {
          address: "desc",
        },
      },
      skip: (json.Page - 1) * PageSize,
      take: PageSize,
    })
    let address_list = []
    result.forEach(item => {
      let new_item = {}
      new_item.Address = item.address
      new_item.Count = item._count.address
      address_list.push(new_item)
    })

    let total = await prisma.Bulletin.findMany({
      select: { address: true },
      distinct: ['address']
    })

    let total_page = calcTotalPage(total.length, PageSize)
    if (address_list.length > 0) {
      let msg = GenBulletinAddressList(json.Page, total_page, address_list)
      SendMessage(from, msg)
    }
  } else if (json.Action === ActionCode.ReplyBulletinRequest && json.Page > 0) {
    let reply_hash_list = await prisma.Reply.findMany({
      where: {
        post_hash: json.Hash
      },
      select: {
        reply_hash: true
      },
      skip: (json.Page - 1) * PageSize,
      take: PageSize,
      orderBy: { signed_at: "asc" }
    })
    let tmp_list = []
    reply_hash_list.forEach(reply => {
      tmp_list.push(reply.reply_hash)
    })

    let reply_json_list = await prisma.Bulletin.findMany({
      where: {
        hash: {
          in: tmp_list
        }
      },
      select: {
        json: true
      },
      orderBy: { signed_at: "asc" }
    })
    tmp_list = []
    reply_json_list.forEach(reply => {
      tmp_list.push(JSON.parse(reply.json))
    })

    let total = await prisma.Reply.count({
      where: {
        post_hash: json.Hash
      }
    })
    let total_page = 0
    if (total > 0) {
      total_page = calcTotalPage(total, PageSize)
    }

    if (tmp_list.length > 0) {
      let msg = GenReplyBulletinList(json.Hash, json.Page, total_page, tmp_list)
      SendMessage(from, msg)
    }
  } else if (json.Action === ActionCode.TagBulletinRequest && json.Page > 0) {
    const whereCondition = {
      AND: json.Tag.map(name => ({ tags: { some: { name: name } } }))
    };
    const [list, total] = await prisma.$transaction([
      prisma.Bulletin.findMany({
        where: whereCondition,
        // include: { tags: true },
        select: {
          json: true,
          tags: { select: { name: true } }
        },
        orderBy: { signed_at: 'desc' },
        skip: (json.Page - 1) * PageSize,
        take: PageSize
      }),
      prisma.Bulletin.count({
        where: whereCondition
      })
    ])
    let tmp_list = []
    list.forEach(bulletin => {
      tmp_list.push(JSON.parse(bulletin.json))
    })
    let total_page = 0
    if (total > 0) {
      total_page = calcTotalPage(total, PageSize)
    }
    if (tmp_list.length > 0) {
      let msg = GenTagBulletinList(json.Hash, json.Page, total_page, tmp_list)
      SendMessage(from, msg)
    }
  } else if (json.Action === ActionCode.FileRequest) {
    HandelFileRequest(json, from)
  } else if (json.Action === ActionCode.AvatarRequest) {
    HandelAvatarReqeust(json, from)
  } else if (json.Action === ActionCode.BulletinRandomRequest) {
    //send random bulletin
    let bulletins = await prisma.$queryRaw`SELECT * FROM "public"."Bulletin" ORDER BY RANDOM() LIMIT 1`
    if (bulletins != null && bulletins.length != 0) {
      SendMessage(from, bulletins[0].json)
    }
  } else if (json.Action === ActionCode.PrivateMessageSync) {
    HandelPrivateMessageSync(json)
  } else if (json.Action === ActionCode.GroupSync) {
    HandelGroupSync(from, json)
  }
}

async function SyncClientRequest(address) {
  // bulletin
  let bulletin_list = await prisma.Bulletin.findMany({
    where: {
      address: address
    },
    orderBy: {
      sequence: "asc"
    },
    select: {
      sequence: true
    }
  })
  let sequence = 1
  for (let i = 0; i < bulletin_list.length; i++) {
    const bulletin = bulletin_list[i]
    if (bulletin.sequence === sequence) {
      sequence = sequence + 1
    } else {
      break
    }
  }
  let msg = GenBulletinRequest(address, sequence, address, SelfPublicKey, SelfPrivateKey)
  SendMessage(address, msg)

  // file
  let file_list = await prisma.File.findMany({
    where: {
      is_saved: false
      // chunk_length: {
      //   gt: prisma.Files.fields.chunk_cursor
      // }
    }
  })
  file_list.forEach(async file => {
    fetchFile(address, address, file.hash, file.chunk_cursor + 1)
  })

  // ecdh
  let dh = await prisma.ECDH.findFirst({
    where: {
      OR: [
        {
          address1: address,
          json1: ""
        },
        {
          address2: address,
          json2: ""
        }
      ]
    }
  })
  if (dh != null) {
    if (dh.json1 === "") {
      SendMessage(address, dh.json2)
    } else if (dh.json2 === "") {
      SendMessage(address, dh.json1)
    }
  }

  // group
  msg = GenGroupSync(SelfPublicKey, SelfPrivateKey)
  SendMessage(address, msg)

  HandelGroupSync(address)
}

async function checkMessage(ws, message) {
  ConsoleInfo(`###################LOG################### Client Message:`)
  ConsoleInfo(`${message}`)
  // ConsoleInfo(`${message.slice(0, 512)}`)
  let json = MsgValidate(message)
  if (json === false) {
    // sendServerMessage(ws, MessageCode.JsonSchemaInvalid)
    teminateConn(ws)
  } else if (json.ObjectType) {
    let connAddress = fetchConnAddress(ws)
    handleObject(connAddress, message, json)
  } else if (json.Action) {
    let address = rippleKeyPairs.deriveAddress(json.PublicKey)
    if (Conns[address] === ws) {
      handleAction(address, message, json)
    } else {
      let connAddress = fetchConnAddress(ws)
      if (connAddress !== null && connAddress !== address) {
        // using different address in same connection
        // sendServerMessage(ws, MessageCode.AddressChanged)
      } else {
        if (!VerifyJsonSignature(json)) {
          // sendServerMessage(ws, MessageCode.SignatureInvalid)
          teminateConn(ws)
          return
        }

        if (json.Timestamp + 60000 < Date.now()) {
          // sendServerMessage(ws, MessageCode.TimestampInvalid)
          teminateConn(ws)
          return
        }

        if (connAddress === null && Conns[address] === undefined && json.Action === ActionCode.Declare) {
          // new connection and new address
          ConsoleWarn(`connected <===> client : <${address}>`)
          Conns[address] = ws
          if (json.URL != null && CheckServerURL(json.URL)) {
            // Server Conntion
            NodeList.push({
              URL: json.URL
            })
            NodeList = UniqArray(NodeList)
          }

          let msg = GenDeclare(SelfPublicKey, SelfPrivateKey, SelfURL)
          SendMessage(address, msg)
          SyncClientRequest(address)
        } else if (Conns[address] && Conns[address] !== ws && Conns[address].readyState === WebSocket.OPEN) {
          // new connection kick old conection with same address
          // sendServerMessage(Conns[address], MessageCode.NewConnectionOpening)
          Conns[address].close()
          Conns[address] = ws
        } else {
          ws.send("WTF...")
          teminateConn(ws)
        }
      }
    }
  }
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// Node Interaction
function SendToNode(url, message) {
  if (NodeConns[url] != null && NodeConns[url].readyState === WebSocket.OPEN) {
    NodeConns[url].send(message)
  }
}

function fetchFileFromNode(url, address, hash, chunk_cursor) {
  let nonce = genFileNonce()
  let tmp = {
    Type: FileRequestType.File,
    Nonce: nonce,
    Hash: hash,
    ChunkCursor: chunk_cursor,
    Address: address,
    Timestamp: Date.now()
  }
  let prev_request = FileRequestList.filter(r => r.Hash === hash)
  if (prev_request.length === 0) {
    FileRequestList.push(tmp)
    let msg = GenFileRequest(FileRequestType.File, hash, nonce, chunk_cursor, SelfPublicKey, SelfPrivateKey)
    SendToNode(url, msg)
  }
}

async function downloadBulletinFile(url) {
  let file_list = await prisma.File.findMany({
    where: {
      is_saved: {
        equals: false
      }
    }
    // where: {
    //   NOT: [
    //     {
    //       chunk_length: {
    //         equals: prisma.File.fields.chunk_cursor
    //       }
    //     }
    //   ]
    // }
  })
  if (file_list && file_list.length > 0) {
    ConsoleInfo(`--------------------------files to download--------------------------`)
    ConsoleInfo(file_list)
    for (let i = 0; i < file_list.length; i++) {
      const file = file_list[i]
      fetchFileFromNode(url,)
    }
  }
}

function pullBulletin(url) {
  // clone all bulletin from server
  // pull step 1: fetch all account
  let msg = GenBulletinAddressListRequest(1, SelfPublicKey, SelfPrivateKey)
  SendToNode(url, msg)
}

async function pushBulletin(url) {
  let bulletin_list = await prisma.Bulletin.findMany({
    select: {
      address: true,
      sequence: true
    }
  })
  let bulletin_sequence = {}
  bulletin_list.forEach(bulletin => {
    if (bulletin_sequence[bulletin.address] === undefined) {
      bulletin_sequence[bulletin.address] = bulletin.sequence
    } else if (bulletin_sequence[bulletin.address] < bulletin.sequence) {
      bulletin_sequence[bulletin.address] = bulletin.sequence
    }
  })

  for (const address in bulletin_sequence) {
    await DelayExec(1000)
    let msg = GenBulletinRequest(address, bulletin_sequence[address] + 1, address, SelfPublicKey, SelfPrivateKey)
    SendToNode(url, msg)
  }
}

function SyncNodeData(url) {
  ConsoleWarn(`sync node data`)
  pullBulletin(url)
  pushBulletin(url)
  // downloadBulletinFile(url)
}

function connectNode(node) {
  ConsoleInfo(`--------------------------connect to node--------------------------`)
  ConsoleWarn(node)
  let ws = new WebSocket(node.URL)
  ws.on('open', function open() {
    ConsoleWarn(`connected <===> ${node.URL}`)
    ws.send(GenDeclare(SelfPublicKey, SelfPrivateKey, SelfURL))
    NodeConns[node.URL] = ws
    console.log(Conns)
    SyncNodeData(node.URL)
  })

  ws.on('message', (data, isBinary) => {
    if (isBinary) {
    } else {
      let message = data.toString()
      checkMessage(ws, message)
    }
  })

  ws.on('close', function close() {
    ConsoleWarn(`disconnected <=X=> ${node.URL}`)
    teminateConn(ws)
  })
}

function keepNodeConn() {
  let notConnected = []
  NodeList.forEach(node => {
    if (NodeConns[node.URL] === undefined) {
      notConnected.push(node)
    }
  })

  if (notConnected.length === 0) {
    return
  }
  ConsoleWarn(`--------------------------keepNodeConn--------------------------`)

  let random = Math.floor(Math.random() * (notConnected.length))
  let randomNode = notConnected[random]
  if (randomNode != null) {
    connectNode(randomNode)
  }
}

function keepNodeSync() {
  ConsoleWarn(`--------------------------keepNodeSync--------------------------`)
  NodeList.forEach(node => {
    if (NodeConns[node.URL]) {
      SyncNodeData(node.URL)
    }
  })
}
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

async function loadGroupMap() {
  let group_list = await prisma.Group.findMany()
  for (let i = 0; i < group_list.length; i++) {
    const group = group_list[i]
    let group_member = JSON.parse(group.member)
    group_member.push(group.created_by)
    GroupMap[group.hash] = group_member
  }
  ConsoleWarn(`*****GroupMap:`)
  console.log(GroupMap)
}

async function printStat() {
  let bulletin_list = await prisma.Bulletin.findMany()
  ConsoleWarn(`BulletinCount: ${bulletin_list.length}`)

  let file_list = await prisma.File.findMany()
  ConsoleWarn(`****FileCount: ${file_list.length}`)

  let address_list = await prisma.Bulletin.groupBy({
    by: "address"
  })
  ConsoleWarn(`*AddressCount: ${address_list.length}`)

  loadGroupMap()
}

async function refreshData() {
  // update pre_bulletin's next_hash
  let bulletin_list = await prisma.Bulletin.findMany({
    orderBy: {
      sequence: "desc"
    }
  })
  for (let i = 0; i < bulletin_list.length; i++) {
    const bulletin = bulletin_list[i]
    if (bulletin.sequence != 1) {
      await prisma.Bulletin.update({
        where: {
          hash: bulletin.pre_hash
        },
        data: {
          next_hash: bulletin.hash
        }
      })
    }
  }

  // link bulletin tag quote file
  bulletin_list.forEach(async bulletin => {
    let bulletin_json = JSON.parse(bulletin.json)

    if (bulletin_json.Tag) {
      await BindBulletinTag(bulletin.hash, bulletin_json.Tag)
    }

    if (bulletin_json.File) {
      await BindBulletinFile(bulletin.hash, bulletin_json.File)
    }

    if (bulletin_json.Quote) {
      if (bulletin_json.Quote.length != 0) {
        bulletin_json.Quote.forEach(async quote => {
          let result = await prisma.Reply.findFirst({
            where: {
              post_hash: quote.Hash,
              reply_hash: bulletin.hash
            }
          })
          if (!result) {
            result = await prisma.Reply.create({
              data: {
                post_hash: quote.Hash,
                reply_hash: bulletin.hash,
                signed_at: bulletin.signed_at
              }
            })
            if (result) {
              console.log(`linking`, quote)
            }
          }
        })
      }
    }
  })
}

function startServerDaemon() {
  if (ServerDaemon === null) {
    ServerDaemon = new WebSocketServer({
      port: 8100, // to bind on 80, must use "sudo node main.js"
      clientTracking: true,
      maxPayload: 2 * 1024 * 1024
    })

    ServerDaemon.on("connection", function connection(ws) {
      ws.on("message", (data, isBinary) => {
        if (isBinary) {
          const nonce = BufferToUint32(Uint8Array.prototype.slice.call(data, 0, 4))
          const content = Uint8Array.prototype.slice.call(data, 4)
          for (let i = 0; i < FileRequestList.length; i++) {
            const request = FileRequestList[i]
            if (request.Nonce === nonce) {
              if (request.Type === FileRequestType.ChatFile) {
                // forward
                FileRequestList = FileRequestList.filter(r => r.Nonce !== request.Nonce)
                SendMessage(request.From, data)
              } else {
                saveBufferFile(request, content)
              }
              break
            }
          }
        } else {
          let message = data.toString()
          checkMessage(ws, message)
        }
      })

      ws.on("close", function close() {
        let connAddress = fetchConnAddress(ws)
        if (connAddress != null) {
          ConsoleWarn(`client <${connAddress}> disconnect...`)
          delete Conns[connAddress]
        }
      })
    })
  }
}

function main() {
  fs.mkdirSync(path.resolve('./File'), { recursive: true })
  fs.mkdirSync(path.resolve('./AvatarFile'), { recursive: true })

  let config = fs.readFileSync(ConfigPath, 'utf8')
  config = JSON.parse(config)
  ConsoleWarn(`*******Config:`)
  console.log(config)
  if (config.SelfURL !== '') {
    SelfURL = config.SelfURL
  }
  NodeList = config.NodeList
  console.log(NodeList)

  const seed = rippleKeyPairs.generateSeed("RandomSeed", 'secp256k1')
  const keypair = rippleKeyPairs.deriveKeypair(seed)
  SelfAddress = rippleKeyPairs.deriveAddress(keypair.publicKey)
  SelfPublicKey = keypair.publicKey
  SelfPrivateKey = keypair.privateKey
  ConsoleWarn(`use******Seed: ${seed}`)
  ConsoleWarn(`use***Address: ${SelfAddress}`)

  printStat()
  refreshData()
  startServerDaemon()

  // >>>>>>>>>>>>>>>>
  // Node Interaction
  if (jobNodeConn === null) {
    jobNodeConn = setInterval(keepNodeConn, 5000)
  }
  if (jobNodeSync === null) {
    jobNodeSync = setInterval(keepNodeSync, 60 * 60 * 1000)
  }
  // <<<<<<<<<<<<<<<<
}

main()