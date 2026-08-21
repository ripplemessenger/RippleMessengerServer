import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { WebSocket, WebSocketServer } from "ws";
import rippleKeyPairs from "ripple-keypairs";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

import {
	ConsoleInfo,
	ConsoleWarn,
	ConsoleError,
	ConsoleDebug,
	DelayExec,
	FileReadHash,
	QuarterSHA512Message,
	UniqArray,
	CheckServerURL,
	genNonce,
	FileBufferHash,
	BufferToUint32,
	Uint32ToBuffer,
	VerifyJsonSignature,
	calcTotalPage,
	shuffleArray,
} from "./util.js";
import {
	ActionCode,
	ObjectType,
	GenesisHash,
	FileRequestType,
	Epoch,
	MessageCode,
} from "./msg_const.js";
import {
	AvatarDir,
	ConfigPath,
	FileChunkSize,
	FileDir,
	PageSize,
	FILE_REQUEST_TTL_MS,
	AVATAR_UPDATE_THROTTLE_MS,
	DECLARE_TIMESTAMP_TOLERANCE_MS,
	NODE_RECONNECT_INTERVAL_MS,
	NODE_SYNC_INTERVAL_MS,
	FILE_PURGE_INTERVAL_MS,
} from "./const.js";
import {
	GenDeclare,
	GenBulletinRequest,
	GenPrivateMessageSync,
	GenFileRequest,
	GenAvatarRequest,
	GenGroupSync,
	GenReplyBulletinList,
	GenTagBulletinList,
	GenRandomBulletinList,
	GenServerAddressListRequest,
	GenServerAddressList,
	GenBulletinRequestByHash,
	GenServerNotifyError,
	GenServerNotifyInfo,
	GenServerNotifyCache,
	GenServerNotifyFileProgress,
} from "./msg_generator.js";
import { MsgValidate } from "./msg_validator.js";

/*
 * TODO: Module splitting for maintainability
 *
 * Current file is ~1800 lines. Recommended split:
 * - connection.js   — WebSocket lifecycle, terminateConn, SendMessage/broadcast
 * - fileHandler.js  — binary frames, fileRequest cache, saveBufferFile
 * - cache/avatar.js — CacheAvatar, HandleAvatarRequest
 * - cache/bulletin.js — CacheBulletin, BindBulletin*, pushBulletin, refreshData
 * - cache/group.js  — CacheGroup, HandleGroupSync, HandlePrivateMessageSync
 * - router/objectHandler.js — handleObject (ObjectType switch)
 * - router/actionHandler.js — handleAction (ActionCode switch)
 * - network/nodeClient.js — node WebSocket management, keepNodeConn/Sync
 * - bootstrap/server.js — config loading, intervals, gracefulShutdown
 */

/** Server identity & authentication — loaded from config at startup */
let SelfURL;
let SelfAddress;
let SelfPublicKey;
let SelfPrivateKey;

/** Remote peer-node network: list of all nodes + whitelist of allowed addresses */
let NodeList = [];
let WhiteList = [];

function isAllowed(address) {
	if (WhiteList.length === 0) return true;
	return WhiteList.includes(address);
}

/** Client-server daemon and active WebSocket connections keyed by address or URL */
let ServerDaemon = null;
const Conns = {}; // client connections: address -> WebSocket
let jobNodeConn = null; // interval timer for reconnecting dropped node links
let jobNodeSync = null; // interval timer for periodic bulletin sync across nodes
let jobFilePurge = null; // interval timer for purging expired file requests
const NodeConns = {}; // node-to-node connections: URL -> WebSocket

/** Pending file-transfer requests queued while awaiting binary chunks */
const fileRequestList = new Map();

/** Group membership map (group_hash -> member list) and subscription map (address -> subscribed addresses) */
const groupMap = {};
const subscribeMap = {};

/** Track which addresses have already had N+1 confirmation sent during Declare-triggered sync */
const syncConfirmSent = {};

/**
 * Throttle for PrivateMessageSync: detects a client-side sync loop. If the same
 * (from, to) pair re-sends the IDENTICAL (SelfSequence, PairSequence) request more
 * than PRIVATE_SYNC_MAX times within PRIVATE_SYNC_WINDOW_MS, it is a loop (the
 * client's local state never advances) — log a warning and skip the response so
 * the server is not flooded. A legitimate re-sync changes the sequences and resets
 * the counter. Key: `${from}:${to}`.
 */
const privateSyncThrottle = new Map();
const PRIVATE_SYNC_MAX = 5;
const PRIVATE_SYNC_WINDOW_MS = 10000;

// keep alive
process.on("uncaughtException", (err) => {
	ConsoleError("[uncaughtException] Server encountered a fatal error:");
	ConsoleError(err);
	ConsoleError(err.stack);
	ConsoleError(
		"[uncaughtException] Process state is now undefined - restart is recommended.",
	);
});

process.on("unhandledRejection", (reason, promise) => {
	ConsoleError("[unhandledRejection] Uncaught async error:");
	ConsoleError(reason);
	if (reason && reason.stack) {
		ConsoleError(reason.stack);
	}
	ConsoleError(
		"[unhandledRejection] Process state may be undefined - restart is recommended.",
	);
});

function fetchConnAddress(ws) {
	return ws._connAddress ?? null;
}
function fetchNodeConnURL(ws) {
	return ws._nodeUrl ?? null;
}

/**
 * Handles incoming binary WebSocket frames (file chunks).
 * Extracts the 4-byte nonce, looks up the matching fileRequestList entry,
 * and either forwards the raw data (private/group chat) or persists to disk.
 * @param {Uint8Array} data - Raw binary frame containing nonce + file chunk data
 */
async function handleBinaryMessage(data) {
	const nonce = BufferToUint32(Uint8Array.prototype.slice.call(data, 0, 4));
	const content = Uint8Array.prototype.slice.call(data, 4);
	const request = fileRequestList.get(nonce);
	if (!request) {
		ConsoleWarn(
			`[handleBinaryMessage] ❌ Unknown nonce ${nonce}, data length=${content.length} bytes. Active requests: ${fileRequestList.size}`,
		);
		return;
	}
	ConsoleInfo(
		`[handleBinaryMessage] ✅ Received chunk for hash=${request.Hash}, nonce=${nonce}, data=${content.length} bytes`,
	);
	if (
		request.Type === FileRequestType.PrivateChatFile ||
		request.Type === FileRequestType.GroupChatFile
	) {
		if (!isAllowed(request.From)) {
			ConsoleWarn(
				`[Chat Filter] Blocked binary file forward to ${request.From} (type=${request.Type})`,
			);
			removeFileRequestByNonce(request.Nonce);
			return;
		}
		// forward file data to the destination peer
		removeFileRequestByNonce(request.Nonce);
		SendMessage(request.From, data);
	} else {
		await saveBufferFile(request, content);
	}
}

function broadcastBulletinToNodes(bulletin) {
	const jsonStr = JSON.stringify(bulletin);
	for (const url in NodeConns) {
		SendToNode(url, jsonStr);
	}
}

// === Client Connection Handler ===
/**
 * Terminates a WebSocket connection by closing it and removing from tracking maps.
 * Checks both client connections (by address) and node connections (by URL).
 * @param {WebSocket} ws - The WebSocket instance to terminate
 */
function terminateConn(ws, reason = "unknown") {
	ConsoleWarn(`[terminateConn] Closing connection — reason: ${reason}`);
	ws.close();
	const connAddress = fetchConnAddress(ws);
	if (connAddress != null) {
		ConsoleWarn(
			`###################LOG################### client disconnect... <${connAddress}>`,
		);
		delete Conns[connAddress];
		// Clear sync confirmation state on disconnect
		delete syncConfirmSent[connAddress];
	}

	const url = fetchNodeConnURL(ws);
	if (url != null) {
		ConsoleWarn(
			`###################LOG################### server disconnect... <${url}>`,
		);
		delete NodeConns[url];
	}
}

// file
function genFileNonce() {
	let nonce;
	do {
		nonce = genNonce();
	} while (fileRequestList.has(nonce));
	return nonce;
}

/** Remove a file-transfer request from fileRequestList by its nonce. */
function removeFileRequestByNonce(nonce) {
	fileRequestList.delete(nonce);
}

/* NOTE: These three purge functions each iterate the full fileRequestList Map.
 * purgeExpiredFileRequests is now called periodically via jobFilePurge (60s interval).
 * The other two are on-demand and scoped by hash/address for targeted cleanup. */
/**
 * Purges expired file-transfer request entries from fileRequestList.
 * Called periodically every 60 seconds via the jobFilePurge interval timer.
 * @returns {void}
 */
function purgeExpiredFileRequests() {
	const now = Date.now();
	for (const [nonce, r] of fileRequestList) {
		if (r.Timestamp + FILE_REQUEST_TTL_MS <= now) {
			fileRequestList.delete(nonce);
		}
	}
}

function purgeFileRequestsByHashAddress(hash, address) {
	for (const [nonce, r] of fileRequestList) {
		if (r.Hash === hash && r.Address === address) {
			fileRequestList.delete(nonce);
		}
	}
}

function purgeFileRequestsByHashFrom(hash, from) {
	for (const [nonce, r] of fileRequestList) {
		if (r.Hash === hash && r.From === from) {
			fileRequestList.delete(nonce);
		}
	}
}

/**
 * Generic file request: generates nonce, caches in fileRequestList, sends to client.
 * @param {string} from - Recipient XRPL address
 * @param {number} type - FileRequestType enum value
 * @param {string} hash - SHA-512 content hash of the file
 * @param {number} chunkCursor - Current chunk index (1-based)
 * @param {string} address - XRPL address owning the file
 * @param {boolean} doCleanup - If true, purge expired + duplicate entries before push
 * @returns {void}
 */
function requestFile(from, type, hash, chunkCursor, address, doCleanup) {
	const nonce = genFileNonce();
	const tmp = {
		Type: type,
		Nonce: nonce,
		Hash: hash,
		Address: address,
		Timestamp: Date.now(),
	};
	if (chunkCursor > 1) {
		tmp.ChunkCursor = chunkCursor;
	}
	if (doCleanup) {
		purgeExpiredFileRequests();
		purgeFileRequestsByHashAddress(hash, address);
	}
	fileRequestList.set(nonce, tmp);
	const msg = GenFileRequest(
		type,
		hash,
		nonce,
		chunkCursor,
		SelfPublicKey,
		SelfPrivateKey,
	);
	ConsoleInfo(
		`[requestFile] Sending FileRequest to ${from} for hash=${hash}, chunkCursor=${chunkCursor}`,
	);
	SendMessage(from, msg);
}

function fetchAvatarFile(from, address, hash) {
	requestFile(from, FileRequestType.Avatar, hash, 1, address, false);
}

function fetchBulletinFile(from, address, hash, chunk_cursor) {
	requestFile(from, FileRequestType.File, hash, chunk_cursor, address, true);
}

/**
 * Cache a file-transfer request in fileRequestList after purging expired and duplicate entries.
 * @param {string} from - Source XRPL address of the sender
 * @param {object} json - The incoming file request message object (contains Nonce, Hash, Timestamp)
 * @param {number} type - FileRequestType enum value (PrivateChatFile or GroupChatFile)
 * @returns {void}
 */
function cacheFileRequest(from, json, type) {
	const tmp = {
		Type: type,
		Nonce: json.Nonce,
		From: from,
		// To: json.To,
		Hash: json.Hash,
		// ChunkCursor: json.ChunkCursor,
		Timestamp: json.Timestamp,
	};
	purgeExpiredFileRequests();
	purgeFileRequestsByHashFrom(json.Hash, from);
	fileRequestList.set(json.Nonce, tmp);
}

function cachePrivateFileRequest(from, json) {
	cacheFileRequest(from, json, FileRequestType.PrivateChatFile);
}

function cacheGroupFileRequest(from, json) {
	cacheFileRequest(from, json, FileRequestType.GroupChatFile);
}

/**
 * Persist incoming file buffer chunks to disk. Handles avatar files (full write)
 * and bulletin attachments (chunked append with hash verification).
 * @param {object} request - File request entry from fileRequestList (Type, Hash, Address, etc.)
 * @param {Uint8Array} content - Raw file chunk data received via WebSocket binary frame
 * @returns {Promise<void>}
 */
async function saveBufferFile(request, content) {
	switch (request.Type) {
		case FileRequestType.Avatar: {
			const content_hash = FileBufferHash(content);
			if (request.Hash === content_hash) {
				const avatar_dir = `./${AvatarDir}/${request.Address.substring(1, 4)}/${request.Address.substring(4, 7)}`;
				await fsp.mkdir(path.resolve(avatar_dir), { recursive: true });
				const avatar_path = `${avatar_dir}/${request.Address}.png`;
				try {
					await fsp.writeFile(avatar_path, content);
					removeFileRequestByNonce(request.Nonce);
					await prisma.Avatar.update({
						where: {
							address: request.Address,
						},
						data: {
							is_saved: true,
						},
					});
				} catch (err) {
					ConsoleWarn(err.message);
				}
			}
			break;
		}
		case FileRequestType.File: {
			const file_dir = `./${FileDir}/${request.Hash.substring(0, 3)}/${request.Hash.substring(3, 6)}`;
			await fsp.mkdir(path.resolve(file_dir), { recursive: true });
			const file_path = `${file_dir}/${request.Hash}`;
			const file = await prisma.File.findFirst({
				where: {
					AND: {
						hash: request.Hash,
						is_saved: false,
					},
				},
				select: {
					size: true,
					chunk_length: true,
					chunk_cursor: true,
					is_saved: true,
				},
			});
			if (file === null) {
				ConsoleWarn(
					`[saveBufferFile] ${request.Hash}: file record not found or already saved`,
				);
			} else {
				// ChunkCursor is only set when cursor > 1 in requestFile;
				// default to 1 for the first chunk
				const expectedCursor = request.ChunkCursor ?? 1;
				if (file.chunk_cursor === file.chunk_length) {
					ConsoleInfo(
						`[saveBufferFile] ${request.Hash}: cursor at end (${file.chunk_length}), resetting to 0`,
					);
					await fsp.rm(path.resolve(file_path), { force: true });
					await prisma.File.update({
						where: {
							hash: request.Hash,
						},
						data: {
							chunk_cursor: 0,
						},
					});
					if (request.NodeUrl) {
						fetchFileFromNode(request.NodeUrl, request.Address, request.Hash, 1);
					} else {
						fetchBulletinFile(request.Address, request.Address, request.Hash, 1);
					}
				} else if (
					file.chunk_cursor < file.chunk_length &&
					file.chunk_cursor + 1 === expectedCursor
				) {
					ConsoleInfo(
						`[saveBufferFile] ${request.Hash}: saving chunk ${expectedCursor}/${file.chunk_length} (${content.length} bytes)`,
					);
					try {
						await fsp.appendFile(file_path, Buffer.from(content));
						removeFileRequestByNonce(request.Nonce);
						const current_chunk_cursor = file.chunk_cursor + 1;
						await prisma.File.update({
							where: {
								hash: request.Hash,
							},
							data: {
								chunk_cursor: current_chunk_cursor,
								updated_at: Date.now(),
							},
						});
						if (current_chunk_cursor < file.chunk_length) {
							ConsoleInfo(
								`[saveBufferFile] ${request.Hash}: requesting next chunk ${current_chunk_cursor + 1}`,
							);
							if (request.NodeUrl) {
								fetchFileFromNode(
									request.NodeUrl,
									request.Address,
									request.Hash,
									current_chunk_cursor + 1,
								);
							} else {
								fetchBulletinFile(
									request.Address,
									request.Address,
									request.Hash,
									current_chunk_cursor + 1,
								);
							}
						} else {
							ConsoleInfo(
								`[saveBufferFile] ${request.Hash}: all chunks received, verifying hash...`,
							);
							const hash = FileReadHash(path.resolve(file_path));
							if (hash === request.Hash) {
								ConsoleInfo(
									`[saveBufferFile] ${request.Hash}: ✅ File saved successfully! (${file.size} bytes)`,
								);
								await prisma.File.update({
									where: {
										hash: request.Hash,
									},
									data: {
										is_saved: true,
									},
								});
							} else {
								ConsoleWarn(
									`[saveBufferFile] ${request.Hash}: ❌ HASH MISMATCH! expected=${request.Hash}, got=${hash}`,
								);
								await fsp.rm(path.resolve(file_path), { force: true });
								await prisma.File.update({
									where: {
										hash: request.Hash,
									},
									data: {
										chunk_cursor: 0,
									},
								});
								if (request.NodeUrl) {
									fetchFileFromNode(request.NodeUrl, request.Address, request.Hash, 1);
								} else {
									fetchBulletinFile(request.Address, request.Address, request.Hash, 1);
								}
							}
						}
					} catch (err) {
						ConsoleWarn(
							`[saveBufferFile] Failed to append file chunk: ${err.message}`,
						);
					}
				} else {
					ConsoleWarn(
						`[saveBufferFile] ${request.Hash}: ❌ Unexpected cursor! expected=${file.chunk_cursor + 1}, got=${expectedCursor}, cursor=${file.chunk_cursor}, length=${file.chunk_length}`,
					);
				}
			}
			break;
		}
		default:
			break;
	}
}

async function HandleFileRequest(request, from) {
	// send cache file
	switch (request.FileType) {
		case FileRequestType.Avatar: {
			const avatar = await prisma.Avatar.findFirst({
				where: {
					hash: request.Hash,
				},
				select: {
					address: true,
				},
			});
			if (avatar === null) {
				ConsoleInfo(
					`[HandleFileRequest] Avatar not found for hash ${request.Hash}`,
				);
				return;
			}
			const avatar_file_path = path.resolve(
				`./${AvatarDir}/${avatar.address.substring(1, 4)}/${avatar.address.substring(4, 7)}/${avatar.address}.png`,
			);
			const buffer = await fsp.readFile(avatar_file_path);
			const nonce = Uint32ToBuffer(request.Nonce);
			SendMessage(from, Buffer.concat([nonce, buffer]));
			break;
		}
		case FileRequestType.File: {
			const file = await prisma.File.findFirst({
				where: {
					AND: {
						hash: request.Hash,
						is_saved: true,
					},
				},
				select: {
					size: true,
					chunk_length: true,
					chunk_cursor: true,
				},
			});
			if (file !== null && file.chunk_cursor === file.chunk_length) {
				const start = (request.ChunkCursor - 1) * FileChunkSize;
				if (start >= file.size) {
					ConsoleWarn(
						`[HandleFileRequest] Chunk cursor ${request.ChunkCursor} out of range for ${request.Hash}, start=${start}, file.size=${file.size}`,
					);
					return;
				}
				const file_left = file.size - start;
				const length = Math.min(FileChunkSize, file_left);
				const file_path = path.resolve(
					`./${FileDir}/${request.Hash.substring(0, 3)}/${request.Hash.substring(3, 6)}/${request.Hash}`,
				);
				try {
					// fsp.readFile does NOT support {start, end} options - use fsp.open + fd.read instead
					const fd = await fsp.open(file_path, "r");
					try {
						const buffer = Buffer.alloc(length);
						await fd.read(buffer, 0, length, start);
						const chunk = Uint8Array.from(buffer);
						const nonce = Uint32ToBuffer(request.Nonce);
						SendMessage(from, Buffer.concat([nonce, chunk]));
					} finally {
						await fd.close();
					}
				} catch (err) {
					ConsoleError(err);
				}
			}
			break;
		}
		case FileRequestType.PrivateChatFile:
			// already forwarded, save relay info
			cachePrivateFileRequest(from, request);
			break;
		case FileRequestType.GroupChatFile: {
			if (!isAllowed(from)) {
				ConsoleWarn(`[Chat Filter] Blocked GroupChatFile from ${from}`);
				SendMessage(
					from,
					GenServerNotifyError(
						MessageCode.NotAllowed,
						"Chat not allowed for this address",
					),
				);
				break;
			}
			cacheGroupFileRequest(from, request);
			const members = groupMap[request.GroupHash];
			if (members) {
				const tmp_members = shuffleArray(members);
				for (let i = 0; i < tmp_members.length; i++) {
					const member = tmp_members[i];
					if (
						from !== member &&
						Conns[member] &&
						Conns[member].readyState === WebSocket.OPEN
					) {
						SendMessage(member, JSON.stringify(request));
						return;
					}
				}
			}
			break;
		}
		default:
			break;
	}
}

// avatar
/**
 * Upsert an avatar record into the database. If the avatar timestamp is newer
 * than what is stored (and throttle period has elapsed), update the record.
 * Triggers a file fetch for the avatar image if hash is not the genesis hash.
 * @param {string} from - Source XRPL address of the sender
 * @param {object} avatar - Avatar object with PublicKey, Hash, Size, Timestamp fields
 * @returns {Promise<void>}
 */
async function CacheAvatar(from, avatar) {
	const timestamp = Date.now();
	const avatar_address = rippleKeyPairs.deriveAddress(avatar.PublicKey);
	if (avatar.Hash !== GenesisHash) {
		fetchAvatarFile(from, avatar_address, avatar.Hash);
	}

	const db_a = await prisma.Avatar.findFirst({
		where: {
			address: avatar_address,
		},
	});
	if (db_a === null) {
		await prisma.Avatar.create({
			data: {
				address: avatar_address,
				hash: avatar.Hash,
				size: avatar.Size,
				signed_at: avatar.Timestamp,
				json: JSON.stringify(avatar),
				is_saved: false,
			},
		});
	} else if (
		avatar.Timestamp > db_a.signed_at &&
		db_a.signed_at < timestamp - AVATAR_UPDATE_THROTTLE_MS &&
		avatar.Hash !== db_a.hash
	) {
		await prisma.Avatar.update({
			where: {
				address: avatar_address,
			},
			data: {
				hash: avatar.Hash,
				size: avatar.Size,
				signed_at: avatar.Timestamp,
				json: JSON.stringify(avatar),
				is_saved: false,
			},
		});
	} else {
		// update too fast, do nothing
	}
}

/**
 * Handle an avatar request from a client. Compares requested avatars against
 * the local database: returns saved avatars the client is missing, and requests
 * from the client any newer avatars the server does not have.
 * @param {object} request - AvatarRequest message containing a List of {Address, SignedAt} objects
 * @param {string} from - Source XRPL address of the requesting client
 * @returns {Promise<void>}
 */
async function HandleAvatarRequest(request, from) {
	const new_list = [];
	const old_list = [];

	const addresses = request.List.map((item) => item.Address);
	const db_avatars = await prisma.Avatar.findMany({
		where: { address: { in: addresses } },
		select: { is_saved: true, signed_at: true, json: true },
	});
	const avatarMap = new Map(db_avatars.map((a) => [a.address, a]));

	for (let i = 0; i < request.List.length; i++) {
		const avatar = request.List[i];
		const db_avatar = avatarMap.get(avatar.Address);

		if (db_avatar !== undefined) {
			if (db_avatar.signed_at > avatar.SignedAt && db_avatar.is_saved) {
				let parsedAvatar;
				try {
					parsedAvatar = JSON.parse(db_avatar.json);
				} catch {
					parsedAvatar = null;
				}
				if (parsedAvatar) new_list.push(parsedAvatar);
			} else if (db_avatar.signed_at < avatar.SignedAt) {
				old_list.push({
					Address: avatar.Address,
					SignedAt: Number(db_avatar.signed_at),
				});
			}
		} else if (avatar.SignedAt !== Epoch) {
			old_list.push({ Address: avatar.Address, SignedAt: Epoch });
		}
	}
	if (new_list.length > 0) {
		const avatar_response = {
			ObjectType: ObjectType.AvatarList,
			List: new_list,
		};
		SendMessage(from, JSON.stringify(avatar_response));
	}
	if (old_list.length > 0) {
		const msg = GenAvatarRequest(old_list, SelfPublicKey, SelfPrivateKey);
		SendMessage(from, msg);
	}
}

async function BindBulletinTag(bulletin_hash, tags) {
	if (!tags || tags.length === 0) return null;

	const uniqueTags = [...new Set(tags)];

	return await prisma.$transaction(async (tx) => {
		await tx.Tag.createMany({
			data: uniqueTags.map((name) => ({ name: name })),
			skipDuplicates: true,
		});

		return await tx.Bulletin.update({
			where: { hash: bulletin_hash },
			data: {
				tags: {
					connect: uniqueTags.map((name) => ({ name })),
				},
			},
			include: { tags: true },
		});
	});
}

async function BindBulletinFile(bulletin_hash, files) {
	return await prisma.$transaction(async (tx) => {
		const fetchedFiles = [];

		for (const f of files) {
			const fileRecord = await tx.File.upsert({
				where: { hash: f.Hash },
				update: {},
				create: {
					hash: f.Hash,
					size: f.Size,
					chunk_length: Math.ceil(f.Size / FileChunkSize),
					chunk_cursor: 0,
					updated_at: Date.now(),
					is_saved: false,
				},
			});

			fetchedFiles.push(fileRecord);
		}

		// Batch-connect all files to bulletin in a single update instead of per-file updates
		if (fetchedFiles.length > 0) {
			await tx.Bulletin.update({
				where: { hash: bulletin_hash },
				data: {
					files: {
						connect: fetchedFiles.map((f) => ({ hash: f.hash })),
					},
				},
			});
		}

		return fetchedFiles;
	});
}

// bulletin
/**
 * Upsert a bulletin into the database with tag, quote (reply), and file bindings.
 * For new records only: links chain pointers (pre_hash/next_hash), creates tags,
 * creates quotes, fetches file chunks, notifies subscribers, and broadcasts to peer nodes.
 * @param {string} from - Source XRPL address of the sender
 * @param {object} bulletin - Bulletin object with PublicKey, PreHash, Sequence, Content, etc.
 * @param {boolean} isFromNode - True if the bulletin arrived via node-to-node sync (whitelist check applies)
 * @returns {Promise<void>}
 */
async function CacheBulletin(from, bulletin, isFromNode) {
	const timestamp = Date.now();
	const hash = QuarterSHA512Message(bulletin);
	const bulletin_address = rippleKeyPairs.deriveAddress(bulletin.PublicKey);

	if (!isAllowed(bulletin_address)) {
		if (isFromNode) {
			ConsoleDebug(
				`[Node Sync Filter] Dropped bulletin from non-whitelisted address: ${bulletin_address}`,
			);
		} else {
			ConsoleWarn(
				`[Whitelist Filter] Rejected bulletin from non-whitelisted address: ${bulletin_address}`,
			);
			SendMessage(
				from,
				GenServerNotifyError(
					MessageCode.NotAllowed,
					"You are not allowed to post bulletins",
				),
			);
		}
		return;
	}

	try {
		const result = await prisma.Bulletin.upsert({
			where: {
				hash: hash,
			},
			update: {},
			create: {
				hash: hash,
				pre_hash: bulletin.PreHash,
				address: bulletin_address,
				sequence: bulletin.Sequence,
				content: bulletin.Content,
				json: JSON.stringify(bulletin),
				signed_at: bulletin.Timestamp,
				created_at: timestamp,
			},
		});

		// 如果是新创建的，才执行后续绑定操作
		const isNewRecord = Number(result.created_at) === timestamp;

		if (isNewRecord) {
			ConsoleInfo(
				`[CacheBulletin] New bulletin saved: ${hash}, seq=${result.sequence}, address=${bulletin_address}`,
			);
			SendMessage(from, GenServerNotifyCache(MessageCode.BulletinCached));

			if (result.sequence !== 1) {
				try {
					await prisma.Bulletin.update({
						where: { hash: bulletin.PreHash },
						data: { next_hash: hash },
					});
				} catch (e) {
					ConsoleDebug(
						`[CacheBulletin] Failed to update next_hash for PreHash ${bulletin.PreHash} -> ${hash}: ${e.message}`,
					);
				}
			}

			// create tag
			if (bulletin.Tag && Array.isArray(bulletin.Tag) && bulletin.Tag.length > 0) {
				await BindBulletinTag(hash, bulletin.Tag);
			}

			// create quote
			if (bulletin.Quote && bulletin.Quote.length > 0) {
				const quoteData = bulletin.Quote.map((q) => ({
					post_hash: q.Hash,
					reply_hash: hash,
					signed_at: bulletin.Timestamp,
				}));
				await prisma.Reply.createMany({
					data: quoteData,
					skipDuplicates: true,
				});
			}

			// create file
			if (
				bulletin.File &&
				Array.isArray(bulletin.File) &&
				bulletin.File.length > 0
			) {
				ConsoleInfo(
					`[CacheBulletin] Bulletin has ${bulletin.File.length} file(s), calling BindBulletinFile`,
				);
				const files_to_fetch = await BindBulletinFile(hash, bulletin.File);
				ConsoleInfo(
					`[CacheBulletin] BindBulletinFile returned ${files_to_fetch.length} file record(s)`,
				);
				for (const file of files_to_fetch) {
					ConsoleInfo(
						`[CacheBulletin] File ${file.hash}: is_saved=${file.is_saved}, cursor=${file.chunk_cursor}`,
					);
					if (file.is_saved) {
						ConsoleInfo(
							`[CacheBulletin] File ${file.hash} already saved, skipping fetch`,
						);
					} else {
						ConsoleInfo(
							`[CacheBulletin] Calling fetchBulletinFile for ${file.hash} from ${bulletin_address} cursor=${file.chunk_cursor + 1}`,
						);
						fetchBulletinFile(
							from,
							bulletin_address,
							file.hash,
							file.chunk_cursor + 1,
						);
					}
				}
			} else {
				ConsoleInfo(
					`[CacheBulletin] Bulletin has NO files (File=${JSON.stringify(bulletin.File)})`,
				);
			}

			// send to subscribers
			if (subscribeMap[from] && subscribeMap[from].length > 0) {
				for (const subscriber of subscribeMap[from]) {
					SendMessage(subscriber, JSON.stringify(bulletin));
				}
			}

			if (isAllowed(bulletin_address)) {
				broadcastBulletinToNodes(bulletin);
			}
		}
	} catch (error) {
		if (error.code === "P2002") {
			ConsoleDebug(
				`[CacheBulletin] Duplicate bulletin ignored (already exists): ${hash}`,
			);
		} else {
			ConsoleError(
				`[CacheBulletin] Error saving bulletin ${hash}: ${error.message}`,
			);
		}
	}
}

function clearSubscribe(address) {
	Object.entries(subscribeMap).forEach(([key, value]) => {
		const new_value = value.filter((a) => a !== address);
		subscribeMap[key] = new_value;
	});
}

function HandleBulletinSubscribe(request, from) {
	clearSubscribe(from);
	for (let i = 0; i < request.List.length; i++) {
		const subscribe_address = request.List[i];
		if (subscribe_address !== from) {
			let new_value = [];
			if (subscribeMap[subscribe_address] !== undefined) {
				new_value = subscribeMap[subscribe_address];
			}
			new_value.push(from);
			subscribeMap[subscribe_address] = new_value;
		}
	}
}

// ecdh
async function CacheECDH(json) {
	let address1 = "";
	let address2 = "";
	let json1 = "";
	let json2 = "";
	const sour_address = rippleKeyPairs.deriveAddress(json.PublicKey);
	const dest_address = json.To;
	if (sour_address > dest_address) {
		address1 = sour_address;
		address2 = dest_address;
		json1 = JSON.stringify(json);
	} else {
		address1 = dest_address;
		address2 = sour_address;
		json2 = JSON.stringify(json);
	}

	const dh = await prisma.ECDH.findFirst({
		where: {
			address1: address1,
			address2: address2,
			partition: json.Partition,
			sequence: json.Sequence,
		},
	});
	if (dh === null) {
		if (json1 != "") {
			await prisma.ECDH.create({
				data: {
					address1: address1,
					address2: address2,
					partition: json.Partition,
					sequence: json.Sequence,
					json1: json1,
					json2: "",
				},
			});
		} else if (json2 != "") {
			await prisma.ECDH.create({
				data: {
					address1: address1,
					address2: address2,
					partition: json.Partition,
					sequence: json.Sequence,
					json1: "",
					json2: json2,
				},
			});
		}
	} else if (json1 != "") {
		if (dh.json1 != "") {
			let old_json1;
			try {
				old_json1 = JSON.parse(dh.json1);
			} catch {
				old_json1 = null;
			}
			if (old_json1 && json.Timestamp >= old_json1.Timestamp) {
				return;
			}
		}
		await prisma.ECDH.update({
			where: {
				address1_address2_partition_sequence: {
					address1: address1,
					address2: address2,
					partition: json.Partition,
					sequence: json.Sequence,
				},
			},
			data: {
				json1: json1,
			},
		});
	} else if (json2 != "") {
		if (dh.json2 != "") {
			let old_json2;
			try {
				old_json2 = JSON.parse(dh.json2);
			} catch {
				old_json2 = null;
			}
			if (old_json2 && json.Timestamp >= old_json2.Timestamp) {
				return;
			}
		}
		await prisma.ECDH.update({
			where: {
				address1_address2_partition_sequence: {
					address1: address1,
					address2: address2,
					partition: json.Partition,
					sequence: json.Sequence,
				},
			},
			data: {
				json2: json2,
			},
		});
	}
}

async function HandleECDHSync(json) {
	let address1 = "";
	let address2 = "";
	const sour_address = rippleKeyPairs.deriveAddress(json.PublicKey);
	const dest_address = json.To;
	if (sour_address === dest_address) {
		return;
	}
	if (sour_address > dest_address) {
		address1 = sour_address;
		address2 = dest_address;
	} else {
		address1 = dest_address;
		address2 = sour_address;
	}

	const dh = await prisma.ECDH.findFirst({
		where: {
			address1: address1,
			address2: address2,
			partition: json.Partition,
			sequence: json.Sequence,
		},
		select: {
			json1: true,
			json2: true,
		},
	});
	if (dh != null && json.Pair === "") {
		if (address1 === sour_address && dh.json2 != "") {
			SendMessage(sour_address, dh.json2);
		} else if (address2 === sour_address && dh.json1 != "") {
			SendMessage(sour_address, dh.json1);
		}
	}
}

// private
async function CachePrivateMessage(json) {
	const str_json = JSON.stringify(json);
	const hash = QuarterSHA512Message(json);
	const sour_address = rippleKeyPairs.deriveAddress(json.PublicKey);
	const dest_address = json.To;
	const last_msg = await prisma.PrivateMessage.findFirst({
		where: {
			sour_address: sour_address,
			dest_address: dest_address,
		},
		orderBy: {
			sequence: "desc",
		},
		select: {
			sequence: true,
			hash: true,
		},
	});
	if (
		(last_msg === null && json.Sequence === 1 && json.PreHash === GenesisHash) ||
		(last_msg !== null &&
			json.Sequence === last_msg.sequence + 1 &&
			json.PreHash === last_msg.hash)
	) {
		await prisma.PrivateMessage.create({
			data: {
				hash: hash,
				sour_address: sour_address,
				dest_address: dest_address,
				sequence: json.Sequence,
				signed_at: json.Timestamp,
				json: str_json,
			},
		});
	} else if (last_msg === null) {
		const msg = GenPrivateMessageSync(
			dest_address,
			0,
			0,
			SelfPublicKey,
			SelfPrivateKey,
		);
		SendMessage(sour_address, msg);
	} else if (last_msg !== null && last_msg.sequence < json.Sequence) {
		const msg = GenPrivateMessageSync(
			dest_address,
			last_msg.sequence,
			last_msg.sequence,
			SelfPublicKey,
			SelfPrivateKey,
		);
		SendMessage(sour_address, msg);
	}
}

/**
 * Handle a private message sync request. Queries the database for all messages
 * exchanged between two addresses that have sequence numbers higher than what
 * the requester already has, then sends them back in ascending order.
 * @param {object} json - PrivateMessageSync message with PublicKey, To, SelfSequence, PairSequence
 * @returns {Promise<void>}
 */
async function HandlePrivateMessageSync(json) {
	const from_address = rippleKeyPairs.deriveAddress(json.PublicKey);
	const msg_list = await prisma.PrivateMessage.findMany({
		where: {
			OR: [
				{
					sour_address: from_address,
					dest_address: json.To,
					sequence: {
						gt: json.SelfSequence,
					},
				},
				{
					sour_address: json.To,
					dest_address: from_address,
					sequence: {
						gt: json.PairSequence,
					},
				},
			],
		},
		select: {
			json: true,
		},
		orderBy: {
			sequence: "asc",
		},
	});
	const msg_list_length = msg_list.length;
	for (let i = 0; i < msg_list_length; i++) {
		SendMessage(from_address, msg_list[i].json);
	}
}

// group
/**
 * Handle a group sync request. Looks up all groups the given address is a member of,
 * fetches their create/delete JSON from the database, and sends a GroupList response.
 * @param {string} from - The XRPL address requesting group membership data
 * @returns {Promise<void>}
 */
async function HandleGroupSync(from) {
	const group_hash_list = [];
	Object.entries(groupMap).forEach(([hash, member]) => {
		if (member.includes(from)) {
			group_hash_list.push(hash);
		}
	});
	if (group_hash_list.length > 0) {
		const group_list = await prisma.Group.findMany({
			where: {
				hash: {
					in: group_hash_list,
				},
			},
			select: {
				create_json: true,
				delete_json: true,
			},
		});
		const group_create_json_list = [];
		for (let i = 0; i < group_list.length; i++) {
			const group = group_list[i];
			if (group.delete_json === null) {
				let parsedGroup;
				try {
					parsedGroup = JSON.parse(group.create_json);
				} catch {
					parsedGroup = null;
				}
				if (parsedGroup) group_create_json_list.push(parsedGroup);
			} else {
				let parsedGroup;
				try {
					parsedGroup = JSON.parse(group.delete_json);
				} catch {
					parsedGroup = null;
				}
				if (parsedGroup) group_create_json_list.push(parsedGroup);
			}
		}
		if (group_create_json_list.length > 0) {
			const group_response = {
				ObjectType: ObjectType.GroupList,
				List: group_create_json_list,
			};
			SendMessage(from, JSON.stringify(group_response));
		}
	}
}

async function CacheGroup(group) {
	const address = rippleKeyPairs.deriveAddress(group.PublicKey);

	const db_g = await prisma.Group.findFirst({
		where: {
			hash: group.Hash,
		},
	});

	if (group.ObjectType === ObjectType.GroupDelete) {
		if (db_g !== null && db_g.deleted_at === null) {
			const result = await prisma.Group.update({
				where: {
					hash: group.Hash,
				},
				data: {
					deleted_at: group.Timestamp,
					delete_json: JSON.stringify(group),
				},
			});
			if (result) {
				delete groupMap[group.Hash];
			}
		}
	} else if (group.ObjectType === ObjectType.GroupCreate) {
		await prisma.Group.upsert({
			where: { hash: group.Hash },
			create: {
				hash: group.Hash,
				created_by: address,
				member: JSON.stringify(group.Member),
				created_at: group.Timestamp,
				create_json: JSON.stringify(group),
			},
			update: {}, // GroupCreate only creates; no update needed for existing records
		});

		const members = group.Member;
		members.push(address);
		groupMap[group.Hash] = members;
	}
}

// send
/** Generic sender: looks up a key in a connection map, checks readyState, and sends. */
function sendTo(key, message, connMap) {
	try {
		if (connMap[key] && connMap[key].readyState === WebSocket.OPEN) {
			connMap[key].send(message);
			ConsoleInfo(`[sendTo] Message SENT to ${key}, bytes=${message.length}`);
		} else {
			ConsoleWarn(
				`[sendTo] FAILED to send to ${key}, readyState=${connMap[key]?.readyState}`,
			);
		}
	} catch (err) {
		ConsoleWarn(`[sendTo] EXCEPTION sending to ${key}: ${err.message}`);
	}
}

/** Send to a client by address (uses Conns map). */
function SendMessage(address, message) {
	sendTo(address, message, Conns);
}

// handle Object
/**
 * Find the first missing sequence number for an address (gap detection).
 * Returns null if sequences 1..N are contiguous.
 */
async function FindFirstMissingSequence(address) {
	const bulletin_list = await prisma.Bulletin.findMany({
		where: { address },
		orderBy: { sequence: "asc" },
		select: { sequence: true },
	});
	let expected = 1;
	for (let i = 0; i < bulletin_list.length; i++) {
		if (bulletin_list[i].sequence === expected) {
			expected++;
		} else {
			ConsoleInfo(
				`[FindFirstMissingSequence] ${address}: gap at seq=${expected}, total=${bulletin_list.length}`,
			);
			return expected;
		}
	}
	ConsoleDebug(
		`[FindFirstMissingSequence] ${address}: no gap, contiguous 1..${expected - 1} (${bulletin_list.length} records)`,
	);
	return null;
}

/**
 * Get max_sequence + 1 for an address, or null if no bulletins exist.
 */
async function GetMaxSequencePlusOne(address) {
	const result = await prisma.Bulletin.findFirst({
		where: { address },
		orderBy: { sequence: "desc" },
		select: { sequence: true },
	});
	if (!result) {
		ConsoleDebug(`[GetMaxSequencePlusOne] ${address}: no bulletins at all`);
		return null;
	}
	const next = result.sequence + 1;
	ConsoleInfo(
		`[GetMaxSequencePlusOne] ${address}: max_seq=${result.sequence}, requesting seq=${next}`,
	);
	return next;
}

/**
 * Route an incoming message by its ObjectType numeric code.
 * Handles Bulletins, ServerAddressLists, PrivateMessages, ECDH handshakes,
 * AvatarLists, GroupLists, and GroupMessageLists. Each case performs
 * signature verification, caching, and optional message forwarding.
 * @param {string} from - Source XRPL address of the sender
 * @param {string} message - Raw JSON string of the message (for forwarding)
 * @param {object} json - Parsed and validated message object
 * @param {boolean} isFromNode - True if the message arrived via node-to-node sync
 * @returns {Promise<void>}
 */
async function handleObject(from, message, json, isFromNode) {
	switch (json.ObjectType) {
		case ObjectType.Bulletin: {
			ConsoleInfo(
				`[handleObject.Bulletin] Verifying signature for PublicKey=${json.PublicKey?.substring(0, 20)}...`,
			);
			const sigValid = VerifyJsonSignature(json);
			ConsoleInfo(`[handleObject.Bulletin] Signature valid: ${sigValid}`);
			if (sigValid) {
				ConsoleInfo(
					`[handleObject.Bulletin] Caching bulletin hash=${json.Hash}, seq=${json.Sequence} from ${from}`,
				);
				await CacheBulletin(from, json, isFromNode);
				//fetch more bulletin — check for gaps first, then chase next sequence
				const address = rippleKeyPairs.deriveAddress(json.PublicKey);
				ConsoleInfo(
					`[handleObject.Bulletin] Received seq=${json.Sequence} from ${address}, checking sync`,
				);
				const gap_sequence = await FindFirstMissingSequence(address);
				if (gap_sequence === null) {
					// No gap — chase the next sequence after current max (only once per address)
					if (syncConfirmSent[address]) {
						ConsoleInfo(
							`[handleObject.Bulletin] ${address}: N+1 confirmation already sent, skipping further chase`,
						);
					} else {
						syncConfirmSent[address] = true;
						const next_seq = await GetMaxSequencePlusOne(address);
						if (next_seq === null) {
							ConsoleDebug(
								`[handleObject.Bulletin] ${address}: no bulletins to request`,
							);
						} else {
							ConsoleInfo(
								`[handleObject.Bulletin] Sending BulletinRequest seq=${next_seq} to ${address} (N+1 confirmation, max cached=${next_seq - 1})`,
							);
							const msg = GenBulletinRequest(
								address,
								next_seq,
								address,
								SelfPublicKey,
								SelfPrivateKey,
							);
							SendMessage(from, msg);
						}
					}
				} else {
					// Gap exists — fetch from the missing point
					ConsoleInfo(
						`[handleObject.Bulletin] Sending BulletinRequest seq=${gap_sequence} to ${address} (filling gap)`,
					);
					const msg = GenBulletinRequest(
						address,
						gap_sequence,
						address,
						SelfPublicKey,
						SelfPrivateKey,
					);
					SendMessage(from, msg);
				}
			}
			break;
		}
		case ObjectType.ServerAddressList: {
			// === Node Interaction ===
			// pull step 2: fetch account latest bulletin
			let items = json.List;
			if (WhiteList.length > 0) {
				items = items.filter((item) => isAllowed(item.Address));
			}

			for (let i = 0; i < items.length; i++) {
				const item = items[i];
				let bulletin = await prisma.Bulletin.findFirst({
					where: {
						address: item.Address,
					},
					select: {
						sequence: true,
					},
					orderBy: {
						sequence: "desc",
					},
				});
				let next_sequence = 1;
				if (bulletin) {
					next_sequence = bulletin.sequence + 1;
					if (bulletin.sequence < item.Count) {
						const bulletin_req = GenBulletinRequest(
							item.Address,
							next_sequence,
							from,
							SelfPublicKey,
							SelfPrivateKey,
						);
						SendMessage(from, bulletin_req);
					} else if (bulletin.sequence > item.Count) {
						bulletin = await prisma.Bulletin.findFirst({
							where: {
								AND: {
									address: item.Address,
									sequence: item.Count + 1,
								},
							},
							select: {
								json: true,
							},
						});
						if (bulletin) {
							SendMessage(from, bulletin.json);
						}
					}
				} else {
					const bulletin_req = GenBulletinRequest(
						item.Address,
						next_sequence,
						from,
						SelfPublicKey,
						SelfPrivateKey,
					);
					SendMessage(from, bulletin_req);
				}
			}
			if (json.Page !== json.TotalPage) {
				const msg = GenServerAddressListRequest(
					json.Page + 1,
					SelfPublicKey,
					SelfPrivateKey,
				);
				SendMessage(from, msg);
			}
			break;
		}
		case ObjectType.PrivateMessage:
			if (!isAllowed(from) || !isAllowed(json.To)) {
				ConsoleWarn(`[Chat Filter] Blocked PrivateMessage: ${from} → ${json.To}`);
				SendMessage(
					from,
					GenServerNotifyError(
						MessageCode.NotAllowed,
						"Chat not allowed for this address",
					),
				);
				break;
			}
			if (VerifyJsonSignature(json)) {
				await CachePrivateMessage(json);
				SendMessage(from, GenServerNotifyCache(MessageCode.PrivateMsgCached));
				SendMessage(json.To, message);
			}
			break;
		case ObjectType.ECDH:
			if (!isAllowed(from) || !isAllowed(json.To)) {
				ConsoleWarn(`[Chat Filter] Blocked ECDH: ${from} → ${json.To}`);
				SendMessage(
					from,
					GenServerNotifyError(
						MessageCode.NotAllowed,
						"Chat not allowed for this address",
					),
				);
				break;
			}
			if (VerifyJsonSignature(json)) {
				await CacheECDH(json);
				SendMessage(from, GenServerNotifyCache(MessageCode.HandshakeCached));
				await HandleECDHSync(json);
				SendMessage(json.To, message);
			}
			break;
		case ObjectType.AvatarList:
			for (let i = 0; i < json.List.length; i++) {
				const avatar = json.List[i];
				if (VerifyJsonSignature(avatar)) {
					await CacheAvatar(from, avatar);
				}
			}
			break;
		// group
		case ObjectType.GroupList:
			if (!isAllowed(from)) {
				ConsoleWarn(`[Chat Filter] Blocked GroupList from ${from}`);
				SendMessage(
					from,
					GenServerNotifyError(
						MessageCode.NotAllowed,
						"Chat not allowed for this address",
					),
				);
				break;
			}
			for (let i = 0; i < json.List.length; i++) {
				const group = json.List[i];
				if (VerifyJsonSignature(group)) {
					await CacheGroup(group);
				}
			}
			break;
		case ObjectType.GroupMessageList: {
			if (!isAllowed(from) || !isAllowed(json.To)) {
				ConsoleWarn(`[Chat Filter] Blocked GroupMessageList: ${from} → ${json.To}`);
				SendMessage(
					from,
					GenServerNotifyError(
						MessageCode.NotAllowed,
						"Chat not allowed for this address",
					),
				);
				break;
			}
			const members = groupMap[json.GroupHash];
			if (members) {
				if (members.includes(from) && members.includes(json.To)) {
					SendMessage(json.To, message);
				}
			} else {
				// Group not in memory map — check if it was deleted, notify the sender
				const db_g = await prisma.Group.findFirst({
					where: { hash: json.GroupHash },
					select: { deleted_at: true, delete_json: true },
				});
				if (db_g && db_g.deleted_at !== null && db_g.delete_json) {
					try {
						const group_response = {
							ObjectType: ObjectType.GroupList,
							List: [JSON.parse(db_g.delete_json)],
						};
						SendMessage(from, JSON.stringify(group_response));
					} catch (e) {
						ConsoleError(
							`[handleObject.GroupMessageList] failed to notify deleted group ${json.GroupHash}: ${e.message}`,
						);
					}
				}
			}
			break;
		}
		default:
			break;
	}
}

// handle Action
/**
 * Route an incoming message by its ActionCode. Handles client actions such as
 * BulletinRequest, BulletinSubscribe, ServerAddressRequest, ReplyBulletinRequest,
 * TagBulletinRequest, RandomBulletinRequest, FileRequest, AvatarRequest,
 * PrivateMessageSync, GroupSync, and GroupMessageSync. All actions require
 * signature verification before processing.
 * @param {string} from - Source XRPL address of the sender
 * @param {string} message - Raw JSON string of the message (for forwarding)
 * @param {object} json - Parsed and validated message object
 * @returns {Promise<void>}
 */
async function handleAction(from, message, json) {
	if (!VerifyJsonSignature(json)) {
		return;
	}

	// forward message only after signature verification succeeds
	if (json.To != undefined) {
		if (!isAllowed(from) || !isAllowed(json.To)) {
			ConsoleWarn(
				`[Chat Filter] Blocked forward: ${from} → ${json.To} (action=${json.Action})`,
			);
			SendMessage(
				from,
				GenServerNotifyError(
					MessageCode.NotAllowed,
					"Chat not allowed for this address",
				),
			);
			return;
		}
		SendMessage(json.To, message);
	}

	if (json.Action === ActionCode.BulletinRequest) {
		//send cache bulletin
		const addrFilter = WhiteList.length > 0 ? { address: { in: WhiteList } } : {};
		if (json.Hash) {
			const bulletin = await prisma.Bulletin.findFirst({
				where: {
					hash: json.Hash,
					...addrFilter,
				},
				select: {
					json: true,
				},
			});
			if (bulletin != null) {
				SendMessage(from, bulletin.json);
			}
		} else if (json.Address && json.Sequence) {
			const bulletin = await prisma.Bulletin.findFirst({
				where: {
					address: json.Address,
					sequence: json.Sequence,
					...addrFilter,
				},
				select: {
					json: true,
				},
			});
			if (bulletin != null) {
				SendMessage(from, bulletin.json);
			}
		}
	} else if (json.Action === ActionCode.BulletinSubscribe) {
		HandleBulletinSubscribe(json, from);
	} else if (json.Action === ActionCode.ServerAddressRequest && json.Page > 0) {
		const where = WhiteList.length > 0 ? { address: { in: WhiteList } } : {};

		const result = await prisma.Bulletin.groupBy({
			where,
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
		});
		const address_list = [];
		result.forEach((item) => {
			const new_item = {};
			new_item.Address = item.address;
			new_item.Count = item._count.address;
			address_list.push(new_item);
		});

		const total = await prisma.Bulletin.findMany({
			select: { address: true },
			distinct: ["address"],
		});

		const total_page = calcTotalPage(total.length, PageSize);
		if (address_list.length > 0) {
			const msg = GenServerAddressList(json.Page, total_page, address_list);
			SendMessage(from, msg);
		}
	} else if (json.Action === ActionCode.ReplyBulletinRequest && json.Page > 0) {
		const addrFilter = WhiteList.length > 0 ? { address: { in: WhiteList } } : {};
		// Check if parent bulletin is from a whitelisted address
		const parentBulletin = await prisma.Bulletin.findFirst({
			where: { hash: json.Hash, ...addrFilter },
			select: { hash: true },
		});
		if (parentBulletin === null) {
			return;
		}
		const reply_hash_list = await prisma.Reply.findMany({
			where: {
				post_hash: json.Hash,
			},
			select: {
				reply_hash: true,
			},
			skip: (json.Page - 1) * PageSize,
			take: PageSize,
			orderBy: { signed_at: "asc" },
		});
		let tmp_list = [];
		reply_hash_list.forEach((reply) => {
			tmp_list.push(reply.reply_hash);
		});

		const reply_json_list = await prisma.Bulletin.findMany({
			where: {
				hash: {
					in: tmp_list,
				},
				...addrFilter,
			},
			select: {
				json: true,
			},
			orderBy: { signed_at: "asc" },
		});
		tmp_list = [];
		reply_json_list.forEach((reply) => {
			let parsedReply;
			try {
				parsedReply = JSON.parse(reply.json);
			} catch {
				parsedReply = null;
			}
			if (parsedReply) tmp_list.push(parsedReply);
		});

		const total = await prisma.Reply.count({
			where: {
				post_hash: json.Hash,
			},
		});
		let total_page = 0;
		if (total > 0) {
			total_page = calcTotalPage(total, PageSize);
		}

		if (tmp_list.length > 0) {
			const msg = GenReplyBulletinList(json.Hash, json.Page, total_page, tmp_list);
			SendMessage(from, msg);
		} else {
			const post_bulletin = await prisma.Bulletin.findFirst({
				where: {
					hash: json.Hash,
				},
				select: {
					hash: true,
				},
			});
			if (post_bulletin === null) {
				const msg = GenBulletinRequestByHash(
					json.Hash,
					from,
					SelfPublicKey,
					SelfPrivateKey,
				);
				SendMessage(from, msg);
			}
		}
	} else if (json.Action === ActionCode.TagBulletinRequest && json.Page > 0) {
		const addrFilter = WhiteList.length > 0 ? { address: { in: WhiteList } } : {};
		const whereCondition = {
			AND: [
				...json.Tag.map((name) => ({ tags: { some: { name: name } } })),
				...Object.entries(addrFilter),
			],
		};
		const [list, total] = await prisma.$transaction([
			prisma.Bulletin.findMany({
				where: whereCondition,
				// include: { tags: true },
				select: {
					json: true,
					tags: { select: { name: true } },
				},
				orderBy: { signed_at: "desc" },
				skip: (json.Page - 1) * PageSize,
				take: PageSize,
			}),
			prisma.Bulletin.count({
				where: whereCondition,
			}),
		]);
		const tmp_list = [];
		list.forEach((bulletin) => {
			let parsedBulletin;
			try {
				parsedBulletin = JSON.parse(bulletin.json);
			} catch {
				parsedBulletin = null;
			}
			if (parsedBulletin) tmp_list.push(parsedBulletin);
		});
		let total_page = 0;
		if (total > 0) {
			total_page = calcTotalPage(total, PageSize);
		}
		if (tmp_list.length > 0) {
			const msg = GenTagBulletinList(json.Tag, json.Page, total_page, tmp_list);
			SendMessage(from, msg);
		}
	} else if (json.Action === ActionCode.RandomBulletinRequest) {
		const whereClause =
			WhiteList.length > 0
				? `WHERE address IN (${WhiteList.map((a) => `'${a}'`).join(",")})`
				: "";
		const list =
			await prisma.$queryRaw`SELECT * FROM "public"."Bulletin" ${whereClause} ORDER BY RANDOM() LIMIT ${20}`;
		const tmp_list = [];
		list.forEach((bulletin) => {
			let parsedBulletin;
			try {
				parsedBulletin = JSON.parse(bulletin.json);
			} catch {
				parsedBulletin = null;
			}
			if (parsedBulletin) tmp_list.push(parsedBulletin);
		});

		if (tmp_list.length > 0) {
			const msg = GenRandomBulletinList(tmp_list);
			SendMessage(from, msg);
		}
	} else if (json.Action === ActionCode.FileRequest) {
		await HandleFileRequest(json, from);
	} else if (json.Action === ActionCode.AvatarRequest) {
		await HandleAvatarRequest(json, from);
	} else if (json.Action === ActionCode.PrivateMessageSync) {
		// Throttle: detect a client-side sync loop. If the same (from, to) pair
		// re-sends the IDENTICAL (SelfSequence, PairSequence) request more than
		// PRIVATE_SYNC_MAX times within PRIVATE_SYNC_WINDOW_MS, the client's local
		// state is not advancing (a loop) — log a warning and skip the response so
		// the server is not flooded. A legitimate re-sync changes the sequences and
		// resets the counter.
		const throttleKey = `${from}:${json.To}`;
		const now = Date.now();
		let entry = privateSyncThrottle.get(throttleKey);
		if (
			!entry ||
			now - entry.windowStart > PRIVATE_SYNC_WINDOW_MS ||
			entry.selfSeq !== json.SelfSequence ||
			entry.pairSeq !== json.PairSequence
		) {
			entry = {
				selfSeq: json.SelfSequence,
				pairSeq: json.PairSequence,
				count: 0,
				windowStart: now,
			};
			privateSyncThrottle.set(throttleKey, entry);
		}
		entry.count++;
		if (entry.count > PRIVATE_SYNC_MAX) {
			ConsoleWarn(
				`[PrivateMessageSync] THROTTLED: ${entry.count} identical requests from ${from} to ${json.To} (SelfSeq=${json.SelfSequence}, PairSeq=${json.PairSequence}) in ${PRIVATE_SYNC_WINDOW_MS}ms — likely a client sync loop, skipping response`,
			);
			return;
		}
		await HandlePrivateMessageSync(json);
	} else if (json.Action === ActionCode.GroupSync) {
		if (!isAllowed(from)) {
			ConsoleWarn(`[Chat Filter] Blocked GroupSync from ${from}`);
			SendMessage(
				from,
				GenServerNotifyError(
					MessageCode.NotAllowed,
					"Chat not allowed for this address",
				),
			);
			return;
		}
		await HandleGroupSync(from);
	} else if (json.Action === ActionCode.GroupMessageSync) {
		if (!isAllowed(from)) {
			ConsoleWarn(`[Chat Filter] Blocked GroupMessageSync from ${from}`);
			SendMessage(
				from,
				GenServerNotifyError(
					MessageCode.NotAllowed,
					"Chat not allowed for this address",
				),
			);
			return;
		}
		const members = groupMap[json.Hash];
		if (members) {
			const tmp_members = shuffleArray(members);
			for (let i = 0; i < tmp_members.length; i++) {
				const member = tmp_members[i];
				if (
					from !== member &&
					Conns[member] &&
					Conns[member].readyState === WebSocket.OPEN
				) {
					SendMessage(member, message);
					return;
				}
			}
		}
	}
}

/**
 * Synchronize a reconnecting client by sending its missing bulletins, pending file
 * chunks, incomplete ECDH handshakes, and group membership data. Called during the
 * Declare action flow when a new client connection is established.
 * @param {string} address - The XRPL address of the client to synchronize
 * @returns {Promise<void>}
 */
async function SyncClientRequest(address) {
	ConsoleInfo(`========================================`);
	ConsoleInfo(`[SyncClientRequest] Starting sync for ${address}`);
	ConsoleInfo(
		`[SyncClientRequest] SelfPublicKey=${SelfPublicKey?.substring(0, 20)}...`,
	);
	// Verify connection is ready
	const ws = Conns[address];
	if (!ws || ws.readyState !== WebSocket.OPEN) {
		ConsoleWarn(
			`[SyncClientRequest] ABORT: connection for ${address} not ready (state=${ws?.readyState})`,
		);
		return;
	}
	ConsoleInfo(`[SyncClientRequest] Connection OK, readyState=${ws.readyState}`);

	// Wait for client to finish its own connection handshake (AvatarRequest, BulletinSubscribe etc.)
	// The client needs cachedSeed/cachedAddress to be set before it can process incoming Action messages
	ConsoleInfo(
		`[SyncClientRequest] Waiting 1.5s for ${address} to finish connection handshake...`,
	);
	await new Promise((resolve) => setTimeout(resolve, 1500));
	ConsoleInfo(
		`[SyncClientRequest] Wait complete, proceeding with sync for ${address}`,
	);

	// bulletin — find first gap, then chase from there
	const gap_sequence = await FindFirstMissingSequence(address);
	ConsoleInfo(
		`[SyncClientRequest] FindFirstMissingSequence result: ${gap_sequence}`,
	);
	let sentBulletinRequest = false;
	if (gap_sequence === null) {
		// No gap — chase next sequence after current max
		const next_seq = await GetMaxSequencePlusOne(address);
		ConsoleInfo(`[SyncClientRequest] GetMaxSequencePlusOne result: ${next_seq}`);
		if (next_seq === null) {
			// Database empty for this address — start from seq=1
			ConsoleInfo(
				`[SyncClientRequest] ${address}: no local bulletins, starting sync from seq=1`,
			);
			const msg = GenBulletinRequest(
				address,
				1,
				address,
				SelfPublicKey,
				SelfPrivateKey,
			);
			// Self-test: verify our own signature before sending
			let selfSigOk = false;
			try {
				selfSigOk = VerifyJsonSignature(JSON.parse(msg));
			} catch (e) {
				ConsoleWarn(`[SyncClientRequest] Self-signature test ERROR: ${e.message}`);
			}
			ConsoleInfo(
				`[SyncClientRequest] Self-signature test: ${selfSigOk ? "PASS" : "FAIL"} for BulletinRequest`,
			);
			ConsoleInfo(`[SyncClientRequest] BulletinRequest FULL payload: ${msg}`);
			SendMessage(address, msg);
			ConsoleInfo(`[SyncClientRequest] BulletinRequest SENT via SendMessage`);
			sentBulletinRequest = true;
		} else {
			ConsoleInfo(
				`[SyncClientRequest] Sending BulletinRequest seq=${next_seq} to ${address} (chasing new)`,
			);
			const msg = GenBulletinRequest(
				address,
				next_seq,
				address,
				SelfPublicKey,
				SelfPrivateKey,
			);
			// Self-test: verify our own signature before sending
			let selfSigOk = false;
			try {
				selfSigOk = VerifyJsonSignature(JSON.parse(msg));
			} catch (e) {
				ConsoleWarn(`[SyncClientRequest] Self-signature test ERROR: ${e.message}`);
			}
			ConsoleInfo(
				`[SyncClientRequest] Self-signature test: ${selfSigOk ? "PASS" : "FAIL"} for BulletinRequest`,
			);
			ConsoleInfo(`[SyncClientRequest] BulletinRequest FULL payload: ${msg}`);
			SendMessage(address, msg);
			ConsoleInfo(`[SyncClientRequest] BulletinRequest SENT via SendMessage`);
			sentBulletinRequest = true;
		}
	} else {
		// Gap exists — fetch from the missing point
		ConsoleInfo(
			`[SyncClientRequest] Sending BulletinRequest seq=${gap_sequence} to ${address} (filling gap)`,
		);
		const msg = GenBulletinRequest(
			address,
			gap_sequence,
			address,
			SelfPublicKey,
			SelfPrivateKey,
		);
		// Self-test: verify our own signature before sending
		let selfSigOk = false;
		try {
			selfSigOk = VerifyJsonSignature(JSON.parse(msg));
		} catch (e) {
			ConsoleWarn(`[SyncClientRequest] Self-signature test ERROR: ${e.message}`);
		}
		ConsoleInfo(
			`[SyncClientRequest] Self-signature test: ${selfSigOk ? "PASS" : "FAIL"} for BulletinRequest`,
		);
		ConsoleInfo(`[SyncClientRequest] BulletinRequest FULL payload: ${msg}`);
		SendMessage(address, msg);
		ConsoleInfo(`[SyncClientRequest] BulletinRequest SENT via SendMessage`);
		sentBulletinRequest = true;
	}

	// Wait for client to respond with bulletin (ObjectType=400)
	if (sentBulletinRequest) {
		ConsoleInfo(
			`[SyncClientRequest] Waiting up to 5s for Bulletin response from ${address}...`,
		);
		const start = Date.now();
		while (Date.now() - start < 5000) {
			const bulletin = await prisma.Bulletin.findFirst({
				where: { address },
				orderBy: { sequence: "desc" },
			});
			if (bulletin) {
				ConsoleInfo(
					`[SyncClientRequest] Bulletin response received! hash=${bulletin.hash}, seq=${bulletin.sequence}`,
				);
				break;
			}
			await new Promise((resolve) => setTimeout(resolve, 500));
		}
		const bulletin = await prisma.Bulletin.findFirst({
			where: { address },
			orderBy: { sequence: "desc" },
		});
		if (!bulletin) {
			ConsoleWarn(
				`[SyncClientRequest] ❌ TIMEOUT: ${address} did NOT return bulletin after 5s!`,
			);
			ConsoleWarn(
				`[SyncClientRequest] Client may have dropped the request (schema/signature failure) or has no bulletins.`,
			);
		}
	}

	// file — only fetch files that don't already have an active request
	const pending_files = await prisma.File.findMany({
		where: {
			is_saved: false,
			bulletins: {
				some: { address },
			},
		},
	});
	ConsoleInfo(
		`[SyncClientRequest] Found ${pending_files.length} pending file(s) for ${address}`,
	);
	for (const file of pending_files) {
		// Skip if there's already an active request for this file
		const hasActiveRequest = [...fileRequestList.values()].some(
			(r) => r.Hash === file.hash && r.Address === address,
		);
		if (hasActiveRequest) {
			ConsoleInfo(
				`[SyncClientRequest] Skipping ${file.hash} - active request already exists`,
			);
			continue;
		}
		ConsoleInfo(
			`[SyncClientRequest] Requesting file ${file.hash} from ${address} (cursor=${file.chunk_cursor + 1})`,
		);
		fetchBulletinFile(address, address, file.hash, file.chunk_cursor + 1);
	}

	// ecdh
	if (isAllowed(address)) {
		const dh = await prisma.ECDH.findFirst({
			where: {
				OR: [
					{
						address1: address,
						json1: "",
					},
					{
						address2: address,
						json2: "",
					},
				],
			},
		});
		if (dh != null) {
			if (dh.json1 === "") {
				SendMessage(address, dh.json2);
			} else if (dh.json2 === "") {
				SendMessage(address, dh.json1);
			}
		}
	} else {
		ConsoleDebug(`[Chat Filter] Skipped ECDH sync for ${address}`);
	}

	// group
	if (isAllowed(address)) {
		const msg = GenGroupSync(SelfPublicKey, SelfPrivateKey);
		SendMessage(address, msg);

		await HandleGroupSync(address);
	} else {
		ConsoleDebug(`[Chat Filter] Skipped Group sync for ${address}`);
	}
}

async function checkMessage(ws, message, isFromNode = false) {
	const connAddress = fetchConnAddress(ws);
	ConsoleInfo(
		`###################LOG################### Client Message (from=${connAddress || "unknown"}, isFromNode=${isFromNode}):`,
	);
	ConsoleInfo(`${message}`);
	// ConsoleInfo(`${message.slice(0, 512)}`)
	const json = MsgValidate(message);
	if (json === false) {
		ConsoleWarn(
			`[checkMessage] ❌ Schema validation FAILED for message from ${connAddress || "unknown"}, terminating connection`,
		);
		ws.send(
			GenServerNotifyError(
				MessageCode.JsonSchemaInvalid,
				"JSON schema validation failed",
			),
		);
		terminateConn(ws, "schema_validation_failed");
	} else if (json.ObjectType) {
		ConsoleInfo(
			`[checkMessage] ObjectType=${json.ObjectType} from ${connAddress}`,
		);
		await handleObject(connAddress, message, json, isFromNode);
	} else if (json.Action) {
		ConsoleInfo(`[checkMessage] Action=${json.Action} from ${connAddress}`);
		const address = rippleKeyPairs.deriveAddress(json.PublicKey);
		if (Conns[address] === ws) {
			await handleAction(address, message, json);
		} else {
			const connAddress = fetchConnAddress(ws);
			if (connAddress !== null && connAddress !== address) {
				// using different address in same connection
				ConsoleWarn(
					`[terminateConn] AddressMismatch: conn=${connAddress} msg=${address}`,
				);
				ws.send(
					GenServerNotifyError(
						MessageCode.AddressMismatch,
						"Address changed within connection",
					),
				);
			} else {
				if (!VerifyJsonSignature(json)) {
					ConsoleWarn(
						`[terminateConn] SignatureInvalid for address ${address} action=${json.Action}`,
					);
					ws.send(
						GenServerNotifyError(
							MessageCode.SignatureInvalid,
							"Message signature verification failed",
						),
					);
					terminateConn(ws, "signature_invalid");
					return;
				}

				if (json.Timestamp + DECLARE_TIMESTAMP_TOLERANCE_MS < Date.now()) {
					ConsoleWarn(
						`[terminateConn] TimestampInvalid: msg=${json.Timestamp} now=${Date.now()} action=${json.Action}`,
					);
					ws.send(
						GenServerNotifyError(
							MessageCode.TimestampInvalid,
							"Message timestamp out of range",
						),
					);
					terminateConn(ws, "timestamp_invalid");
					return;
				}

				if (
					connAddress === null &&
					Conns[address] === undefined &&
					json.Action === ActionCode.Declare
				) {
					const isNodeConnection = json.URL != null && CheckServerURL(json.URL);

					// new connection and new address
					ConsoleWarn(
						`connected <===> ${isNodeConnection ? "node" : "client"} : <${address}>`,
					);
					ws._connAddress = address;
					Conns[address] = ws;
					if (isNodeConnection) {
						// Server Connection
						NodeList.push({
							URL: json.URL,
						});
						NodeList = UniqArray(NodeList);
						SyncNodeData(json.URL);
					}

					const msg = GenDeclare(SelfPublicKey, SelfPrivateKey, SelfURL);
					ConsoleInfo(`[Declare] Sending Declare to ${address}`);
					SendMessage(address, msg);
					// Only sync client data for actual clients, not nodes
					if (!isNodeConnection) {
						ConsoleInfo(`[Declare] Calling SyncClientRequest for ${address}`);
						await SyncClientRequest(address);
					}
				} else if (
					Conns[address] &&
					Conns[address] !== ws &&
					Conns[address].readyState === WebSocket.OPEN
				) {
					// new connection kick old conection with same address
					ConsoleWarn(`[terminateConn] KickOldConn: address=${address}`);
					try {
						Conns[address].send(
							GenServerNotifyInfo(
								MessageCode.KickedByNewConn,
								"Kicked by new connection",
							),
						);
					} catch {}
					Conns[address].close();
					ws._connAddress = address;
					Conns[address] = ws;
				} else {
					// Fallback: unregistered connection with non-Declare message
					const actionLabel = json.Action ?? "unknown";
					ConsoleWarn(
						`[terminateConn] UnregisteredNonDeclare: connAddr=${connAddress} msgAddr=${address} action=${actionLabel}`,
					);
					ws.send(
						GenServerNotifyError(
							MessageCode.AddressMismatch,
							"Duplicate connection rejected",
						),
					);
					terminateConn(ws, `unregistered_action_${actionLabel}`);
				}
			}
		}
	}
}

// === Node Interaction ===
/** Send to a peer node by URL (uses NodeConns map). */
function SendToNode(url, message) {
	sendTo(url, message, NodeConns);
}

function fetchFileFromNode(url, address, hash, chunk_cursor) {
	const nonce = genFileNonce();
	const tmp = {
		Type: FileRequestType.File,
		Nonce: nonce,
		Hash: hash,
		ChunkCursor: chunk_cursor,
		Address: address,
		NodeUrl: url,
		Timestamp: Date.now(),
	};
	const prev_request =
		fileRequestList.has(nonce) ||
		fileRequestList.values().some((r) => r.Hash === hash);
	if (!prev_request) {
		fileRequestList.set(nonce, tmp);
		const msg = GenFileRequest(
			FileRequestType.File,
			hash,
			nonce,
			chunk_cursor,
			SelfPublicKey,
			SelfPrivateKey,
		);
		SendToNode(url, msg);
	}
}

async function downloadBulletinFile(url) {
	const address = fetchNodeConnURL(NodeConns[url]);
	if (address === null) {
		return;
	}

	const file_list = await prisma.File.findMany({
		where: {
			is_saved: {
				equals: false,
			},
			...(WhiteList.length > 0
				? {
						bulletins: {
							some: {
								address: { in: WhiteList },
							},
						},
					}
				: {}),
		},
	});

	if (file_list && file_list.length > 0) {
		for (let i = 0; i < file_list.length; i++) {
			const file = file_list[i];
			fetchFileFromNode(url, address, file.hash, file.chunk_cursor + 1);
		}
	}
}

function pullBulletin(url) {
	// clone all bulletin from server
	// pull step 1: fetch all account
	const msg = GenServerAddressListRequest(1, SelfPublicKey, SelfPrivateKey);
	SendToNode(url, msg);
}

/**
 * Push new bulletins to a peer node by requesting each address's next sequence.
 * Queries the database for max(sequence) per address and sends a BulletinRequest
 * for the next expected sequence number to the target node.
 * @param {string} url - WebSocket URL of the peer node to push bulletins to
 * @returns {Promise<void>}
 */
async function pushBulletin(url) {
	// Use GROUP BY to get max(sequence) per address in a single query instead of loading all rows
	const whereClause =
		WhiteList.length > 0
			? `WHERE address IN (${WhiteList.map((a) => `'${a}'`).join(",")})`
			: "";
	const bulletin_list = await prisma.$queryRawUnsafe(
		`SELECT address, MAX(sequence) as max_seq FROM "Bulletin" ${whereClause} GROUP BY address`,
	);

	for (const row of bulletin_list) {
		const msg = GenBulletinRequest(
			String(row.address),
			Number(row.max_seq) + 1,
			String(row.address),
			SelfPublicKey,
			SelfPrivateKey,
		);
		SendToNode(url, msg);
	}
}

function SyncNodeData(url) {
	ConsoleWarn(`sync node data`);
	pullBulletin(url);
	pushBulletin(url);
	downloadBulletinFile(url);
}

function connectNode(node) {
	ConsoleInfo(
		`--------------------------connect to node--------------------------`,
	);
	ConsoleWarn(node);
	const ws = new WebSocket(node.URL);
	ws.on("open", function open() {
		ConsoleWarn(`connected <===> ${node.URL}`);
		ws.send(GenDeclare(SelfPublicKey, SelfPrivateKey, SelfURL));
		ws._nodeUrl = node.URL;
		NodeConns[node.URL] = ws;
		SyncNodeData(node.URL);
	});

	ws.on("message", async (data, isBinary) => {
		try {
			if (isBinary) {
				await handleBinaryMessage(data);
			} else {
				const message = data.toString();
				await checkMessage(ws, message, true);
			}
		} catch (err) {
			ConsoleError(
				`[node-message-error] Failed to process node message from ${fetchNodeConnURL(ws)}: ${err.message}`,
			);
			if (err.stack) {
				ConsoleError(err.stack);
			}
		}
	});

	ws.on("close", function close() {
		try {
			ConsoleWarn(`disconnected <=X=> ${node.URL}`);
			terminateConn(ws);
		} catch (err) {
			ConsoleError(
				`[node-close-error] Failed to handle node close for ${node.URL}: ${err.message}`,
			);
		}
	});

	ws.on("error", (error) => {
		ConsoleWarn(`Node connection error for ${node.URL}: ${error.message}`);
	});
}

function keepNodeConn() {
	const notConnected = [];
	NodeList.forEach((node) => {
		if (NodeConns[node.URL] === undefined) {
			notConnected.push(node);
		}
	});

	if (notConnected.length === 0) {
		return;
	}
	ConsoleWarn(
		`--------------------------keepNodeConn--------------------------`,
	);

	const random = Math.floor(Math.random() * notConnected.length);
	const randomNode = notConnected[random];
	if (randomNode != null) {
		connectNode(randomNode);
	}
}

function keepNodeSync() {
	ConsoleWarn(
		`--------------------------keepNodeSync--------------------------`,
	);
	NodeList.forEach((node) => {
		if (NodeConns[node.URL]) {
			SyncNodeData(node.URL);
		}
	});
}

async function loadgroupMap() {
	const group_list = await prisma.Group.findMany({
		where: { deleted_at: null },
	});
	for (let i = 0; i < group_list.length; i++) {
		const group = group_list[i];
		let group_member;
		try {
			group_member = JSON.parse(group.member);
		} catch {
			continue;
		}
		group_member.push(group.created_by);
		groupMap[group.hash] = group_member;
	}
	ConsoleWarn(`*****groupMap:`);
	ConsoleInfo(JSON.stringify(groupMap, null, 2));
}

async function printStat() {
	const bulletinCount = await prisma.Bulletin.count();
	ConsoleWarn(`BulletinCount: ${bulletinCount}`);

	const fileCount = await prisma.File.count();
	ConsoleWarn(`****FileCount: ${fileCount}`);

	const addressCount = await prisma.Bulletin.groupBy({
		by: "address",
	});
	ConsoleWarn(`*AddressCount: ${addressCount.length}`);

	loadgroupMap();
}

// refreshData - Startup routine that rebuilds bulletin chain links and association indexes.
// Phase 1: Restore pre_hash <-> next_hash pointers on the bulletin chain.
// Phase 2: Batch-create all tags referenced across bulletins (single upsert).
//           Then bulk-connect tag relations so each Bulletin node has its tags linked.
// Phase 3: Upsert file records and connect Bulletin <-> File relations per-bulletin,
//           then fetch any missing chunks from peer nodes.
// Phase 4: Batch-create Reply (quote) links in a single insertMany to avoid N+1 queries.
async function refreshData() {
	// Fetch all bulletins needed for processing
	const bulletin_list = await prisma.Bulletin.findMany({
		select: {
			hash: true,
			pre_hash: true,
			sequence: true,
			json: true,
			signed_at: true,
		},
		orderBy: { sequence: "desc" },
	});

	// Phase 1: Restore next_hash chain pointers
	for (let i = 0; i < bulletin_list.length; i++) {
		const bulletin = bulletin_list[i];
		if (bulletin.sequence != 1) {
			try {
				await prisma.Bulletin.update({
					where: { hash: bulletin.pre_hash },
					data: { next_hash: bulletin.hash },
				});
			} catch (e) {
				ConsoleDebug(
					`[refreshData] Failed to update next_hash for pre_hash ${bulletin.pre_hash} -> ${bulletin.hash}: ${e.message}`,
				);
			}
		}
	}

	// Pre-parse all bulletin JSON upfront
	const parsed = bulletin_list
		.map((b) => {
			let bJson;
			try {
				bJson = JSON.parse(b.json);
			} catch {
				bJson = null;
			}
			return bJson ? { hash: b.hash, json: bJson, signed_at: b.signed_at } : null;
		})
		.filter(Boolean);

	// Phase 2: Batch-create all unique tags across every bulletin, then bulk-connect
	const allTagNames = new Set();
	for (const { json } of parsed) {
		if (json.Tag && Array.isArray(json.Tag)) {
			for (const tag of json.Tag) allTagNames.add(tag);
		}
	}

	if (allTagNames.size > 0) {
		await prisma.Tag.createMany({
			data: [...allTagNames].map((name) => ({ name })),
			skipDuplicates: true,
		});
	}

	// Bulk-connect tags to bulletins in groups to avoid one DB round-trip per bulletin
	const tagBatchSize = 50;
	for (let i = 0; i < parsed.length; i += tagBatchSize) {
		const batch = parsed
			.slice(i, i + tagBatchSize)
			.filter(
				({ json }) => json.Tag && Array.isArray(json.Tag) && json.Tag.length > 0,
			);
		if (batch.length === 0) continue;

		await prisma.$transaction(
			batch.map(({ hash, json: bJson }) =>
				prisma.Bulletin.update({
					where: { hash },
					data: {
						tags: {
							connect: [...new Set(bJson.Tag)].map((name) => ({ name })),
						},
					},
				}),
			),
		);
	}

	// Phase 3: Files - must stay per-bulletin (BindBulletinFile ties files to one bulletin)
	for (const { hash, json: bJson } of parsed) {
		if (bJson.File) {
			const bulletin_address = rippleKeyPairs.deriveAddress(bJson.PublicKey);
			const files_to_fetch = await BindBulletinFile(hash, bJson.File);
			for (let i = 0; i < files_to_fetch.length; i++) {
				const file = files_to_fetch[i];
				if (!file.is_saved) {
					fetchBulletinFile(
						bulletin_address,
						bulletin_address,
						file.hash,
						file.chunk_cursor + 1,
					);
				}
			}
		}
	}

	// Phase 4: Batch-quote links - collect all new replies, insert in one shot
	const existingQuotes = await prisma.Reply.findMany({
		select: { post_hash: true, reply_hash: true },
	});
	const existingSet = new Set(
		existingQuotes.map((q) => `${q.post_hash}:${q.reply_hash}`),
	);

	const newReplies = [];
	for (const { hash, json: bJson, signed_at } of parsed) {
		if (bJson.Quote && Array.isArray(bJson.Quote)) {
			for (const quote of bJson.Quote) {
				const key = `${quote.Hash}:${hash}`;
				if (!existingSet.has(key)) {
					newReplies.push({
						post_hash: quote.Hash,
						reply_hash: hash,
						signed_at,
					});
					existingSet.add(key);
				}
			}
		}
	}

	if (newReplies.length > 0) {
		await prisma.Reply.createMany({ data: newReplies, skipDuplicates: true });
		ConsoleInfo(
			`[refreshData] Linked ${newReplies.length} new quote(s) in batch`,
		);
	}
}

function startServerDaemon() {
	if (ServerDaemon === null) {
		ServerDaemon = new WebSocketServer({
			port: 8100, // to bind on 80, must use "sudo node main.js"
			clientTracking: true,
			maxPayload: 2 * 1024 * 1024,
		});

		ServerDaemon.on("connection", function connection(ws) {
			ws.on("message", async (data, isBinary) => {
				try {
					if (isBinary) {
						handleBinaryMessage(data);
					} else {
						const message = data.toString();
						await checkMessage(ws, message, false);
					}
				} catch (err) {
					ConsoleError(
						`[message-error] Failed to process client message: ${err.message}`,
					);
					if (err.stack) {
						ConsoleError(err.stack);
					}
				}
			});

			ws.on("close", function close() {
				try {
					const connAddress = fetchConnAddress(ws);
					if (connAddress != null) {
						ConsoleWarn(`client <${connAddress}> disconnect...`);
						delete Conns[connAddress];
						clearSubscribe(connAddress);
					}
				} catch (err) {
					ConsoleError(
						`[close-error] Failed to handle client close: ${err.message}`,
					);
				}
			});

			ws.on("error", (error) => {
				ConsoleWarn(`Client WebSocket error: ${error.message}`);
			});
		});
	}
}

async function main() {
	fs.mkdirSync(path.resolve(`./${FileDir}`), { recursive: true });
	fs.mkdirSync(path.resolve(`./${AvatarDir}`), { recursive: true });

	const seed = rippleKeyPairs.generateSeed("RandomSeed", "secp256k1");
	const keypair = rippleKeyPairs.deriveKeypair(seed);
	SelfAddress = rippleKeyPairs.deriveAddress(keypair.publicKey);
	SelfPublicKey = keypair.publicKey;
	SelfPrivateKey = keypair.privateKey;
	ConsoleWarn(`use***Address: ${SelfAddress}`);

	await printStat();
	await refreshData();
	startServerDaemon();

	// === Node Interaction: load config & start daemons ===
	try {
		let config = fs.readFileSync(ConfigPath, "utf8");
		config = JSON.parse(config);
		ConsoleWarn(`*******Config:`);
		ConsoleInfo(JSON.stringify(config, null, 2));
		if (config.SelfURL !== "") {
			SelfURL = config.SelfURL;
		}
		NodeList = config.NodeList;
		ConsoleInfo(JSON.stringify(NodeList, null, 2));

		const wl = config.WhiteList;
		if (Array.isArray(wl)) {
			WhiteList = wl;
		}
		ConsoleWarn(`WhiteList loaded: ${WhiteList.length} address(es)`);
		if (WhiteList.length > 0) {
			ConsoleWarn(
				"⚠️  WhiteList mode enabled - only whitelisted addresses have full access",
			);
		} else {
			ConsoleWarn("🌐  WhiteList is empty - open to all addresses");
		}

		if (jobNodeConn === null) {
			jobNodeConn = setInterval(keepNodeConn, NODE_RECONNECT_INTERVAL_MS);
		}
		if (jobNodeSync === null) {
			jobNodeSync = setInterval(keepNodeSync, NODE_SYNC_INTERVAL_MS);
		}

		// Periodic purge of expired file request entries
		if (jobFilePurge === null) {
			jobFilePurge = setInterval(() => {
				purgeExpiredFileRequests();
			}, FILE_PURGE_INTERVAL_MS);
		}
	} catch (error) {
		ConsoleError(
			`[main] Failed to load node config from ${ConfigPath}: ${error.message}`,
		);
	}
}

async function gracefulShutdown(signal) {
	ConsoleWarn(`[${signal}] Shutting down gracefully...`);
	if (jobNodeConn) clearInterval(jobNodeConn);
	if (jobNodeSync) clearInterval(jobNodeSync);
	if (jobFilePurge) clearInterval(jobFilePurge);

	// Notify all connected clients before closing
	const shutdownMsg = GenServerNotifyInfo(
		MessageCode.ServerShutdown,
		"Server is shutting down",
	);
	for (const addr in Conns) {
		try {
			if (Conns[addr].readyState === WebSocket.OPEN) {
				Conns[addr].send(shutdownMsg);
			}
		} catch {}
	}
	// Give clients time to receive the notification
	await new Promise((resolve) => setTimeout(resolve, 1000));

	for (const addr in Conns) {
		try {
			Conns[addr].close();
		} catch {}
	}
	for (const url in NodeConns) {
		try {
			NodeConns[url].close();
		} catch {}
	}
	ConsoleWarn("All connections closed. Exiting.");
	await prisma.$disconnect();
	process.exit(0);
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

main();
