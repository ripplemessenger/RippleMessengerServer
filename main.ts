import "dotenv/config";
import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { WebSocket, WebSocketServer } from "ws";
import rippleKeyPairs from "ripple-keypairs";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient({
	adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
});

import {
	ConsoleInfo,
	ConsoleWarn,
	ConsoleError,
	ConsoleDebug,
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
	FileMaxSize,
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
let SelfURL: string | undefined;
let SiteURL: string | undefined;
let SelfAddress: string;
let SelfPublicKey: string;
let SelfPrivateKey: string;

/** Remote peer-node network: list of all nodes + whitelist of allowed addresses */
let NodeList: { URL: string }[] = [];
let WhiteList: string[] = [];

function isAllowed(address: string): boolean {
	if (WhiteList.length === 0) return true;
	return WhiteList.includes(address);
}

/** Client-server daemon and active WebSocket connections keyed by address or URL */
let ServerDaemon: WebSocketServer | null = null;
const Conns: Record<string, WebSocket> = {}; // client connections: address -> WebSocket
let jobNodeConn: NodeJS.Timeout | null = null; // interval timer for reconnecting dropped node links
let jobNodeSync: NodeJS.Timeout | null = null; // interval timer for periodic bulletin sync across nodes
let jobFilePurge: NodeJS.Timeout | null = null; // interval timer for purging expired file requests
const NodeConns: Record<string, WebSocket> = {}; // node-to-node connections: URL -> WebSocket

/** Pending file-transfer requests queued while awaiting binary chunks */
interface FileRequestEntry {
	Type: number;
	Nonce: number;
	Hash: string;
	Address?: string;
	From?: string;
	To?: string;
	ChunkCursor?: number;
	NodeUrl?: string;
	Timestamp: number;
	GroupHash?: string;
}

const fileRequestList = new Map<number, FileRequestEntry>();

// Retry cap for bulletin file downloads: a file that keeps hash-mismatching
// (or whose re-request keeps failing) is abandoned after this many attempts
// instead of looping forever and stalling the sync pipeline.
const MAX_FILE_RETRIES = 3;
const fileRetryCount = new Map<string, number>();

// --- Paced bulletin-file fetching -------------------------------------------------
// A full sync can surface ~90 file downloads at once when the bulletins land.
// Firing every request immediately saturated the peer node's message pipeline and
// starved bulletin sync: with files flowing the cache advanced ~50 bulletins/120s,
// with file fetching paused it reached 302 bulletins/75s. Two rules keep the peer
// responsive:
//   1. bulletin sync has priority — no file is started while bulletins still flow;
//   2. at most ONE file request is outstanding at a time, and the next is only
//      released when the previous file lands (or times out).
// The peer serves a file for tens of seconds and processes our frames from one
// queue, so a larger backlog would block every bulletin round-trip behind it.
interface FileFetchJob {
	from: string;
	address: string;
	hash: string;
	cursor: number;
	viaNode: boolean;
}
/** FIFO of hashes waiting for a slot. */
const fileFetchQueue: string[] = [];
/** Original request for every hash that is queued or in flight (needed to retry). */
const fileFetchJobs = new Map<string, FileFetchJob>();
let fileFetchTimer: NodeJS.Timeout | null = null;

const FILE_FETCH_QUIET_MS = 4000;
// A request entry lives FILE_REQUEST_TTL_MS (120s) in fileRequestList. If the peer
// has not answered by then the entry is purged and the chunk arrives as an
// "Unknown nonce" — the file would be silently abandoned. The slot is therefore
// released when the request stops being outstanding, and the file is re-queued
// for another attempt (bounded by MAX_FILE_RETRIES).
const FILE_FETCH_TICK_MS = 1000;
// The peer serves roughly one chunk per 10-25s. A small window hides that latency
// without building a node-side queue deep enough to starve bulletin sync or to
// push a file's first chunk past its TTL.
const FILE_FETCH_MAX_INFLIGHT = 2;
let lastBulletinAt = 0;
const fileFetchInFlight = new Map<string, number>();

/** True while a queued request for this hash is still waiting on the peer. */
function hasOutstandingFileRequest(hash: string): boolean {
	for (const r of fileRequestList.values()) {
		if (r.Hash === hash) return true;
	}
	return false;
}

/** Release an in-flight slot once a queued download finishes. */
function markFileFetchDone(hash: string): void {
	fileFetchInFlight.delete(hash);
	fileFetchJobs.delete(hash);
}

/** Queue a bulletin file download instead of requesting it immediately. */
function enqueueFileFetch(
	from: string,
	address: string,
	hash: string,
	cursor: number,
	viaNode = false,
): void {
	if (fileFetchJobs.has(hash)) return;
	fileFetchJobs.set(hash, { from, address, hash, cursor, viaNode });
	fileFetchQueue.push(hash);
	pumpFileFetchQueue();
}

function pumpFileFetchQueue(): void {
	if (fileFetchTimer !== null) return;
	fileFetchTimer = setInterval(() => {
		if (fileFetchQueue.length === 0 && fileFetchInFlight.size === 0) {
			if (fileFetchTimer !== null) clearInterval(fileFetchTimer);
			fileFetchTimer = null;
			return;
		}
		const now = Date.now();
		for (const [hash, startedAt] of fileFetchInFlight) {
			// A multi-chunk file legitimately stays in flight for minutes, and every
			// answered chunk re-registers the next one — so "still waiting on the
			// peer" is the only correct progress signal. A time-based timeout here
			// would restart a healthy download from chunk 1.
			if (hasOutstandingFileRequest(hash)) continue;
			// No request left: the peer's answer was consumed (the file finished and
			// markFileFetchDone already dropped it) or the entry expired unanswered.
			fileFetchInFlight.delete(hash);
			const attempts = fileRetryCount.get(hash) ?? 0;
			if (attempts >= MAX_FILE_RETRIES) {
				ConsoleWarn(
					`[fileFetchQueue] ${hash}: giving up after ${attempts} queued attempts`,
				);
				fileRetryCount.delete(hash);
				fileFetchJobs.delete(hash);
				continue;
			}
			fileRetryCount.set(hash, attempts + 1);
			ConsoleWarn(
				`[fileFetchQueue] ${hash}: request expired without a chunk after ${Math.round((now - startedAt) / 1000)}s, re-queued (attempt ${attempts + 1}/${MAX_FILE_RETRIES})`,
			);
			fileFetchQueue.push(hash);
		}
		if (fileFetchInFlight.size >= FILE_FETCH_MAX_INFLIGHT) {
			// Enough downloads are already outstanding.
			return;
		}
		if (now - lastBulletinAt < FILE_FETCH_QUIET_MS) {
			// Bulletin sync still running — let it finish first.
			return;
		}
		const nextHash = fileFetchQueue.shift();
		if (nextHash === undefined) return;
		const job = fileFetchJobs.get(nextHash);
		if (job === undefined) return;
		fileFetchInFlight.set(job.hash, now);
		try {
			if (job.viaNode) {
				fetchFileFromNode(job.from, job.address, job.hash, job.cursor);
			} else {
				fetchBulletinFile(job.from, job.address, job.hash, job.cursor);
			}
		} catch (e: any) {
			ConsoleWarn(
				`[fileFetchQueue] failed to request ${job.hash}: ${(e as Error).message}`,
			);
		}
	}, FILE_FETCH_TICK_MS);
	if (typeof fileFetchTimer.unref === "function") fileFetchTimer.unref();
}

/** Group membership map (group_hash -> member list) and subscription map (address -> subscribed addresses) */
const groupMap: Record<string, string[]> = {};
const subscribeMap: Record<string, string[]> = {};

/** Track which addresses have already had N+1 confirmation sent during Declare-triggered sync */
const syncConfirmSent: Record<string, unknown> = {};

/**
 * Throttle for PrivateMessageSync: detects a client-side sync loop. If the same
 * (from, to) pair re-sends the IDENTICAL (SelfSequence, PairSequence) request more
 * than PRIVATE_SYNC_MAX times within PRIVATE_SYNC_WINDOW_MS, it is a loop (the
 * client's local state never advances) — log a warning and skip the response so
 * the server is not flooded. A legitimate re-sync changes the sequences and resets
 * the counter. Key: `${from}:${to}`.
 */
const privateSyncThrottle = new Map<string, {
	selfSeq: number;
	pairSeq: number;
	count: number;
	windowStart: number;
}>();
const PRIVATE_SYNC_MAX = 5;
const PRIVATE_SYNC_WINDOW_MS = 10000;

/**
 * Chain backfill throttle.
 *
 * The cache policy is deliberately *fragmented*: any signature-valid bulletin is
 * stored regardless of whether its ancestors are present (a relay must never let
 * one missing sequence block every later post by that address). The cost is that
 * a hole which can never be filled would otherwise cause a BulletinRequest on
 * every subsequent bulletin for that address.
 *
 * Key: address → { seq, ts }. Only re-request the SAME gap after
 * BACKFILL_MIN_INTERVAL_MS; if the gap moved (it got filled), request at once.
 */
const backfillThrottle = new Map<string, { seq: number; ts: number }>();
const BACKFILL_MIN_INTERVAL_MS = 10 * 1000;
const BACKFILL_THROTTLE_MAX_ENTRIES = 5000;

/**
 * Decide whether a backfill request for `address` at `seq` should be sent now.
 * @param {string} address - Chain owner
 * @param {number} seq - Missing sequence being requested
 * @returns {boolean} True if the request should be sent
 */
function shouldRequestBackfill(address: string, seq: number): boolean {
	const now = Date.now();
	const prev = backfillThrottle.get(address);
	if (prev && prev.seq === seq && now - prev.ts < BACKFILL_MIN_INTERVAL_MS) {
		return false;
	}
	if (backfillThrottle.size > BACKFILL_THROTTLE_MAX_ENTRIES) {
		backfillThrottle.clear();
	}
	backfillThrottle.set(address, { seq, ts: now });
	return true;
}

// keep alive
/**
 * After an uncaught exception the process state is undefined — continuing to
 * serve WebSocket traffic from that state can silently corrupt data (half-applied
 * cache writes, torn file appends). Log everything, then exit non-zero and let
 * the supervisor (pm2/systemd) restart a clean process. This also matches Node's
 * own default behaviour, which the previous log-only handlers were suppressing.
 */
function fatalExit(label: string, detail: unknown): void {
	ConsoleError(`[${label}] Process state is undefined — exiting for a clean restart.`);
	try {
		if (detail && (detail as { stack?: string }).stack) ConsoleError((detail as { stack?: string }).stack);
	} catch {
		/* best-effort: stack may not be printable; never block the exit */
	}
	// Best-effort flush; never let cleanup prevent the exit.
	Promise.resolve()
		.then(() => prisma.$disconnect())
		.catch(() => {})
		.finally(() => process.exit(1));
}

process.on("uncaughtException", (err) => {
	ConsoleError("[uncaughtException] Server encountered a fatal error:");
	ConsoleError(err);
	fatalExit("uncaughtException", err);
});

process.on("unhandledRejection", (reason) => {
	ConsoleError("[unhandledRejection] Uncaught async error:");
	ConsoleError(reason);
	fatalExit("unhandledRejection", reason);
});

function fetchConnAddress(ws: WebSocket): string | null {
	return (ws as any)._connAddress ?? null;
}
function fetchNodeConnURL(ws: WebSocket): string | null {
	return (ws as any)._nodeUrl ?? null;
}

/**
 * Handles incoming binary WebSocket frames (file chunks).
 * Extracts the 4-byte nonce, looks up the matching fileRequestList entry,
 * and either forwards the raw data (private/group chat) or persists to disk.
 * @param {Uint8Array} data - Raw binary frame containing nonce + file chunk data
 */
async function handleBinaryMessage(data: any): Promise<void> {
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
		if (!isAllowed(request.From as string)) {
			ConsoleWarn(
				`[Chat Filter] Blocked binary file forward to ${request.From} (type=${request.Type})`,
			);
			removeFileRequestByNonce(request.Nonce);
			return;
		}
		// forward file data to the destination peer
		removeFileRequestByNonce(request.Nonce);
		SendMessage(request.From as string, data);
	} else {
		await saveBufferFile(request, content);
	}
}

function broadcastBulletinToNodes(bulletin: unknown, excludeAddr?: string): void {
	const jsonStr = JSON.stringify(bulletin);
	for (const url in NodeConns) {
		// Don't echo a bulletin back to the peer that just handed it to us: it
		// already has it, and the echo re-triggers its own chase logic. Other
		// nodes still receive it.
		if (excludeAddr !== undefined && fetchConnAddress(NodeConns[url]) === excludeAddr) {
			continue;
		}
		SendToNode(url, jsonStr);
	}
}

// === Client Connection Handler ===
/**
 * Terminates a WebSocket connection by closing it and removing from tracking maps.
 * Checks both client connections (by address) and node connections (by URL).
 * @param {WebSocket} ws - The WebSocket instance to terminate
 */
function terminateConn(ws: WebSocket, reason = "unknown"): void {
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
function removeFileRequestByNonce(nonce: number): void {
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

function purgeFileRequestsByHashAddress(hash: string, address: string): void {
	for (const [nonce, r] of fileRequestList) {
		if (r.Hash === hash && r.Address === address) {
			fileRequestList.delete(nonce);
		}
	}
}

function purgeFileRequestsByHashFrom(hash: string, from: string): void {
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
function requestFile(
	from: string,
	type: number,
	hash: string,
	chunkCursor: number,
	address: string,
	doCleanup: boolean,
): void {
	const nonce = genFileNonce();
	const tmp = {
		Type: type,
		Nonce: nonce,
		Hash: hash,
		Address: address,
		// Remember the peer we asked for the file so a re-request after a
		// hash mismatch goes back to that peer (the node holding the file),
		// NOT to the bulletin signer (which has no open WS connection).
		From: from,
		Timestamp: Date.now(),
	};
	if (chunkCursor > 1) {
		(tmp as { ChunkCursor?: number }).ChunkCursor = chunkCursor;
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

function fetchAvatarFile(from: string, address: string, hash: string): void {
	requestFile(from, FileRequestType.Avatar, hash, 1, address, false);
}

function fetchBulletinFile(from: string, address: string, hash: string, chunk_cursor: number): void {
	requestFile(from, FileRequestType.File, hash, chunk_cursor, address, true);
}

/**
 * Cache a file-transfer request in fileRequestList after purging expired and duplicate entries.
 * @param {string} from - Source XRPL address of the sender
 * @param {object} json - The incoming file request message object (contains Nonce, Hash, Timestamp)
 * @param {number} type - FileRequestType enum value (PrivateChatFile or GroupChatFile)
 * @returns {void}
 */
function cacheFileRequest(from: string, json: Record<string, unknown>, type: number): void {
	const tmp: FileRequestEntry = {
		Type: type,
		Nonce: json.Nonce as number,
		From: from,
		// To: json.To,
		Hash: json.Hash as string,
		// ChunkCursor: json.ChunkCursor,
		Timestamp: json.Timestamp as number,
	};
	purgeExpiredFileRequests();
	purgeFileRequestsByHashFrom(json.Hash as string, from);
	fileRequestList.set(json.Nonce as number, tmp);
}

function cachePrivateFileRequest(from: string, json: Record<string, unknown>): void {
	cacheFileRequest(from, json, FileRequestType.PrivateChatFile);
}

function cacheGroupFileRequest(from: string, json: Record<string, unknown>): void {
	cacheFileRequest(from, json, FileRequestType.GroupChatFile);
}

/**
 * Persist incoming file buffer chunks to disk. Handles avatar files (full write)
 * and bulletin attachments (chunked append with hash verification).
 * @param {object} request - File request entry from fileRequestList (Type, Hash, Address, etc.)
 * @param {Uint8Array} content - Raw file chunk data received via WebSocket binary frame
 * @returns {Promise<void>}
 */
async function saveBufferFile(request: FileRequestEntry, content: any): Promise<void> {
	switch (request.Type) {
		case FileRequestType.Avatar: {
			const content_hash = FileBufferHash(content);
			if (request.Hash === content_hash) {
				const avatar_dir = `./${AvatarDir}/${(request.Address as string).substring(1, 4)}/${(request.Address as string).substring(4, 7)}`;
				await fsp.mkdir(path.resolve(avatar_dir), { recursive: true });
				const avatar_path = `${avatar_dir}/${request.Address as string}.png`;
				try {
					await fsp.writeFile(avatar_path, content);
					removeFileRequestByNonce(request.Nonce);
					await prisma.avatar.update({
						where: {
							address: request.Address as string,
						},
						data: {
							is_saved: true,
						},
					});
				} catch (err: any) {
					ConsoleWarn((err as Error).message);
				}
			}
			break;
		}
		case FileRequestType.File: {
			const file_dir = `./${FileDir}/${request.Hash.substring(0, 3)}/${request.Hash.substring(3, 6)}`;
			await fsp.mkdir(path.resolve(file_dir), { recursive: true });
			const file_path = `${file_dir}/${request.Hash}`;
			const file = await prisma.file.findFirst({
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
				markFileFetchDone(request.Hash);
			} else {
				// ChunkCursor is only set when cursor > 1 in requestFile;
				// default to 1 for the first chunk
				const expectedCursor = request.ChunkCursor ?? 1;
				if (file.chunk_cursor === file.chunk_length) {
					ConsoleInfo(
						`[saveBufferFile] ${request.Hash}: cursor at end (${file.chunk_length}), resetting to 0`,
					);
					await fsp.rm(path.resolve(file_path), { force: true });
					await prisma.file.update({
						where: {
							hash: request.Hash,
						},
						data: {
							chunk_cursor: 0,
						},
					});
					if (request.NodeUrl) {
						fetchFileFromNode(request.NodeUrl, request.Address as string, request.Hash, 1);
					} else if (request.From) {
						fetchBulletinFile(request.From, request.Address as string, request.Hash, 1);
					} else {
						fetchBulletinFile(request.Address as string, request.Address as string, request.Hash, 1);
					}
				} else if (
					file.chunk_cursor < file.chunk_length &&
					file.chunk_cursor + 1 === expectedCursor
				) {
					// Guard: the peer may send more bytes than it declared. Without this
					// a publisher could declare 1MB and push 1GB, decoupling on-disk
					// usage from the (capped) declared size.
					const writtenBefore = (expectedCursor - 1) * FileChunkSize;
					if (writtenBefore + content.length > file.size) {
						ConsoleWarn(
							`[saveBufferFile] ${request.Hash}: chunk overruns declared size ` +
								`(${writtenBefore + content.length} > ${file.size}), resetting`,
						);
						await fsp.rm(path.resolve(file_path), { force: true });
						await prisma.file.update({
							where: {
								hash: request.Hash,
							},
							data: {
								chunk_cursor: 0,
							},
						});
						return;
					}
					// Defensive: if this is the first chunk, delete any stale
					// partial file left on disk by a prior failed attempt so we
					// don't append to it (which would corrupt the content and
					// cause a spurious hash mismatch).
					if (file.chunk_cursor === 0) {
						await fsp.rm(path.resolve(file_path), { force: true });
					}
					ConsoleInfo(
						`[saveBufferFile] ${request.Hash}: saving chunk ${expectedCursor}/${file.chunk_length} (${content.length} bytes)`,
					);
					try {
						await fsp.appendFile(file_path, Buffer.from(content));
						removeFileRequestByNonce(request.Nonce);
						const current_chunk_cursor = file.chunk_cursor + 1;
						await prisma.file.update({
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
									request.Address as string,
									request.Hash,
									current_chunk_cursor + 1,
								);
							} else if (request.From) {
								// Use the node (request.From) that sent the current chunk,
								// NOT the bulletin signer (request.Address) which has no
								// open WS connection.
								fetchBulletinFile(
									request.From as string,
									request.Address as string,
									request.Hash,
									current_chunk_cursor + 1,
								);
							} else {
								fetchBulletinFile(
									request.Address as string,
									request.Address as string,
									request.Hash,
									current_chunk_cursor + 1,
								);
							}
						} else {
							ConsoleInfo(
								`[saveBufferFile] ${request.Hash}: all chunks received, verifying hash...`,
							);
							const hash = await FileReadHash(path.resolve(file_path));
							if (hash === request.Hash) {
								ConsoleInfo(
									`[saveBufferFile] ${request.Hash}: ✅ File saved successfully! (${file.size} bytes)`,
								);
								fileRetryCount.delete(request.Hash);
								markFileFetchDone(request.Hash);
								await prisma.file.update({
									where: {
										hash: request.Hash,
									},
									data: {
										is_saved: true,
									},
								});
							} else {
								const retries = fileRetryCount.get(request.Hash) ?? 0;
								if (retries >= MAX_FILE_RETRIES) {
									ConsoleWarn(
										`[saveBufferFile] ${request.Hash}: ❌ Giving up after ${MAX_FILE_RETRIES} retries (persistent hash mismatch)`,
									);
									fileRetryCount.delete(request.Hash);
									markFileFetchDone(request.Hash);
									return;
								}
								fileRetryCount.set(request.Hash, retries + 1);
								ConsoleWarn(
									`[saveBufferFile] ${request.Hash}: ❌ HASH MISMATCH! expected=${request.Hash}, got=${hash} (retry ${retries + 1}/${MAX_FILE_RETRIES})`,
								);
								await fsp.rm(path.resolve(file_path), { force: true });
								await prisma.file.update({
									where: {
										hash: request.Hash,
									},
									data: {
										chunk_cursor: 0,
									},
								});
								if (request.NodeUrl) {
									fetchFileFromNode(request.NodeUrl, request.Address as string, request.Hash, 1);
								} else if (request.From) {
									fetchBulletinFile(request.From, request.Address as string, request.Hash, 1);
								} else {
									fetchBulletinFile(request.Address as string, request.Address as string, request.Hash, 1);
								}
							}
						}
					} catch (err: any) {
						ConsoleWarn(
							`[saveBufferFile] Failed to append file chunk: ${(err as Error).message}`,
						);
					}
				} else {
					ConsoleWarn(
						`[saveBufferFile] ${request.Hash}: ❌ Unexpected cursor! expected=${file.chunk_cursor + 1}, got=${expectedCursor}, cursor=${file.chunk_cursor}, length=${file.chunk_length}`,
					);
					markFileFetchDone(request.Hash);
				}
			}
			break;
		}
		default:
			break;
	}
}

async function HandleFileRequest(request: Record<string, unknown>, from: string): Promise<void> {
	// send cache file
	switch (request.FileType) {
		case FileRequestType.Avatar: {
			const avatar = await prisma.avatar.findFirst({
				where: {
					hash: request.Hash as string,
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
			const nonce = Uint32ToBuffer(request.Nonce as number);
			SendMessage(from, Buffer.concat([nonce as Buffer, buffer]));
			break;
		}
		case FileRequestType.File: {
			const file = await prisma.file.findFirst({
				where: {
					AND: {
						hash: request.Hash as string,
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
				const start = ((request.ChunkCursor as number) - 1) * FileChunkSize;
				if (start >= file.size) {
					ConsoleWarn(
						`[HandleFileRequest] Chunk cursor ${request.ChunkCursor} out of range for ${request.Hash}, start=${start}, file.size=${file.size}`,
					);
					return;
				}
				const file_left = file.size - start;
				const length = Math.min(FileChunkSize, file_left);
				const file_path = path.resolve(
					`./${FileDir}/${(request.Hash as string).substring(0, 3)}/${(request.Hash as string).substring(3, 6)}/${request.Hash}`,
				);
				try {
					// fsp.readFile does NOT support {start, end} options - use fsp.open + fd.read instead
					const fd = await fsp.open(file_path, "r");
					try {
						const buffer = Buffer.alloc(length);
						await fd.read(buffer, 0, length, start);
						const chunk = Uint8Array.from(buffer);
						const nonce = Uint32ToBuffer(request.Nonce as number);
						SendMessage(from, Buffer.concat([nonce as Buffer, chunk]));
					} finally {
						await fd.close();
					}
				} catch (err: any) {
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
			const members = groupMap[request.GroupHash as string];
			if (members) {
				const tmp_members = shuffleArray(members);
				for (let i = 0; i < tmp_members.length; i++) {
					const member = tmp_members[i];
					if (
						from !== member &&
						Conns[member as string] &&
						Conns[member as string].readyState === WebSocket.OPEN
					) {
						SendMessage(member as string, JSON.stringify(request));
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
async function CacheAvatar(from: string, avatar: Record<string, unknown>): Promise<void> {
	const timestamp = Date.now();
	const avatar_address = rippleKeyPairs.deriveAddress(avatar.PublicKey as string);
	if (avatar.Hash !== GenesisHash) {
		fetchAvatarFile(from, avatar_address, avatar.Hash as string);
	}

	const db_a = await prisma.avatar.findFirst({
		where: {
			address: avatar_address,
		},
	});
	if (db_a === null) {
		await prisma.avatar.create({
			data: {
				address: avatar_address,
				hash: avatar.Hash as string,
				size: avatar.Size as number,
				signed_at: avatar.Timestamp as number,
				json: JSON.stringify(avatar),
				is_saved: false,
			},
		});
	} else if (
		avatar.Timestamp as number > db_a.signed_at &&
		db_a.signed_at < timestamp - AVATAR_UPDATE_THROTTLE_MS &&
		avatar.Hash as string !== db_a.hash
	) {
		await prisma.avatar.update({
			where: {
				address: avatar_address,
			},
			data: {
				hash: avatar.Hash as string,
				size: avatar.Size as number,
				signed_at: avatar.Timestamp as number,
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
async function HandleAvatarRequest(request: Record<string, unknown>, from: string): Promise<void> {
	const new_list: unknown[] = [];
	const old_list: { Address: string; SignedAt: number }[] = [];

	const addresses = (request.List as { Address: string }[]).map((item) => item.Address);
	const db_avatars = await prisma.avatar.findMany({
		where: { address: { in: addresses } },
		select: { address: true, is_saved: true, signed_at: true, json: true },
	});
	const avatarMap = new Map(db_avatars.map((a) => [a.address, a]));

	for (let i = 0; i < (request.List as { Address: string; SignedAt: number }[]).length; i++) {
		const avatar = (request.List as { Address: string; SignedAt: number }[])[i];
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
				else console.log(`[HandleAvatarRequest]   parsedAvatar is NULL`);
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

async function BindBulletinTag(bulletin_hash: string, tags: string[] | null | undefined): Promise<unknown> {
	if (!tags || tags.length === 0) return null;

	const uniqueTags = [...new Set(tags)];

	return await prisma.$transaction(async (tx) => {
		await tx.tag.createMany({
			data: uniqueTags.map((name) => ({ name: name })),
			skipDuplicates: true,
		});

		return await tx.bulletin.update({
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

async function BindBulletinFile(bulletin_hash: string, files: { Hash: string; Size: number }[]): Promise<unknown> {
	return await prisma.$transaction(async (tx) => {
		const fetchedFiles = [];

		for (const f of files) {
			// `Hash` and `Size` come straight from the bulletin JSON, i.e. from the
			// publisher (signed, but a malicious author can sign anything). Without
			// this guard a declared size of e.g. 1TB yields chunk_length = ~1e6 and
			// the relay would queue an unbounded fetch loop and fill the disk.
			//
			// Oversized attachments are SKIPPED, not rejected with the bulletin:
			// the bulletin itself is valid and part of the hash chain — dropping it
			// would leave a permanent hole that clients can never backfill.
			if (
				!f ||
				typeof f.Hash !== "string" ||
				!Number.isFinite(f.Size) ||
				f.Size <= 0 ||
				f.Size > FileMaxSize
			) {
				ConsoleWarn(
					`[BindBulletinFile] Skipped attachment for ${bulletin_hash}: ` +
						`invalid or oversized (size=${f?.Size}, hash=${String(f?.Hash).substring(0, 12)}, max=${FileMaxSize})`,
				);
				continue;
			}

			const fileRecord = await tx.file.upsert({
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
			await tx.bulletin.update({
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
async function CacheBulletin(from: string, bulletin: Record<string, unknown>, isFromNode: boolean): Promise<boolean> {
	const timestamp = Date.now();
	const hash = QuarterSHA512Message(bulletin);
	const bulletin_address = rippleKeyPairs.deriveAddress(bulletin.PublicKey as string);
	let isNewRecord = false;

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
		return false;
	}

	try {
		const result = await prisma.bulletin.upsert({
			where: {
				hash: hash,
			},
			update: {},
			create: {
				hash: hash,
				pre_hash: bulletin.PreHash as string,
				address: bulletin_address,
				sequence: bulletin.Sequence as number,
				content: bulletin.Content as string,
				json: JSON.stringify(bulletin),
				signed_at: bulletin.Timestamp as number,
				created_at: timestamp,
			},
		});

		// 如果是新创建的，才执行后续绑定操作
		isNewRecord = Number(result.created_at) === timestamp;

		if (isNewRecord) {
			lastBulletinAt = Date.now();
			ConsoleInfo(
				`[CacheBulletin] New bulletin saved: ${hash}, seq=${result.sequence}, address=${bulletin_address}`,
			);
			SendMessage(from, GenServerNotifyCache(MessageCode.BulletinCached));

			if (result.sequence !== 1) {
				try {
					await prisma.bulletin.update({
						where: { hash: bulletin.PreHash as string },
						data: { next_hash: hash },
					});
				} catch (e: any) {
					ConsoleDebug(
						`[CacheBulletin] Failed to update next_hash for PreHash ${bulletin.PreHash} -> ${hash}: ${(e as Error).message}`,
					);
				}
			}

			// create tag
			if (bulletin.Tag && Array.isArray(bulletin.Tag) && bulletin.Tag.length > 0) {
				await BindBulletinTag(hash, bulletin.Tag as string[]);
			}

			// create quote
			if (bulletin.Quote && (bulletin.Quote as unknown[]).length > 0) {
				const quoteData = (bulletin.Quote as { Hash: string }[]).map((q) => ({
					post_hash: q.Hash,
					reply_hash: hash,
					signed_at: bulletin.Timestamp as number,
				}));
				await prisma.reply.createMany({
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
				const files_to_fetch: { hash: string; is_saved: boolean; chunk_cursor: number }[] = await BindBulletinFile(hash, bulletin.File as { Hash: string; Size: number }[]) as { hash: string; is_saved: boolean; chunk_cursor: number }[];
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
					} else if (process.env.RMS_SKIP_FILE_FETCH) {
						ConsoleWarn(
							`[CacheBulletin] RMS_SKIP_FILE_FETCH: not fetching ${file.hash}`,
						);
					} else {
						ConsoleInfo(
							`[CacheBulletin] Queuing fetchBulletinFile for ${file.hash} from ${bulletin_address} cursor=${file.chunk_cursor + 1}`,
						);
						enqueueFileFetch(
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
				// Pass the originating peer so it doesn't receive its own bulletin back.
				broadcastBulletinToNodes(bulletin, isFromNode ? from : undefined);
			}
		}
	} catch (error) {
		if ((error as { code?: string }).code === "P2002") {
			ConsoleDebug(
				`[CacheBulletin] Duplicate bulletin ignored (already exists): ${hash}`,
			);
		} else {
			ConsoleError(
				`[CacheBulletin] Error saving bulletin ${hash}: ${(error as Error).message}`,
			);
		}
	}
	return isNewRecord;
}

function clearSubscribe(address: string): void {
	Object.entries(subscribeMap).forEach(([key, value]) => {
		const new_value = value.filter((a) => a !== address);
		subscribeMap[key] = new_value;
	});
}

function HandleBulletinSubscribe(request: Record<string, unknown>, from: string): void {
	clearSubscribe(from);
	for (let i = 0; i < (request.List as string[]).length; i++) {
		const subscribe_address = (request.List as string[])[i];
		if (subscribe_address !== from) {
			let new_value: string[] = [];
			if (subscribeMap[subscribe_address] !== undefined) {
				new_value = subscribeMap[subscribe_address];
			}
			new_value.push(from);
			subscribeMap[subscribe_address] = new_value;
		}
	}
}

// ecdh
async function CacheECDH(json: Record<string, unknown>): Promise<void> {
	let address1 = "";
	let address2 = "";
	let json1 = "";
	let json2 = "";
	const sour_address = rippleKeyPairs.deriveAddress(json.PublicKey as string);
	const dest_address = json.To as string;
	if (sour_address > dest_address) {
		address1 = sour_address;
		address2 = dest_address;
		json1 = JSON.stringify(json);
	} else {
		address1 = dest_address;
		address2 = sour_address;
		json2 = JSON.stringify(json);
	}

	const dh = await prisma.eCDH.findFirst({
		where: {
			address1: address1,
			address2: address2,
			partition: json.Partition as number,
			sequence: json.Sequence as number,
		},
	});
	if (dh === null) {
		if (json1 != "") {
			await prisma.eCDH.create({
				data: {
					address1: address1,
					address2: address2,
					partition: json.Partition as number,
					sequence: json.Sequence as number,
					json1: json1,
					json2: "",
				},
			});
		} else if (json2 != "") {
			await prisma.eCDH.create({
				data: {
					address1: address1,
					address2: address2,
					partition: json.Partition as number,
					sequence: json.Sequence as number,
					json1: "",
					json2: json2,
				},
			});
		}
	} else if (json1 != "") {
		if (dh.json1 != "") {
			let old_json1;
			try {
				old_json1 = JSON.parse(dh.json1 as string);
			} catch {
				old_json1 = null;
			}
			if (old_json1 && json.Timestamp as number >= old_json1.Timestamp) {
				return;
			}
		}
		await prisma.eCDH.update({
			where: {
				address1_address2_partition_sequence: {
					address1: address1,
					address2: address2,
					partition: json.Partition as number,
					sequence: json.Sequence as number,
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
				old_json2 = JSON.parse(dh.json2 as string);
			} catch {
				old_json2 = null;
			}
			if (old_json2 && json.Timestamp as number >= old_json2.Timestamp) {
				return;
			}
		}
		await prisma.eCDH.update({
			where: {
				address1_address2_partition_sequence: {
					address1: address1,
					address2: address2,
					partition: json.Partition as number,
					sequence: json.Sequence as number,
				},
			},
			data: {
				json2: json2,
			},
		});
	}
}

async function HandleECDHSync(json: Record<string, unknown>): Promise<void> {
	let address1 = "";
	let address2 = "";
	const sour_address = rippleKeyPairs.deriveAddress(json.PublicKey as string);
	const dest_address = json.To as string;
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

	const dh = await prisma.eCDH.findFirst({
		where: {
			address1: address1,
			address2: address2,
			partition: json.Partition as number,
			sequence: json.Sequence as number,
		},
		select: {
			json1: true,
			json2: true,
		},
	});
	if (dh != null && json.Pair === "") {
		if (address1 === sour_address && dh.json2 != "") {
			SendMessage(sour_address, dh.json2 as string);
		} else if (address2 === sour_address && dh.json1 != "") {
			SendMessage(sour_address, dh.json1 as string);
		}
	}
}

// private
async function CachePrivateMessage(json: Record<string, unknown>): Promise<void> {
	const str_json = JSON.stringify(json);
	const hash = QuarterSHA512Message(json);
	const sour_address = rippleKeyPairs.deriveAddress(json.PublicKey as string);
	const dest_address = json.To as string;
	const last_msg = await prisma.privateMessage.findFirst({
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
		(last_msg === null && json.Sequence as number === 1 && json.PreHash === GenesisHash) ||
		(last_msg !== null &&
			json.Sequence as number === last_msg.sequence + 1 &&
			json.PreHash === last_msg.hash)
	) {
		await prisma.privateMessage.create({
			data: {
				hash: hash,
				sour_address: sour_address,
				dest_address: dest_address,
				sequence: json.Sequence as number,
				signed_at: json.Timestamp as number,
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
	} else if (last_msg !== null && last_msg.sequence < (json.Sequence as number)) {
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
async function HandlePrivateMessageSync(json: Record<string, unknown>): Promise<void> {
	const from_address = rippleKeyPairs.deriveAddress(json.PublicKey as string);
	const msg_list = await prisma.privateMessage.findMany({
		where: {
			OR: [
				{
					sour_address: from_address,
				dest_address: json.To as string,
				sequence: {
					gt: json.SelfSequence as number,
				},
				},
				{
					sour_address: json.To as string,
					dest_address: from_address,
					sequence: {
						gt: json.PairSequence as number,
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
async function HandleGroupSync(from: string): Promise<void> {
	const group_hash_list: string[] = [];
	Object.entries(groupMap).forEach(([hash, member]) => {
		if (member.includes(from)) {
			group_hash_list.push(hash);
		}
	});
	if (group_hash_list.length > 0) {
		const group_list = await prisma.group.findMany({
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

async function CacheGroup(group: Record<string, unknown>): Promise<void> {
	const address = rippleKeyPairs.deriveAddress(group.PublicKey as string);

	const db_g = await prisma.group.findFirst({
		where: {
			hash: group.Hash as string,
		},
	});

	if (group.ObjectType === ObjectType.GroupDelete) {
		if (db_g !== null && db_g.deleted_at === null) {
			const result = await prisma.group.update({
				where: {
					hash: group.Hash as string,
				},
				data: {
					deleted_at: group.Timestamp as number,
					delete_json: JSON.stringify(group),
				},
			});
			if (result) {
				delete groupMap[group.Hash as string];
			}
		}
	} else if (group.ObjectType === ObjectType.GroupCreate) {
		await prisma.group.upsert({
			where: { hash: group.Hash as string },
			create: {
				hash: group.Hash as string,
				created_by: address,
				member: JSON.stringify(group.Member),
				created_at: group.Timestamp as number,
				create_json: JSON.stringify(group),
			},
			update: {}, // GroupCreate only creates; no update needed for existing records
		});

		const members = group.Member as string[];
		members.push(address);
		groupMap[group.Hash as string] = members;
	}
}

// send
/** Generic sender: looks up a key in a connection map, checks readyState, and sends. */
function sendTo(key: string, message: string | Buffer, connMap: Record<string, WebSocket>): void {
	try {
		if (connMap[key] && connMap[key].readyState === WebSocket.OPEN) {
			connMap[key].send(message);
			// Success is the common case and dominated the log (~11k lines per
			// 10 min). Keep it at debug level; failures stay visible.
			ConsoleDebug(`[sendTo] Message SENT to ${key}, bytes=${(message as string).length}`);
		} else {
			ConsoleWarn(
				`[sendTo] FAILED to send to ${key}, readyState=${connMap[key]?.readyState}`,
			);
		}
	} catch (err: any) {
		ConsoleWarn(`[sendTo] EXCEPTION sending to ${key}: ${(err as Error).message}`);
	}
}

/** Send to a client by address (uses Conns map).
 * Falls back to NodeConns so replies addressed to a peer node URL are routed
 * over the node connection instead of being silently dropped. Client
 * addresses (rXXX) and node URLs (wss://...) never collide, so the fallback
 * cannot misdirect a client message. */
function SendMessage(address: string, message: string | Buffer): void {
	sendTo(address, message, Conns);
	if (NodeConns[address] !== undefined) {
		sendTo(address, message, NodeConns);
	}
}

// handle Object
/**
 * Chain state for one address: the highest sequence cached, and the length of
 * the contiguous prefix starting at 1.
 *
 * Runs entirely in Postgres — the previous implementation loaded every row for
 * the address into Node and scanned it, on every incoming bulletin. With the
 * (address, sequence) index this is an index scan; the window function finds the
 * first position where `sequence <> row_number`, which is exactly the first hole.
 *
 * @param {string} address - Chain owner
 * @returns {Promise<{max_sequence: number, contiguous_prefix: number}>}
 */
async function fetchChainState(address: string): Promise<{ max_sequence: number; contiguous_prefix: number }> {
	const rows = await prisma.$queryRaw`
		WITH seqs AS (
			SELECT DISTINCT sequence AS s FROM "Bulletin" WHERE address = ${address}
		), numbered AS (
			SELECT s, ROW_NUMBER() OVER (ORDER BY s) AS rn FROM seqs
		)
		SELECT
			COALESCE((SELECT MAX(s) FROM seqs), 0)::int AS max_sequence,
			COALESCE(
				(SELECT MIN(rn - 1) FROM numbered WHERE s <> rn),
				(SELECT COUNT(*) FROM seqs)
			)::int AS contiguous_prefix
	`;
	const row = (rows as { max_sequence: number; contiguous_prefix: number }[]) && (rows as { max_sequence: number; contiguous_prefix: number }[])[0] ? (rows as { max_sequence: number; contiguous_prefix: number }[])[0] : {};
	return {
		max_sequence: Number((row as { max_sequence: number }).max_sequence) || 0,
		contiguous_prefix: Number((row as { contiguous_prefix: number }).contiguous_prefix) || 0,
	};
}

/**
 * Find the first missing sequence number for an address (gap detection).
 * Returns null when nothing is cached yet, or when 1..max are all present.
 *
 * NOTE: this is a *reporting* function. Callers must not treat a gap as a reason
 * to reject the bulletin that triggered the check — fragments are intentional.
 *
 * @param {string} address - Chain owner
 * @returns {Promise<number|null>} First missing sequence, or null
 */
async function FindFirstMissingSequence(address: string): Promise<number | null> {
	const { max_sequence, contiguous_prefix } = await fetchChainState(address);
	if (max_sequence === 0) return null;
	if (contiguous_prefix >= max_sequence) {
		ConsoleDebug(
			`[FindFirstMissingSequence] ${address}: no gap, contiguous 1..${max_sequence}`,
		);
		return null;
	}
	ConsoleInfo(
		`[FindFirstMissingSequence] ${address}: gap at seq=${contiguous_prefix + 1} (contiguous 1..${contiguous_prefix}, max=${max_sequence})`,
	);
	return contiguous_prefix + 1;
}

/**
 * Get max_sequence + 1 for an address, or null if no bulletins exist.
 */
async function GetMaxSequencePlusOne(address: string): Promise<number | null> {
	const result = await prisma.bulletin.findFirst({
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
async function handleObject(from: string, message: string, json: Record<string, unknown>, isFromNode: boolean): Promise<void> {
	switch (json.ObjectType) {
		case ObjectType.Bulletin: {
			ConsoleInfo(
				`[handleObject.Bulletin] Verifying signature for PublicKey=${(json.PublicKey as string)?.substring(0, 20)}...`,
			);
			const sigValid = VerifyJsonSignature(json);
			ConsoleInfo(`[handleObject.Bulletin] Signature valid: ${sigValid}`);
			if (sigValid) {
				ConsoleInfo(
					`[handleObject.Bulletin] Caching bulletin hash=${json.Hash}, seq=${json.Sequence} from ${from}`,
				);
				const isNew = await CacheBulletin(from, json, isFromNode);
				//fetch more bulletin — check for gaps first, then chase next sequence
				const address = rippleKeyPairs.deriveAddress(json.PublicKey as string);
				ConsoleInfo(
					`[handleObject.Bulletin] Received seq=${json.Sequence} from ${address}, checking sync`,
				);
				const gap_sequence = await FindFirstMissingSequence(address);
				if (gap_sequence === null) {
					// No gap — chase the next sequence after current max.
					// ONLY if this bulletin is NEW (advanced our max). If the node
					// returned an old bulletin (we already had it), it has nothing
					// newer, and chasing the next sequence would loop forever
					// (node keeps returning its latest, server keeps requesting next).
					if (!isNew) {
						ConsoleDebug(
							`[handleObject.Bulletin] ${address}: received old bulletin seq=${json.Sequence} (already cached), not chasing next`,
						);
					} else {
						const next_seq = await GetMaxSequencePlusOne(address);
						if (next_seq === null) {
							ConsoleDebug(
								`[handleObject.Bulletin] ${address}: no bulletins to request`,
							);
						} else {
							ConsoleInfo(
								`[handleObject.Bulletin] Sending BulletinRequest seq=${next_seq} to ${address} (chasing next, max cached=${next_seq - 1})`,
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
					// Gap exists — fetch from the missing point.
					// Throttled: under the fragmented-cache policy a hole that can
					// never be filled must not trigger a request on every later post.
					if (shouldRequestBackfill(address, gap_sequence)) {
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
					} else {
						ConsoleDebug(
							`[handleObject.Bulletin] ${address}: gap seq=${gap_sequence} re-request throttled`,
						);
					}
				}
			}
			break;
		}
		case ObjectType.ServerAddressList: {
			// === Node Interaction ===
			// pull step 2: fetch account latest bulletin
			let items = json.List as { Address: string; Count: number }[];
			if (WhiteList.length > 0) {
				items = items.filter((item) => isAllowed(item.Address));
			}

			for (let i = 0; i < items.length; i++) {
				const item = items[i];
				let bulletin = await prisma.bulletin.findFirst({
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
						const bulletin_json = await prisma.bulletin.findFirst({
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
						if (bulletin_json) {
							SendMessage(from, bulletin_json.json);
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
			if ((json.Page as number) !== (json.TotalPage as number)) {
				const msg = GenServerAddressListRequest(
					json.Page as number + 1,
					SelfPublicKey,
					SelfPrivateKey,
				);
				SendMessage(from, msg);
			}
			break;
		}
		case ObjectType.PrivateMessage:
			if (!isAllowed(from) || !isAllowed(json.To as string)) {
				ConsoleWarn(`[Chat Filter] Blocked PrivateMessage: ${from} → ${json.To as string}`);
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
				SendMessage(json.To as string, message);
			}
			break;
		case ObjectType.ECDH:
			if (!isAllowed(from) || !isAllowed(json.To as string)) {
				ConsoleWarn(`[Chat Filter] Blocked ECDH: ${from} → ${json.To as string}`);
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
				SendMessage(json.To as string, message);
			}
			break;
		case ObjectType.AvatarList:
			for (let i = 0; i < (json.List as unknown[]).length; i++) {
				const avatar = (json.List as unknown[])[i];
				if (VerifyJsonSignature(avatar as Record<string, unknown>)) {
					await CacheAvatar(from, avatar as Record<string, unknown>);
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
			for (let i = 0; i < (json.List as unknown[]).length; i++) {
				const group = (json.List as unknown[])[i];
				if (VerifyJsonSignature(group as Record<string, unknown>)) {
					await CacheGroup(group as Record<string, unknown>);
				}
			}
			break;
		case ObjectType.GroupMessageList: {
			if (!isAllowed(from) || !isAllowed(json.To as string)) {
				ConsoleWarn(`[Chat Filter] Blocked GroupMessageList: ${from} → ${json.To as string}`);
				SendMessage(
					from,
					GenServerNotifyError(
						MessageCode.NotAllowed,
						"Chat not allowed for this address",
					),
				);
				break;
			}
			const members = groupMap[json.GroupHash as string];
			if (members) {
				if (members.includes(from) && members.includes(json.To as string)) {
					SendMessage(json.To as string, message);
				}
			} else {
				// Group not in memory map — check if it was deleted, notify the sender
				const db_g = await prisma.group.findFirst({
					where: { hash: json.GroupHash as string },
					select: { deleted_at: true, delete_json: true },
				});
				if (db_g && db_g.deleted_at !== null && db_g.delete_json) {
					try {
						const group_response = {
							ObjectType: ObjectType.GroupList,
							List: [JSON.parse(db_g.delete_json)],
						};
						SendMessage(from, JSON.stringify(group_response));
					} catch (e: any) {
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
 * Address leaderboard: accounts ordered by how many bulletins they have, paged.
 *
 * Shared by two action codes that are deliberately distinct on the client but
 * identical in semantics here:
 *   - `ServerAddressRequest` (403)          — legacy name
 *   - `BulletinAddressListRequest` (406)    — newer name, same request shape
 * Both are answered with `ObjectType.ServerAddressList`, which is what the
 * client already knows how to render.
 *
 * @param {object} json - Validated request carrying at least `Page`
 * @param {string} from - Requesting XRPL address
 * @returns {Promise<void>}
 */
async function HandleAddressLeaderboard(json: Record<string, unknown>, from: string): Promise<void> {
	const where = WhiteList.length > 0 ? { address: { in: WhiteList } } : {};

	const result = await prisma.bulletin.groupBy({
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
		skip: ((json.Page as number) - 1) * PageSize,
		take: PageSize,
	});
	const address_list: { Address: string; Count: number }[] = [];
	result.forEach((item) => {
		address_list.push({
			Address: item.address,
			Count: item._count.address,
		});
	});

	// Total distinct addresses for pagination. Computed per request, which is
	// wasteful on a busy server; a periodically refreshed counter would be the
	// next improvement here.
	const total = await prisma.bulletin.findMany({
		where,
		select: { address: true },
		distinct: ["address"],
	});

	const total_page = calcTotalPage(total.length, PageSize);
	if (address_list.length > 0) {
		const msg = GenServerAddressList(json.Page as number, total_page, address_list as any[]);
		SendMessage(from, msg);
	}
}

/**
 * Pick `limit` pseudo-random bulletins.
 *
 * `ORDER BY RANDOM()` was used here and is the worst possible cost profile for
 * this endpoint: RANDOM() is a per-row value, so no index can ever serve the
 * sort — every request does a full table scan + a temp B-tree sort of the whole
 * table, then discards all but 20 rows. Measured in-memory: 0.48ms @10k rows,
 * 2.27ms @50k, 4.72ms @100k — and it is triggered by a single cheap client
 * click, from any declared address.
 *
 * Instead we sample a random offset and read 20 consecutive rows off the
 * `signed_at` index (0.83ms @100k, i.e. ~5.7x cheaper, and it no longer sorts).
 * Distribution is uniform over the *time axis* rather than over rows; bulletins
 * are published over time, so in practice the two are very close.
 *
 * @param {number} limit - Number of bulletins to return
 * @returns {Promise<Array>} Raw Bulletin rows
 */
async function fetchRandomBulletins(limit: number): Promise<unknown[]> {
	const rows = await prisma.$queryRaw`SELECT COUNT(*)::int AS c FROM "Bulletin"`;
	const total = (rows as any[])[0] ? Number((rows as any[])[0].c) || 0 : 0;
	if (total === 0) return [];
	const take = Math.min(limit, total);
	const offset = Math.floor(Math.random() * Math.max(1, total - take + 1));
	return await prisma.$queryRaw`
		SELECT * FROM "Bulletin" ORDER BY signed_at LIMIT ${take} OFFSET ${offset}`;
}

/**
 * Fetch bulletins that contain media files (video/image/audio).
 * Uses PostgreSQL JSON queries to filter bulletins whose `file` array
 * includes at least one media extension.
 *
 * @param {number} limit - Maximum number of bulletins to return
 * @returns {Promise<Array>} Raw Bulletin rows with media files
 */
async function fetchMediaBulletins(limit: number): Promise<unknown[]> {
	const take = Math.min(limit || 20, 100);
	return await prisma.$queryRaw`
		SELECT b.* FROM "Bulletin" b
		WHERE b.json::json->'File' IS NOT NULL
		  AND EXISTS (
		    SELECT 1 FROM json_array_elements(b.json::json->'File') AS f
		    WHERE lower(f->>'Ext') IN ('mp4','webm','mov','m4v','mp3','ogg','oga','opus','wav','m4a','aac','flac','jpg','jpeg','png','gif','webp','bmp','svg')
		  )
		ORDER BY random()
		LIMIT ${take}`;
}

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
async function handleAction(from: string, message: string, json: Record<string, unknown>): Promise<void> {
	if (!VerifyJsonSignature(json)) {
		return;
	}

	// forward message only after signature verification succeeds
	if (json.To != undefined) {
		if (!isAllowed(from) || !isAllowed(json.To as string)) {
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
		// Only forward to a live peer. Forwarding to an address with no open
		// connection is a guaranteed no-op (sendTo logs FAILED), and under the
		// node-sync workload it accounted for hundreds of noisy failures per
		// cycle because nodes stamp `To` with the bulletin owner, who is often
		// offline. Dropping here keeps deliverable traffic identical.
		const to = json.To as string;
		if (
			Conns[to]?.readyState === WebSocket.OPEN ||
			NodeConns[to]?.readyState === WebSocket.OPEN
		) {
			SendMessage(to, message);
		} else {
			ConsoleDebug(
				`[forward] ${to} not connected, dropped action=${json.Action}`,
			);
		}
	}

	if (json.Action === ActionCode.BulletinRequest) {
		//send cache bulletin
		const addrFilter = WhiteList.length > 0 ? { address: { in: WhiteList } } : {};
		if (json.Hash) {
			const bulletin = await prisma.bulletin.findFirst({
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
			const bulletin = await prisma.bulletin.findFirst({
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
	} else if (
		(json.Action === ActionCode.ServerAddressRequest ||
			json.Action === ActionCode.BulletinAddressListRequest) &&
		(json.Page as number) > 0
	) {
		await HandleAddressLeaderboard(json, from);
	} else if (json.Action === ActionCode.ReplyBulletinRequest && (json.Page as number) > 0) {
		const addrFilter = WhiteList.length > 0 ? { address: { in: WhiteList } } : {};
		// Check if parent bulletin is from a whitelisted address
		const parentBulletin = await prisma.bulletin.findFirst({
			where: { hash: json.Hash as string, ...addrFilter },
			select: { hash: true },
		});
		if (parentBulletin === null) {
			return;
		}
		const reply_hash_list = await prisma.reply.findMany({
			where: {
				post_hash: json.Hash as string,
			},
			select: {
				reply_hash: true,
			},
			skip: (json.Page as number - 1) * PageSize,
			take: PageSize,
			orderBy: { signed_at: "asc" },
		});
		let tmp_list: unknown[] = [];
		reply_hash_list.forEach((reply) => {
			tmp_list.push(reply.reply_hash);
		});

		const reply_json_list = await prisma.bulletin.findMany({
			where: {
				hash: {
					in: tmp_list as string[],
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

		const total = await prisma.reply.count({
			where: {
				post_hash: json.Hash as string,
			},
		});
		let total_page = 0;
		if (total > 0) {
			total_page = calcTotalPage(total, PageSize);
		}

		if (tmp_list.length > 0) {
			const msg = GenReplyBulletinList(json.Hash as string, json.Page as number, total_page, tmp_list as any[]);
			SendMessage(from, msg);
		} else {
			const post_bulletin = await prisma.bulletin.findFirst({
				where: {
					hash: json.Hash as string,
				},
				select: {
					hash: true,
				},
			});
			if (post_bulletin === null) {
				const msg = GenBulletinRequestByHash(
					json.Hash as string,
					from,
					SelfPublicKey,
					SelfPrivateKey,
				);
				SendMessage(from, msg);
			}
		}
	} else if (json.Action === ActionCode.TagBulletinRequest && (json.Page as number) > 0) {
		const whereCondition = {
			AND: (json.Tag as string[]).map((name) => ({ tags: { some: { name: name } } })),
		};
		const [list, total] = await prisma.$transaction([
			prisma.bulletin.findMany({
				where: whereCondition,
				// include: { tags: true },
				select: {
					json: true,
					tags: { select: { name: true } },
				},
				orderBy: { signed_at: "desc" },
				skip: (json.Page as number - 1) * PageSize,
				take: PageSize,
			}),
			prisma.bulletin.count({
				where: whereCondition,
			}),
		]);
		const tmp_list: unknown[] = [];
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
			const msg = GenTagBulletinList(json.Tag as string, json.Page as number, total_page, tmp_list as any[]);
			SendMessage(from, msg);
		}
	} else if (json.Action === ActionCode.RandomBulletinRequest) {
		const list = await fetchRandomBulletins(20);
		const tmp_list: unknown[] = [];
		list.forEach((bulletin) => {
			let parsedBulletin;
			try {
				parsedBulletin = JSON.parse((bulletin as any).json);
			} catch {
				parsedBulletin = null;
			}
			if (parsedBulletin) tmp_list.push(parsedBulletin);
		});

		if (tmp_list.length > 0) {
			const msg = GenRandomBulletinList(tmp_list as any[]);
			SendMessage(from, msg);
		}
	} else if (json.Action === (ActionCode as any).MediaBulletinRequest) {
		const list = await fetchMediaBulletins(json.Limit as number || 20);
		const tmp_list: unknown[] = [];
		for (const bulletin of list) {
			let parsedBulletin;
			try {
				parsedBulletin = JSON.parse((bulletin as any).json);
			} catch {
				parsedBulletin = null;
			}
			if (parsedBulletin) tmp_list.push(parsedBulletin);
		}
		if (tmp_list.length > 0) {
			const msg = GenRandomBulletinList(tmp_list as any[]);
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
		const throttleKey = `${from}:${json.To as string}`;
		const now = Date.now();
		let entry = privateSyncThrottle.get(throttleKey);
		if (
			!entry ||
			now - entry.windowStart > PRIVATE_SYNC_WINDOW_MS ||
			entry.selfSeq !== json.SelfSequence as number ||
			entry.pairSeq !== json.PairSequence as number
		) {
			entry = {
				selfSeq: json.SelfSequence as number,
				pairSeq: json.PairSequence as number,
				count: 0,
				windowStart: now,
			};
			privateSyncThrottle.set(throttleKey, entry);
		}
		entry.count++;
		if (entry.count > PRIVATE_SYNC_MAX) {
			ConsoleWarn(
				`[PrivateMessageSync] THROTTLED: ${entry.count} identical requests from ${from} to ${json.To as string} (SelfSeq=${json.SelfSequence as number}, PairSeq=${json.PairSequence as number}) in ${PRIVATE_SYNC_WINDOW_MS}ms — likely a client sync loop, skipping response`,
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
		const members = groupMap[json.Hash as string];
		if (members) {
			const tmp_members = shuffleArray(members);
			for (let i = 0; i < tmp_members.length; i++) {
				const member = tmp_members[i];
				if (
					from !== member &&
					Conns[member as string] &&
					Conns[member as string].readyState === WebSocket.OPEN
				) {
					SendMessage(member as string, message);
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
async function SyncClientRequest(address: string): Promise<void> {
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
			} catch (e: any) {
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
			} catch (e: any) {
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
	} else if (shouldRequestBackfill(address, gap_sequence)) {
		// Gap exists — fetch from the missing point.
		// Throttled for the same reason as handleObject.Bulletin: a permanently
		// missing sequence must not re-fire on every reconnect of this client.
		// NOTE: this must stay an `else if`, not an early `return` — the private /
		// ECDH / group sync below must still run.
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
		} catch (e: any) {
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
			const bulletin = await prisma.bulletin.findFirst({
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
		const bulletin = await prisma.bulletin.findFirst({
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
	const pending_files = await prisma.file.findMany({
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
		const dh = await prisma.eCDH.findFirst({
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
				SendMessage(address, dh.json2 as string);
			} else if (dh.json2 === "") {
				SendMessage(address, dh.json1 as string);
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

async function checkMessage(ws: WebSocket, message: string, isFromNode = false): Promise<void> {
	const connAddress = fetchConnAddress(ws);
	ConsoleInfo(
		`###################LOG################### Client Message (from=${connAddress || "unknown"}, isFromNode=${isFromNode}):`,
	);
	// 不打印完整消息（bulletin 的 Content 可能很大，console I/O 慢且刷屏）。
	// 只打长度 + 前 160 字符预览，够定位用。
	ConsoleInfo(
		`[checkMessage] len=${message.length} preview=${message.slice(0, 160)}${message.length > 160 ? "..." : ""}`,
	);
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
	} else if (json.ActionCode) {
		// ServerNotify / ClientAck: control-plane messages, not actionable client requests.
		ConsoleInfo(
			`[checkMessage] ActionCode=${json.ActionCode} MessageCode=${json.MessageCode ?? "-"} from ${connAddress || "unknown"} (isFromNode=${isFromNode}), acknowledged`,
		);
	} else if (json.ObjectType) {
		// Node connections are tracked by URL (`_nodeUrl`) but not by address
		// (`_connAddress`). Without this fallback every reply addressed to `from`
		// for a node-originated object (e.g. ServerAddressList / 403) hit
		// `sendTo(null)` and the whole pull-sync pipeline stalled.
		const objFrom = connAddress ?? fetchNodeConnURL(ws);
		ConsoleInfo(`[checkMessage] ObjectType=${json.ObjectType} from ${objFrom}`);
		await handleObject(objFrom as string, message, json, isFromNode);
	} else if (json.Action) {
		ConsoleInfo(`[checkMessage] Action=${json.Action} from ${connAddress}`);
		const address = rippleKeyPairs.deriveAddress(json.PublicKey as string);
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

				if (json.Timestamp as number + DECLARE_TIMESTAMP_TOLERANCE_MS < Date.now()) {
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
					const isNodeConnection = json.URL != null && CheckServerURL(json.URL as string);

					// new connection and new address
					ConsoleWarn(
						`connected <===> ${isNodeConnection ? "node" : "client"} : <${address}>`,
					);
					(ws as any)._connAddress = address;
					Conns[address] = ws;
					if (isNodeConnection) {
						// Server Connection
						(NodeList as any[]).push({
							URL: json.URL as string,
						});
						NodeList = UniqArray(NodeList) as any;
						SyncNodeData(json.URL as string);
					}

					const msg = GenDeclare(SelfPublicKey, SelfPrivateKey, SelfURL, SiteURL);
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
					} catch {
						/* best-effort: notify-then-close; a send failure must not block the kick */
					}
					Conns[address].close();
					(ws as any)._connAddress = address;
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
function SendToNode(url: string, message: string | Buffer): void {
	sendTo(url, message, NodeConns);
}

function fetchFileFromNode(url: string, address: string, hash: string, chunk_cursor: number): void {
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
	// NOTE: `fileRequestList.values()` is a Map iterator — it has no `.some()`.
	// Calling it directly threw `TypeError: ... .some is not a function`, which
	// aborted fetchFileFromNode and (since callers are fire-and-forget inside
	// timers/socket handlers) surfaced as an unhandledRejection — now fatal.
	// Spread into an array first.
	const prev_request =
		fileRequestList.has(nonce) ||
		[...fileRequestList.values()].some((r) => r.Hash === hash);
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

async function downloadBulletinFile(url: string): Promise<void> {
	const address = fetchNodeConnURL(NodeConns[url]);
	if (address === null) {
		return;
	}

	const file_list = await prisma.file.findMany({
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
			enqueueFileFetch(url, address, file.hash, file.chunk_cursor + 1, true);
		}
	}
}

function pullBulletin(url: string): void {
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
async function pushBulletin(url: string): Promise<void> {
	// Use GROUP BY to get max(sequence) per address in a single query instead of loading all rows
	const whereClause =
		WhiteList.length > 0
			? `WHERE address IN (${WhiteList.map((a) => `'${a}'`).join(",")})`
			: "";
	const bulletin_list = await prisma.$queryRawUnsafe(
		`SELECT address, MAX(sequence) as max_seq FROM "Bulletin" ${whereClause} GROUP BY address`,
	);

	for (const row of (bulletin_list as any[])) {
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

function SyncNodeData(url: string): void {
	ConsoleWarn(`sync node data`);
	pullBulletin(url);
	pushBulletin(url);
	downloadBulletinFile(url);
}

function connectNode(node: { URL: string }): void {
	ConsoleInfo(
		`--------------------------connect to node--------------------------`,
	);
	ConsoleWarn(node);
	const ws = new WebSocket(node.URL as string);
	ws.on("open", function open() {
		ConsoleWarn(`connected <===> ${node.URL}`);
		ws.send(GenDeclare(SelfPublicKey, SelfPrivateKey, SelfURL));
		(ws as any)._nodeUrl = node.URL as string;
		NodeConns[node.URL as string] = ws;
		SyncNodeData(node.URL as string);
	});

	ws.on("message", async (data, isBinary) => {
		try {
			if (isBinary) {
				await handleBinaryMessage(data);
			} else {
				const message = data.toString();
				await checkMessage(ws, message, true);
			}
		} catch (err: any) {
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
		} catch (err: any) {
			ConsoleError(
				`[node-close-error] Failed to handle node close for ${node.URL}: ${err.message}`,
			);
		}
	});

	ws.on("error", (error) => {
		ConsoleWarn(`Node connection error for ${node.URL}: ${error.message}`);
	});
}

function keepNodeConn(): void {
	const notConnected: any[] = [];
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

function keepNodeSync(): void {
	ConsoleWarn(
		`--------------------------keepNodeSync--------------------------`,
	);
	NodeList.forEach((node) => {
		if (NodeConns[node.URL]) {
			SyncNodeData(node.URL);
		}
	});
}

async function loadgroupMap(): Promise<void> {
	const group_list = await prisma.group.findMany({
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

async function printStat(): Promise<void> {
	const bulletinCount = await prisma.bulletin.count();
	ConsoleWarn(`BulletinCount: ${bulletinCount}`);

	const fileCount = await prisma.file.count();
	ConsoleWarn(`****FileCount: ${fileCount}`);

	const addressCount = await prisma.bulletin.groupBy({
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
async function refreshData(): Promise<void> {
	// Fetch all bulletins needed for processing
	const bulletin_list = await prisma.bulletin.findMany({
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
				await prisma.bulletin.update({
					where: { hash: bulletin.pre_hash },
					data: { next_hash: bulletin.hash },
				});
			} catch (e: any) {
				ConsoleDebug(
					`[refreshData] Failed to update next_hash for pre_hash ${bulletin.pre_hash} -> ${bulletin.hash}: ${e.message}`,
				);
			}
		}
	}

	// Pre-parse all bulletin JSON upfront
	const parsed = (bulletin_list as any[])
		.map((b: any) => {
			let bJson;
			try {
				bJson = JSON.parse(b.json);
			} catch {
				bJson = null;
			}
			return bJson ? { hash: b.hash, json: bJson, signed_at: b.signed_at } : null;
		})
		.filter(Boolean) as any[];

	// Phase 2: Batch-create all unique tags across every bulletin, then bulk-connect
	const allTagNames = new Set();
	for (const { json } of parsed) {
		if (json.Tag && Array.isArray(json.Tag)) {
			for (const tag of json.Tag) allTagNames.add(tag);
		}
	}

	if (allTagNames.size > 0) {
		await prisma.tag.createMany({
			data: [...allTagNames].map((name) => ({ name: name as string })),
			skipDuplicates: true,
		});
	}

	// Bulk-connect tags to bulletins in groups to avoid one DB round-trip per bulletin
	const tagBatchSize = 50;
	for (let i = 0; i < parsed.length; i += tagBatchSize) {
		const batch = parsed
			.slice(i, i + tagBatchSize)
			.filter(
				({ json }: any) => json.Tag && Array.isArray(json.Tag) && json.Tag.length > 0,
			);
		if (batch.length === 0) continue;

await prisma.$transaction(
			batch.map(({ hash, json: bJson }: any) =>
				prisma.bulletin.update({
					where: { hash: hash as string },
					data: {
						tags: {
							connect: [...new Set(bJson.Tag as string[])].map((name) => ({ name: name as string })),
						},
					},
				}),
			),
		);
	}

	// Phase 3: Files - must stay per-bulletin (BindBulletinFile ties files to one bulletin)
	for (const { hash, json: bJson } of (parsed as any[])) {
		if (bJson.File) {
			const bulletin_address = rippleKeyPairs.deriveAddress(bJson.PublicKey as string);
			const files_to_fetch = await BindBulletinFile(hash as string, bJson.File) as any[];
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
	const existingQuotes = await prisma.reply.findMany({
		select: { post_hash: true, reply_hash: true },
	});
	const existingSet = new Set(
		existingQuotes.map((q) => `${q.post_hash}:${q.reply_hash}`),
	);

	const newReplies: any[] = [];
	for (const { hash, json: bJson, signed_at } of (parsed as any[])) {
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
		await prisma.reply.createMany({ data: newReplies, skipDuplicates: true });
		ConsoleInfo(
			`[refreshData] Linked ${newReplies.length} new quote(s) in batch`,
		);
	}
}

function startServerDaemon(): void {
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
				} catch (err: any) {
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
				} catch (err: any) {
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

async function main(): Promise<void> {
	fs.mkdirSync(path.resolve(`./${FileDir}`), { recursive: true });
	fs.mkdirSync(path.resolve(`./${AvatarDir}`), { recursive: true });

	const seed = rippleKeyPairs.generateSeed({algorithm:'ed25519'});
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
		if ((config as any).SelfURL !== "") {
			SelfURL = (config as any).SelfURL;
		}
		if ((config as any).SiteURL) {
			SiteURL = (config as any).SiteURL;
		}
		NodeList = (config as any).NodeList;
		ConsoleInfo(JSON.stringify(NodeList, null, 2));

		const wl = (config as any).WhiteList;
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
	} catch (error: any) {
		ConsoleError(
			`[main] Failed to load node config from ${ConfigPath}: ${error.message}`,
		);
	}
}

async function gracefulShutdown(signal: string): Promise<void> {
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
		} catch {
			/* best-effort: shutdown notice; connection may already be gone */
		}
	}
	// Give clients time to receive the notification
	await new Promise((resolve) => setTimeout(resolve, 1000));

	for (const addr in Conns) {
		try {
			Conns[addr].close();
		} catch {
			/* best-effort: close may throw if already closing */
		}
	}
	for (const url in NodeConns) {
		try {
			NodeConns[url].close();
		} catch {
			/* best-effort: close may throw if already closing */
		}
	}
	ConsoleWarn("All connections closed. Exiting.");
	await prisma.$disconnect();
	process.exit(0);
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

main();
