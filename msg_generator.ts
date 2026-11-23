import { ActionCode, ObjectType } from "./msg_const.js";
import { SignJson } from "./util.js";

function GenDeclare(pk: string, sk: string, url: string | undefined, siteUrl?: string): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.Declare,
		URL: url,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	if (siteUrl) json.SiteURL = siteUrl;
	return JSON.stringify(SignJson(json, sk));
}

function GenFileRequest(type: number, hash: string, nonce: number, chunk_cursor: number, pk: string, sk: string): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.FileRequest,
		FileType: type,
		Hash: hash,
		Nonce: nonce,
		ChunkCursor: chunk_cursor,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	return JSON.stringify(SignJson(json, sk));
}

// ***Avatar***
function GenAvatarRequest(list: { Address: string; SignedAt: number }[], pk: string, sk: string): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.AvatarRequest,
		List: list,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	return JSON.stringify(SignJson(json, sk));
}

function GenBulletinRequest(address: string, sequence: number, to: string, pk: string, sk: string): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.BulletinRequest,
		Address: address,
		Sequence: sequence,
		To: to,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	return JSON.stringify(SignJson(json, sk));
}

function GenBulletinRequestByHash(hash: string, to: string, pk: string, sk: string): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.BulletinRequest,
		Hash: hash,
		To: to,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	return JSON.stringify(SignJson(json, sk));
}

function GenServerAddressListRequest(page: number, pk: string, sk: string): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.ServerAddressRequest,
		Page: page,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	return JSON.stringify(SignJson(json, sk));
}

function GenServerAddressList(page: number, total_page: number, address_list: string[]): string {
	const json: Record<string, unknown> = {
		ObjectType: ObjectType.ServerAddressList,
		Page: page,
		TotalPage: total_page,
		List: address_list,
	};
	return JSON.stringify(json);
}

function GenReplyBulletinList(hash: string, page: number, total_page: number, bulletin_list: unknown[]): string {
	const json: Record<string, unknown> = {
		ObjectType: ObjectType.ReplyBulletinList,
		Hash: hash,
		Page: page,
		TotalPage: total_page,
		List: bulletin_list,
	};
	return JSON.stringify(json);
}

function GenTagBulletinList(tag: string, page: number, total_page: number, bulletin_list: unknown[]): string {
	const json: Record<string, unknown> = {
		ObjectType: ObjectType.TagBulletinList,
		Tag: tag,
		Page: page,
		TotalPage: total_page,
		List: bulletin_list,
	};
	return JSON.stringify(json);
}

function GenRandomBulletinList(bulletin_list: unknown[]): string {
	const json: Record<string, unknown> = {
		ObjectType: ObjectType.RandomBulletinList,
		List: bulletin_list,
	};
	return JSON.stringify(json);
}

// ***Private***
function GenPrivateMessageSync(
	pair_address: string,
	self_sequence: number,
	pair_sequence: number,
	pk: string,
	sk: string,
): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.PrivateMessageSync,
		To: pair_address,
		SelfSequence: self_sequence,
		PairSequence: pair_sequence,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	return JSON.stringify(SignJson(json, sk));
}

// ***Group***
function GenGroupSync(pk: string, sk: string): string {
	const json: Record<string, unknown> = {
		Action: ActionCode.GroupSync,
		Timestamp: Date.now(),
		PublicKey: pk,
	};
	return JSON.stringify(SignJson(json, sk));
}

// === Control-Plane Generators (unsigned) ===
/**
 * Generate error notification message
 */
function GenServerNotifyError(code: number, message: string): string {
	return JSON.stringify({
		ActionCode: ActionCode.ServerNotify,
		MessageCode: code,
		ErrorMessage: message,
	});
}

/**
 * Generate info notification message (KickedByNewConn, ServerShutdown, SyncComplete)
 */
function GenServerNotifyInfo(code: number, message?: string): string {
	const msg: Record<string, unknown> = {
		ActionCode: ActionCode.ServerNotify,
		MessageCode: code,
	};
	if (message) msg.ErrorMessage = message;
	return JSON.stringify(msg);
}

/**
 * Generate cache success confirmation
 */
function GenServerNotifyCache(code: number): string {
	return JSON.stringify({
		ActionCode: ActionCode.ServerNotify,
		MessageCode: code,
	});
}

/**
 * Generate file transfer progress notification
 */
function GenServerNotifyFileProgress(code: number, hash: string, progress?: { ReceivedBytes: number; TotalBytes: number }): string {
	const msg: Record<string, unknown> = {
		ActionCode: ActionCode.ServerNotify,
		MessageCode: code,
		Hash: hash,
	};
	if (progress) msg.ProgressInfo = progress;
	return JSON.stringify(msg);
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
};
