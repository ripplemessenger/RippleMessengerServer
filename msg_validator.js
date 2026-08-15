import Ajv from "ajv";
import {
	DeclareSchema,
	BulletinSchema,
	RandomBulletinRequestSchema,
	RandomBulletinListSchema,
	BulletinRequestSchema,
	ReplyBulletinRequestSchema,
	ECDHHandshakeSchema,
	PrivateMessageSchema,
	PrivateMessageSyncSchema,
	FileRequestSchema,
	AvatarRequestSchema,
	GroupMessageSyncSchema,
	AvatarListSchema,
	GroupListSchema,
	GroupSyncSchema,
	GroupMessageListSchema,
	BulletinSubscribeSchema,
	ReplyBulletinListSchema,
	TagBulletinListSchema,
	TagBulletinRequestSchema,
	ServerAddressListSchema,
	ServerAddressRequestSchema,
	GroupCreateSchema,
	GroupDeleteSchema,
	GroupMessageSchema,
} from "./msg_schema.js";
import { ConsoleWarn, ConsoleError } from "./util.js";
import { ActionCode, ObjectType } from "./msg_const.js";

const ajv = new Ajv({ allErrors: true });

// --- Pre-compiled validators ---
const vDeclare = ajv.compile(DeclareSchema);
const vBulletin = ajv.compile(BulletinSchema);
const vBulletinRequest = ajv.compile(BulletinRequestSchema);
const vBulletinSubscribe = ajv.compile(BulletinSubscribeSchema);
const vECDHHandshake = ajv.compile(ECDHHandshakeSchema);
const vPrivateMessage = ajv.compile(PrivateMessageSchema);
const vPrivateMessageSync = ajv.compile(PrivateMessageSyncSchema);
const vFileRequest = ajv.compile(FileRequestSchema);
const vAvatarRequest = ajv.compile(AvatarRequestSchema);
const vGroupMessageSync = ajv.compile(GroupMessageSyncSchema);
const vAvatarList = ajv.compile(AvatarListSchema);
const vGroupList = ajv.compile(GroupListSchema);
const vGroupSync = ajv.compile(GroupSyncSchema);
const vGroupMessageList = ajv.compile(GroupMessageListSchema);
const vReplyBulletinRequest = ajv.compile(ReplyBulletinRequestSchema);
const vReplyBulletinList = ajv.compile(ReplyBulletinListSchema);
const vTagBulletinList = ajv.compile(TagBulletinListSchema);
const vTagBulletinRequest = ajv.compile(TagBulletinRequestSchema);
const vServerAddressList = ajv.compile(ServerAddressListSchema);
const vServerAddressRequest = ajv.compile(ServerAddressRequestSchema);
const vRandomBulletinRequest = ajv.compile(RandomBulletinRequestSchema);
const vRandomBulletinList = ajv.compile(RandomBulletinListSchema);
const vGroupCreate = ajv.compile(GroupCreateSchema);
const vGroupDelete = ajv.compile(GroupDeleteSchema);
const vGroupMessage = ajv.compile(GroupMessageSchema);

// --- Generic schema checker (extracts 18-line pattern into 6 lines) ---
function checkSchema(validate, name, json) {
	try {
		if (!validate(json)) {
			ConsoleWarn(`${name} invalid`);
			return false;
		}
		return json;
	} catch (error) {
		ConsoleError(`${name} check failed: ${error.message}`);
		return false;
	}
}

// --- Shorthand wrappers ---
const chkDeclare = (j) => checkSchema(vDeclare, "Declare", j);
const chkBulletin = (j) => checkSchema(vBulletin, "Bulletin", j);
const chkBulletinRequest = (j) =>
	checkSchema(vBulletinRequest, "BulletinRequest", j);
const chkBulletinSubscribe = (j) =>
	checkSchema(vBulletinSubscribe, "BulletinSubscribe", j);
const chkECDHHandshake = (j) => checkSchema(vECDHHandshake, "ECDHHandshake", j);
const chkPrivateMessage = (j) =>
	checkSchema(vPrivateMessage, "PrivateMessage", j);
const chkPrivateMessageSync = (j) =>
	checkSchema(vPrivateMessageSync, "PrivateMessageSync", j);
const chkFileRequest = (j) => checkSchema(vFileRequest, "FileRequest", j);
const chkAvatarRequest = (j) => checkSchema(vAvatarRequest, "AvatarRequest", j);
const chkGroupMessageSync = (j) =>
	checkSchema(vGroupMessageSync, "GroupMessageSync", j);
const chkAvatarList = (j) => checkSchema(vAvatarList, "AvatarList", j);
const chkGroupList = (j) => checkSchema(vGroupList, "GroupList", j);
const chkGroupSync = (j) => checkSchema(vGroupSync, "GroupSync", j);
const chkGroupMessageList = (j) =>
	checkSchema(vGroupMessageList, "GroupMessageList", j);
const chkReplyBulletinRequest = (j) =>
	checkSchema(vReplyBulletinRequest, "ReplyBulletinRequest", j);
const chkReplyBulletinList = (j) =>
	checkSchema(vReplyBulletinList, "ReplyBulletinList", j);
const chkTagBulletinList = (j) =>
	checkSchema(vTagBulletinList, "TagBulletinList", j);
const chkTagBulletinRequest = (j) =>
	checkSchema(vTagBulletinRequest, "TagBulletinRequest", j);
const chkServerAddressList = (j) =>
	checkSchema(vServerAddressList, "ServerAddressList", j);
const chkServerAddressRequest = (j) =>
	checkSchema(vServerAddressRequest, "ServerAddressRequest", j);
const chkRandomBulletinRequest = (j) =>
	checkSchema(vRandomBulletinRequest, "RandomBulletinRequest", j);
const chkRandomBulletinList = (j) =>
	checkSchema(vRandomBulletinList, "RandomBulletinList", j);
const chkGroupCreate = (j) => checkSchema(vGroupCreate, "GroupCreate", j);
const chkGroupDelete = (j) => checkSchema(vGroupDelete, "GroupDelete", j);
const chkGroupMessage = (j) => checkSchema(vGroupMessage, "GroupMessage", j);

function deriveJson(str) {
	try {
		return JSON.parse(str);
	} catch (e) {
		ConsoleWarn("not a valid json");
		return false;
	}
}

function MsgValidate(strJson) {
	const json = deriveJson(strJson);
	if (!json) return false;

	if (json.Action) {
		switch (json.Action) {
			case ActionCode.Declare:
				return chkDeclare(json);
			case ActionCode.FileRequest:
				return chkFileRequest(json);
			case ActionCode.AvatarRequest:
				return chkAvatarRequest(json);
			case ActionCode.BulletinRequest:
				return chkBulletinRequest(json);
			case ActionCode.BulletinSubscribe:
				return chkBulletinSubscribe(json);
			case ActionCode.ServerAddressRequest:
				return chkServerAddressRequest(json);
			case ActionCode.ReplyBulletinRequest:
				return chkReplyBulletinRequest(json);
			case ActionCode.TagBulletinRequest:
				return chkTagBulletinRequest(json);
			case ActionCode.RandomBulletinRequest:
				return chkRandomBulletinRequest(json);
			case ActionCode.PrivateMessageSync:
				return chkPrivateMessageSync(json);
			case ActionCode.GroupSync:
				return chkGroupSync(json);
			case ActionCode.GroupMessageSync:
				return chkGroupMessageSync(json);
			default:
				ConsoleWarn("unknown Action code");
				return false;
		}
	} else if (json.ObjectType) {
		switch (json.ObjectType) {
			case ObjectType.AvatarList:
				return chkAvatarList(json);
			case ObjectType.Bulletin:
				return chkBulletin(json);
			case ObjectType.ServerAddressList:
				return chkServerAddressList(json);
			case ObjectType.ReplyBulletinList:
				return chkReplyBulletinList(json);
			case ObjectType.TagBulletinList:
				return chkTagBulletinList(json);
			case ObjectType.RandomBulletinList:
				return chkRandomBulletinList(json);
			case ObjectType.ECDH:
				return chkECDHHandshake(json);
			case ObjectType.PrivateMessage:
				return chkPrivateMessage(json);
			case ObjectType.GroupCreate:
				return chkGroupCreate(json);
			case ObjectType.GroupDelete:
				return chkGroupDelete(json);
			case ObjectType.GroupList:
				return chkGroupList(json);
			case ObjectType.GroupMessage:
				return chkGroupMessage(json);
			case ObjectType.GroupMessageList:
				return chkGroupMessageList(json);
			default:
				ConsoleWarn("unknown ObjectType");
				return false;
		}
	}

	return false;
}

export { MsgValidate };
