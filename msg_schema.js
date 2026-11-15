// JSON schemas.
//
// The canonical schemas live in @ripplemessenger/protocol. This file is a thin
// re-export so existing `import { DeclareSchema } from "./msg_schema.js"` call
// sites keep working unchanged.
//
// Verified identical to the old local copy by
// packages/protocol/scripts/schema-parity.mjs (35 schemas, 43 assertions).
export {
	// declare
	DeclareSchema,
	// file
	FileRequestSchema,
	// avatar
	AvatarRequestSchema,
	AvatarSchema,
	AvatarListSchema,
	// bulletin
	BulletinSchema,
	BulletinSubscribeSchema,
	BulletinRequestSchema,
	ServerAddressRequestSchema,
	ServerAddressListSchema,
	ReplyBulletinRequestSchema,
	ReplyBulletinListSchema,
	TagBulletinRequestSchema,
	TagBulletinListSchema,
	RandomBulletinRequestSchema,
	RandomBulletinListSchema,
	// chat handshake
	ECDHHandshakeSchema,
	// private
	PrivateMessageSchema,
	PrivateMessageSyncSchema,
	// group
	GroupSyncSchema,
	GroupMessageSyncSchema,
	GroupListSchema,
	GroupCreateSchema,
	GroupDeleteSchema,
	GroupMessageSchema,
	GroupMessageListSchema,
	// message objects
	MessageObjectBulletinSchema,
	MessageObjectPrivateChatFileSchema,
	MessageObjectGroupChatFileSchema,
	// control plane
	ServerNotifyErrorSchema,
	ServerNotifyInfoSchema,
	ServerNotifyCacheSchema,
	ServerNotifyFileProgressSchema,
	ClientAckSchema,
} from "@ripplemessenger/protocol/schema";
