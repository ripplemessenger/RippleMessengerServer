// Message validation.
//
// The canonical validator lives in @ripplemessenger/protocol. This file is a
// thin re-export so existing `import { MsgValidate } from "./msg_validator.js"`
// call sites keep working unchanged.
//
// Semantics (unchanged from the old local copy):
//   - Input is a JSON **string**.
//   - On success it returns the **parsed object** (truthy), not `true`.
//   - On failure it returns `false`.
//
// Verified identical to the old local copy by
// packages/protocol/scripts/parity-test.mjs (49 behaviour samples, 49/49 pass).
export { MsgValidate } from "@ripplemessenger/protocol/validator";
