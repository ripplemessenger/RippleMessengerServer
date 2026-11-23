# RippleMessengerServer

> TypeScript（strict）+ tsx 运行时。核心逻辑在 `main.ts` / `msg_generator.ts` / `util.ts` / `const.ts`；
> 协议 shim（`msg_const.js` / `msg_schema.js` / `msg_validator.js`）保持 .js 不动（parity 测试直接 import）。

## Run
1. install nodejs (>=18) and postgresql database
2. clone the code
3. run
```
npm install
npx prisma generate
npx prisma migrate dev
npx prisma migrate reset
npx prisma migrate deploy
npm start          # = tsx main.ts
```

## Dev
- 类型检查：`npx tsc --noEmit`
- devDependencies：`typescript` / `tsx` / `@types/node`

## Donate
rBoy4AAAAA9qxv7WANSdP5j5y59NP6soJS
