# Legacy server entrypoints

`server.js` (plain Node/Express-ish) and `server.express.js` were near-duplicate
copies of `server.fastify.js`, kept in sync by hand. Only `server.fastify.js`
is ever started — see `back/package.json` (`main`, `start`, `dev` all point to
it) — so the other two were dead code that still had to be edited every time a
bug fix landed, which is exactly how the `system_config` cron bug shipped
identically in all three files.

Archived here instead of deleted so the history isn't lost. Safe to delete
outright once nobody needs to diff against them.
