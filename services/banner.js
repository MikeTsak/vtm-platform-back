// services/banner.js
//
// In-process notifier for the global announcement banner. The admin write
// endpoint emits 'update'; every open /api/system/banner/stream SSE connection
// listens and re-pushes, so a banner change lands on connected clients without
// them polling.

const { EventEmitter } = require('events');

const bannerEmitter = new EventEmitter();
// One listener per open SSE connection; the default cap of 10 would start
// printing spurious leak warnings with a handful of admins watching.
bannerEmitter.setMaxListeners(0);

module.exports = { bannerEmitter };
