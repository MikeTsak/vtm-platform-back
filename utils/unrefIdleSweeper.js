// mysql2 closes idle pool connections (maxIdle < connectionLimit) with a
// setTimeout it re-arms every second from the moment the pool is created.
// That timer is ref'd, so any one-shot script that merely loads a pool
// (swagger-autogen, migrations CLI, media scripts) would never exit. Unref
// each timer: the server is kept alive by its HTTP listener anyway.
// Relies on a mysql2 internal; if it ever changes this degrades to a no-op
// (scripts hang again) rather than breaking the pool.
module.exports = function unrefIdleSweeper(promisePool) {
  const inner = promisePool.pool;
  const rearm = inner && inner._removeIdleTimeoutConnections;
  if (typeof rearm !== 'function') return;
  inner._removeIdleTimeoutConnections = function () {
    rearm.call(this);
    this._removeIdleTimeoutConnectionsTimer?.unref?.();
  };
  inner._removeIdleTimeoutConnectionsTimer?.unref?.();
};
