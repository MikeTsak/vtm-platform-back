const { defineConfig } = require('vitest/config');

module.exports = defineConfig({
  test: {
    // The `vitest` package itself is ESM-only and this is a CommonJS
    // backend (no "type": "module") — `globals: true` exposes describe/it/
    // expect/etc. as real globals instead of requiring an import that would
    // break `require()`-based test files.
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.js'],
    // Integration tests share one isolated test database (see
    // tests/setup/testDb.js) and reset its tables between files — running
    // test files in parallel would race those resets against each other.
    fileParallelism: false,
    testTimeout: 15000,
    hookTimeout: 30000,
    globalSetup: ['./tests/setup/globalSetup.js'],
    // Redirects DB_NAME to the isolated test database before any test file's
    // own code (or the modules it requires) can build a connection pool.
    setupFiles: ['./tests/setup/env.js'],
  },
});
