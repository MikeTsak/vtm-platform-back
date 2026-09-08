// services/token.js
//
// Session JWT minting. `tv` is the token version — bumping a user's version
// (utils/tokenVersion.js) invalidates every token already issued to them,
// which is how logout-everywhere and forced re-auth after a role change work.
//
// routes/auth.js keeps its own copy of this for now: it is registered with an
// injected pool for integration tests and must not reach into ../db.

const jwt = require('jsonwebtoken');

const issueToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, role: user.role, display_name: user.display_name, tv: user.token_version || 0 },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

module.exports = { issueToken };
