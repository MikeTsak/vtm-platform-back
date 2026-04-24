# Erebus Portal Backend — Developer Guide

This document covers everything you need to clone, configure, run, and deploy the Erebus Portal backend.

For a product/feature overview see [README.md](README.md).

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Repository Layout](#repository-layout)
3. [Setup](#setup)
4. [Configuration (.env)](#configuration-env)
5. [Database Schema](#database-schema)
6. [NPM Scripts](#npm-scripts)
7. [Local Development Workflow](#local-development-workflow)
8. [API Documentation (Swagger)](#api-documentation-swagger)
9. [Logging](#logging)
10. [Testing](#testing)
11. [Linting & Formatting](#linting--formatting)
12. [Debugging](#debugging)
13. [Docker](#docker)
14. [Deployment](#deployment)
15. [Common Gotchas](#common-gotchas)
16. [Example curl Requests](#example-curl-requests)

---

## Prerequisites

| Tool | Minimum version | Notes |
|---|---|---|
| Node.js | 18 | LTS recommended |
| npm | 9 | Comes with Node 18 |
| MariaDB | 10.5 | Tested on 10.6; MySQL 8 also works |
| Git | any | — |

> **Optional:** `nodemon` is included as a dev-dependency; no global install needed.

---

## Repository Layout

```
vtm-platform-back/
├── server.js              # Single-file Express app — all 150+ API routes
├── db.js                  # mysql2/promise connection pool
├── authMiddleware.js      # JWT authRequired + requireAdmin guards
├── logger.js              # Structured emoji logger (JSON-lines compatible)
├── swagger.config.js      # OpenAPI 3.0 spec (sources @swagger JSDoc from server.js)
├── Roboto_Condensed-Bold.ttf  # Font used for server-side meme/image generation
├── package.json
├── .gitignore
├── LICENSE.txt
├── bin/
│   └── www                # Express generator stub (not used in production — start via server.js)
├── public/                # Static file root (Express generator default)
├── routes/
│   ├── index.js           # Express generator stub
│   └── users.js           # Express generator stub
└── views/                 # Jade/Pug templates (Express generator default, not actively used)
```

> All meaningful logic lives in `server.js`. The `bin/`, `routes/`, and `views/` directories are Express generator artefacts kept for reference.

---

## Setup

```bash
# 1. Clone
git clone https://github.com/MikeTsak/vtm-platform-back.git
cd vtm-platform-back

# 2. Install dependencies
#    The postinstall script strips optional native Discord.js packages that
#    are not needed for the REST API (zlib-sync, bufferutil, utf-8-validate, erlpack).
npm install

# 3. Create your environment file
cp .env.example .env   # if .env.example exists, otherwise create .env manually
#    See "Configuration" below for all required variables.

# 4. Start the development server
npm run dev
```

The server will print startup logs and then listen on `http://localhost:3001` (or the `PORT` you set).

Tables are created automatically the first time each route group is hit — you only need an empty database.

---

## Configuration (.env)

Create a `.env` file at the project root. **Never commit this file** — it is listed in `.gitignore`.

### Required

```env
# ── HTTP ──────────────────────────────────────────────────────────────────────
PORT=3001
NODE_ENV=development          # use "production" in prod

# ── MariaDB ───────────────────────────────────────────────────────────────────
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_db_user
DB_PASS=your_db_password      # note: DB_PASS (not DB_PASSWORD)
DB_NAME=vtm

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET=replace_with_a_long_random_string
```

### Optional — Email / Password Reset

```env
# EmailJS (used for password-reset emails)
EMAILJS_SERVICE_ID=
EMAILJS_TEMPLATE_ID=
EMAILJS_USER_ID=
EMAILJS_PRIVATE_KEY=

# Template variable name overrides (defaults shown)
EMAILJS_VAR_TO=to_email
EMAILJS_VAR_NAME=to_name
EMAILJS_VAR_APP=app_name
EMAILJS_VAR_LINK=reset_link
EMAILJS_VAR_EXPIRES=expires_minutes
```

### Optional — Discord Bot

```env
DISCORD_TOKEN=                # Bot token from Discord Developer Portal
DISCORD_CLIENT_ID=            # Application / client ID
DISCORD_GUILD_ID=             # Your server (guild) ID
```

### Optional — Google Gemini AI (NPC chat)

```env
GEMINI_API_KEY=
```

### Optional — Web Push (VAPID)

```env
VAPID_PUBLIC_KEY=
VAPID_PRIVATE_KEY=
```

### Optional — CORS

```env
# Comma-separated list of allowed origins; omit for "allow all" (development default)
CORS_ORIGIN=https://vtm.miketsak.gr,https://www.vtm.miketsak.gr
```

### Optional — Logging

```env
LOG_LEVEL=debug               # debug | info | warn | error  (default: info)
LOG_JSON=0                    # 1 = emit JSON-lines (great for log aggregators)
LOG_EMOJI=1                   # 0 = strip emoji prefixes
LOG_FILE=                     # Absolute path — append log lines to file (optional)
LOG_SILENCE_PATHS=            # Comma-separated URL prefixes to suppress from request logs
```

---

## Database Schema

Tables are created automatically via `CREATE TABLE IF NOT EXISTS` when the relevant endpoint is first called. You can also create them manually:

<details>
<summary>Core tables (click to expand)</summary>

```sql
-- USERS
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email         VARCHAR(190) NOT NULL UNIQUE,
  display_name  VARCHAR(190) NOT NULL,
  role          ENUM('user','admin','court') NOT NULL DEFAULT 'user',
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- CHARACTERS (user_id nullable so NPCs can exist without an owner)
CREATE TABLE IF NOT EXISTS characters (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NULL,
  name       VARCHAR(190) NOT NULL,
  clan       VARCHAR(64)  NOT NULL,
  sheet      JSON NULL,
  xp         INT NOT NULL DEFAULT 50,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_char_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- XP LOG
CREATE TABLE IF NOT EXISTS xp_log (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  character_id  INT UNSIGNED NOT NULL,
  action        VARCHAR(64) NOT NULL,
  target        VARCHAR(190) NULL,
  from_level    INT NULL,
  to_level      INT NULL,
  cost          INT NOT NULL DEFAULT 0,
  payload       JSON NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_xp_char (character_id),
  CONSTRAINT fk_xp_char
    FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOWNTIMES
CREATE TABLE IF NOT EXISTS downtimes (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  character_id  INT UNSIGNED NOT NULL,
  title         VARCHAR(255) NOT NULL,
  feeding_type  VARCHAR(128) NULL,
  body          TEXT NOT NULL,
  status        ENUM('submitted','approved','rejected','resolved') NOT NULL DEFAULT 'submitted',
  gm_notes      TEXT NULL,
  gm_resolution TEXT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at   TIMESTAMP NULL DEFAULT NULL,
  INDEX idx_dt_char (character_id),
  CONSTRAINT fk_dt_char
    FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAINS
CREATE TABLE IF NOT EXISTS domains (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(190) NOT NULL,
  description TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAIN CLAIMS (map division → owner/color/character)
CREATE TABLE IF NOT EXISTS domain_claims (
  division             INT UNSIGNED NOT NULL PRIMARY KEY,
  owner_name           VARCHAR(190) NULL,
  color                CHAR(7) NOT NULL DEFAULT '#454545',
  owner_character_id   INT UNSIGNED NULL,
  updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_claim_char (owner_character_id),
  CONSTRAINT fk_claim_char
    FOREIGN KEY (owner_character_id) REFERENCES characters(id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- PASSWORD RESETS
CREATE TABLE IF NOT EXISTS password_resets (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  token_id    VARCHAR(255) NOT NULL,
  secret_hash VARCHAR(255) NOT NULL,
  expires_at  TIMESTAMP NOT NULL,
  used_at     TIMESTAMP NULL,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_token (token_id),
  CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

</details>

Additional tables (chat, emails, premonitions, boons, coteries, dice, news, hunts, push subscriptions, etc.) are auto-created by the server on first use.

> **FK tip:** All primary keys and foreign keys use `INT UNSIGNED`. Mismatched signedness is the most common cause of `errno: 150` when creating foreign-key constraints.

---

## NPM Scripts

```jsonc
// package.json — scripts
{
  "start":       "node server.js",          // Production start
  "dev":         "nodemon server.js",        // Development with auto-restart
  "postinstall": "npm uninstall zlib-sync bufferutil utf-8-validate erlpack --no-save"
  //              ^ Strips optional native Discord.js modules after install
}
```

| Command | Purpose |
|---|---|
| `npm start` | Start the server with plain Node (production) |
| `npm run dev` | Start with nodemon — restarts on any `.js` file change |

---

## Local Development Workflow

1. **Start the server** in watch mode: `npm run dev`
2. **Test endpoints** via:
   - Swagger UI at `http://localhost:3001/api-docs` (easiest for manual testing)
   - `curl` / Postman / HTTPie
3. **Read logs** in the terminal — the structured logger prints method, path, status, and latency for every request.
4. **Change a route** in `server.js` — nodemon reloads automatically.
5. **Add a new table** — write a `_ensure<Table>()` function (see existing pattern in `server.js`) and call it at startup.

### Useful dev endpoints

| URL | Description |
|---|---|
| `GET /api/health` | Returns `{ status: "ok" }` plus uptime info |
| `GET /api/debug/db-check` | Verifies the DB connection is alive |
| `GET /api-docs` | Swagger UI |

---

## API Documentation (Swagger)

The server self-documents via `swagger-jsdoc`. OpenAPI annotations are written as `@swagger` JSDoc comments directly in `server.js`.

**Running locally:**

1. `npm run dev`
2. Open `http://localhost:3001/api-docs`
3. Click **Authorize**, paste `Bearer <your-token>`, and use try-it-out.

**Adding documentation for a new endpoint:**

```js
/**
 * @swagger
 * /api/example:
 *   get:
 *     summary: Short description
 *     tags: [Example]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Success
 */
app.get('/api/example', authRequired, async (req, res) => { ... });
```

Swagger configuration (title, servers, security schemes, shared schemas) lives in `swagger.config.js`.

---

## Logging

The custom logger in `logger.js` supports:

| Feature | How to enable |
|---|---|
| JSON-lines output | `LOG_JSON=1` |
| Disable emoji prefixes | `LOG_EMOJI=0` |
| Adjust verbosity | `LOG_LEVEL=debug` / `info` / `warn` / `error` |
| File sink (append) | `LOG_FILE=/absolute/path/app.log` |
| Silence noisy paths | `LOG_SILENCE_PATHS=/api/health,/api/admin/logs` |

Example log output (default text mode):

```
2025-01-01T10:00:00.000Z [INFO] 🚀 start: API booting…
2025-01-01T10:00:01.000Z [INFO] ➡️  req: POST /api/auth/login | {"ip":"127.0.0.1","method":"POST","url":"/api/auth/login"}
2025-01-01T10:00:01.050Z [INFO] ✅ ok: 200 POST /api/auth/login (50ms) | {"status":200,"ms":50}
2025-01-01T10:00:05.000Z [INFO] ✨ xp: XP spend complete | {"user_id":3,"remaining_xp":40}
```

Logger categories: `start` 🚀, `auth` 🔐, `char` 🧛, `xp` ✨, `dt` 🕰️, `dom` 🏰, `adm` 🛡️, `ok` ✅, `warn` ⚠️, `err` 💥, `req` ➡️, `res` ⬅️, `mail` ✉️, `db` 🗄️, `http` 🌐, `dbg` 🐛.

---

## Testing

> **TODO:** No automated test suite exists yet. The following is a placeholder for future work.

Recommended approach when adding tests:

- Use [Jest](https://jestjs.io/) or [Vitest](https://vitest.dev/) as the test runner.
- Use [Supertest](https://github.com/ladjs/supertest) to send HTTP requests against a test instance of the Express app.
- Use a separate test database (set `DB_NAME=vtm_test` in a `.env.test` file).
- Run with: `npm test` (once configured in `package.json`).

---

## Linting & Formatting

> **TODO:** No linter or formatter is currently configured. Recommended additions:

```bash
# ESLint (JavaScript linting)
npm install --save-dev eslint

# Prettier (code formatting)
npm install --save-dev prettier
```

Suggested configs: `eslint:recommended` + `prettier` integration. Add `"lint": "eslint ."` and `"format": "prettier --write ."` to `package.json` scripts.

---

## Debugging

### Node.js debugger (VS Code)

Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug server.js",
      "program": "${workspaceFolder}/server.js",
      "envFile": "${workspaceFolder}/.env",
      "restart": true,
      "runtimeExecutable": "nodemon"
    }
  ]
}
```

### Command-line

```bash
# Enable Node inspector, then attach any DAP-compatible debugger
node --inspect server.js

# Or break on first line:
node --inspect-brk server.js
```

### Verbose logging

Set `LOG_LEVEL=debug` in `.env` to see all database queries and internal debug messages.

---

## Docker

> **TODO:** No `Dockerfile` or `docker-compose.yml` is currently present in the repository.

When added, a minimal setup would look like:

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3001
CMD ["node", "server.js"]
```

And a `docker-compose.yml` pairing it with MariaDB:

```yaml
services:
  api:
    build: .
    ports: ["3001:3001"]
    env_file: .env
    depends_on: [db]
  db:
    image: mariadb:10.6
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: vtm
      MYSQL_USER: vtm
      MYSQL_PASSWORD: vtm
    volumes:
      - db-data:/var/lib/mysql
volumes:
  db-data:
```

---

## Deployment

### With PM2 (recommended for VPS / Plesk)

```bash
npm install -g pm2

# Start
NODE_ENV=production pm2 start server.js --name erebus-api

# Auto-start on reboot
pm2 startup
pm2 save

# View logs
pm2 logs erebus-api

# Reload without downtime
pm2 reload erebus-api
```

### Environment

- Set `NODE_ENV=production` to suppress development-only behaviour.
- Set a strong random `JWT_SECRET` (e.g., `openssl rand -hex 64`).
- Restrict `CORS_ORIGIN` to your frontend domain(s).
- Use `LOG_JSON=1` if you forward logs to a log aggregator (Loki, Datadog, etc.).
- Optionally point `LOG_FILE` to a persistent path for local log retention.

### Reverse proxy (nginx example)

```nginx
server {
    listen 443 ssl;
    server_name vtm.back.miketsak.gr;

    location / {
        proxy_pass         http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection keep-alive;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

### Database

- Create a dedicated MariaDB user with privileges scoped to the `vtm` database only.
- Take regular backups (`mysqldump vtm | gzip > vtm-$(date +%F).sql.gz`).
- The server uses a connection pool with keep-alive and idle-timeout settings (`db.js`) to survive long-lived database connections.

---

## Common Gotchas

| Symptom | Cause & Fix |
|---|---|
| `Cannot find module 'mysql2/promise'` | Run `npm install` — `mysql2` is a dependency |
| `Tried to await query that isn't a promise` | Import from `db.js` which exports `pool` (mysql2/promise) — already async |
| `errno: 150` when creating `domain_claims` | Foreign key type mismatch — ensure all IDs are `INT UNSIGNED` |
| `403 Forbidden` on admin routes | Token's `role` is not `admin`. Update the `users` row and log in again |
| `401 Invalid token` after server restart | `JWT_SECRET` changed. Users must log in again to get new tokens |
| CORS errors in the browser | In dev, omit `CORS_ORIGIN` to allow all origins. In prod, set it to your frontend URL |
| Discord bot offline | `DISCORD_TOKEN` missing or invalid — check the Developer Portal |
| Meme images show tofu boxes | `Roboto_Condensed-Bold.ttf` must be present next to `server.js` |
| `ECONNRESET` from MariaDB | Normal for long-idle connections — the pool auto-reconnects; check `keepAliveInitialDelay` in `db.js` |

---

## Example curl Requests

### Register

```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"player@example.com","display_name":"Alexios","password":"changeme"}'
# => { "token": "eyJ..." }
```

### Login

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"player@example.com","password":"changeme"}'
# => { "token": "eyJ..." }
export TOKEN="eyJ..."
```

### Create a character

```bash
curl -X POST http://localhost:3001/api/characters \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alexios","clan":"Tremere","sheet":{"predatorType":"Siren"}}'
```

### Spend XP — buy a discipline level (clan)

```bash
curl -X POST http://localhost:3001/api/characters/xp/spend \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "discipline",
    "disciplineKind": "clan",
    "target": "Auspex",
    "currentLevel": 1,
    "newLevel": 2,
    "patchSheet": {
      "disciplines": { "Auspex": 2 },
      "disciplinePowers": { "Auspex": [{ "level": 2, "id": "premonition", "name": "Premonition" }] }
    }
  }'
# => { "character": { ... }, "spent": 10 }
```

### Assign a power for an existing dot (FREE)

```bash
curl -X POST http://localhost:3001/api/characters/xp/spend \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "discipline",
    "disciplineKind": "select",
    "target": "Auspex",
    "currentLevel": 2,
    "newLevel": 2,
    "patchSheet": {
      "disciplinePowers": { "Auspex": [{ "level": 1, "id": "heightened_senses", "name": "Heightened Senses" }] }
    }
  }'
# => { "character": { ... }, "spent": 0 }
```

### Admin: resolve a downtime

```bash
export ADMIN_TOKEN="eyJ..."
curl -X PATCH http://localhost:3001/api/admin/downtimes/12 \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"status":"resolved","gm_resolution":"You tracked the ghoul and reclaimed the book."}'
```

### Admin: upsert a domain claim

```bash
curl -X PATCH http://localhost:3001/api/admin/domain-claims/3 \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"owner_name":"Alexios Tremere","color":"#2563eb","owner_character_id":42}'
```

### Health check

```bash
curl http://localhost:3001/api/health
```
