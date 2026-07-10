# VTM Platform (V5 LARP) — Backend

Express + MariaDB backend API for the **Vampire: The Masquerade V5 LARP** platform.

It provides authentication, character management, XP economy (including discipline power assignment), downtimes, domains/claims, and admin tooling (users, XP tools, and NPCs).

- Frontend: Located in the `front/` directory of this repository
- API base (local default): `http://localhost:3001/api`
- Swagger UI (if enabled): `http://localhost:3001/api-docs`

## Project Ecosystem

This backend is part of the Vampire Platform monorepo, which includes:

- `front/` - React single-page application for player and Storyteller/admin interfaces
- `hunt/` - Hunt tracker application for managing hunting chronicles
- `erebus-mobile/` - Mobile companion app for in-character (SchreckNet) and out-of-character (Surface Web) communication
- `larp-badges/` - Tool for generating printable character badges
- `attlarp.gr/` - Athens Through Time chronicle website (lore, setting, gallery)
- `db/` - Database schemas and sample data

All components communicate with this backend API to provide a full-featured LARP management platform.

---

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Environment variables](#environment-variables)
- [Database schema (SQL)](#database-schema-sql)
- [Project layout](#project-layout)
- [Authentication & roles](#authentication--roles)
- [API overview](#api-overview)
  - [Auth](#auth)
  - [Characters (player)](#characters-player)
  - [Downtimes (player)](#downtimes-player)
  - [Domains / claims](#domains--claims)
  - [Admin endpoints](#admin-endpoints)
  - [NPC endpoints (admin)](#npc-endpoints-admin)
- [XP spend rules](#xp-spend-rules)
- [Swagger / OpenAPI](#swagger--openapi)
- [Troubleshooting / gotchas](#troubleshooting--gotchas)
- [cURL examples](#curl-examples)
- [Production notes](#production-notes)

---

## Requirements

- Node.js 18+ (npm 9+ recommended)
- MariaDB 10.5+ (tested on 10.6)
- A database + user with privileges to create tables (InnoDB)

---

## Quick start

```bash
# 1) Install deps
npm install

# 2) Create .env
cp .env.example .env
# edit .env with DB credentials + JWT secret

# 3) Run migrations (creates tables)
npm run migrate

# 4) Run server
npm start
# or (if present)
npm run dev
```

The API should be available on:

- `http://localhost:3001/api`

---

## Environment variables

Create a `.env` file in the repo root:

```env
# HTTP
PORT=3001
NODE_ENV=development

# MariaDB
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=vtm

# JWT
JWT_SECRET=replace_me_with_strong_random

# Optional logging
LOG_LEVEL=debug
```

Notes:

- The server uses strict startup validation (via `Zod`). If any required variable is missing, the app will instantly crash and tell you which one.
- Don’t commit secrets. Ensure `.env` is in `.gitignore`.
- Changing `JWT_SECRET` invalidates existing tokens (users must re-login).

---

## Database schema (SQL)

Run these statements in your MariaDB database (InnoDB + `utf8mb4`).

> If you ever hit `errno: 150` on foreign keys: it’s usually type mismatch (signed vs unsigned) or different engines/collations. The schema below uses `INT UNSIGNED` consistently for IDs.

```sql
-- USERS
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email         VARCHAR(190) NOT NULL UNIQUE,
  display_name  VARCHAR(190) NOT NULL,
  role          ENUM('user','admin') NOT NULL DEFAULT 'user',
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- CHARACTERS
-- user_id is nullable so NPCs can exist (NPC = character with user_id NULL)
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

-- XP LOG (optional but recommended)
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

-- DOMAINS (optional catalog)
CREATE TABLE IF NOT EXISTS domains (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(190) NOT NULL,
  description TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAIN CLAIMS (map division -> owner/color/character)
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
```

---

## Project layout

(High level — see the repo for exact filenames)

```
server.js            # Express app + routes
db.js                # mysql2 pool (promise)
authMiddleware.js    # JWT auth + requireAdmin
swagger.config.js    # OpenAPI config (if enabled)
```

---

## Authentication & roles

- Auth uses JWT.
- Clients must send: `Authorization: Bearer <token>`
- Users have a `role` of `user` or `admin`.
- Admin routes return **403** if the token role is not `admin`.

---

## API overview

Base path: `/api`

### Auth

- `POST /auth/register` → returns `{ token }`
- `POST /auth/login` → returns `{ token }`
- `GET /auth/me` → returns `{ user }` (requires auth)

### Characters (player)

- `GET /characters/me` → `{ character }`
- `POST /characters` body `{ name, clan, sheet }` → `{ character }` (starts at **50 XP**)
- `PUT /characters` body `{ name?, clan?, sheet? }` → `{ character }`
- `POST /characters/xp/spend` → `{ character, spent }`

### Downtimes (player)

- `GET /downtimes/quota` → `{ used, limit: 3 }` (per calendar month)
- `GET /downtimes/mine` → `{ downtimes: [...] }`
- `POST /downtimes` body `{ title, body, feeding_type? }` → `{ downtime }`

### Domains / claims

- `GET /domain-claims` → `{ claims: [...] }`

### Admin endpoints

- `GET /admin/users`
- `PATCH /admin/users/:id` body `{ display_name?, email?, role? }` (if implemented)
- `PATCH /admin/characters/:id` body `{ name?, clan?, sheet? }`
- `PATCH /admin/characters/:id/xp` body `{ delta }`
- `GET /admin/downtimes`
- `PATCH /admin/downtimes/:id` body `{ status?, gm_notes?, gm_resolution? }`
- Claims:
  - `PATCH /admin/domain-claims/:division` body `{ owner_name?, color?, owner_character_id? }` (upsert)
  - `DELETE /admin/domain-claims/:division`

### NPC endpoints (admin)

NPCs are `characters` with `user_id IS NULL`.

- `GET /admin/npcs`
- `POST /admin/npcs` body `{ name, clan, sheet? }` → starts at **10,000 XP**
- `GET /admin/npcs/:id`
- `PATCH /admin/npcs/:id` body `{ name?, clan?, sheet? }`
- `DELETE /admin/npcs/:id`
- `POST /admin/npcs/:id/xp/spend`

---

## XP spend rules

Endpoint:

- `POST /api/characters/xp/spend`

Body (varies by purchase type):

```jsonc
{
  "type": "attribute" | "skill" | "specialty" |
          "discipline" | "ritual" | "ceremony" |
          "thin_blood_formula" | "advantage" |
          "blood_potency",
  "target": "Presence",
  "currentLevel": 1,
  "newLevel": 2,
  "disciplineKind": "clan" | "other" | "caitiff" | "select",
  "ritualLevel": 2,
  "formulaLevel": 1,
  "dots": 1,
  "patchSheet": { /* optional updated sheet JSON */ }
}
```

Costs:

- Attribute: `new × 5`
- Skill: `new × 3`
- Specialty: `3`
- Discipline:
  - clan: `new × 5`
  - other: `new × 7`
  - caitiff: `new × 6`
- Discipline power assignment **only** (no dot increase): **free**
- Ritual: `level × 3`
- Ceremony: `level × 3`
- Thin-blood formula: `level × 3`
- Advantage: `3 × dots`
- Blood potency: `new × 10`

Response:

```json
{ "character": { /* updated */ }, "spent": 15 }
```

---

## Swagger / OpenAPI

If Swagger is enabled in this backend:

- Local: `http://localhost:3001/api-docs`
- Production (as referenced in code/docs): `https://vtm.back.miketsak.gr/api-docs`

To authorize in Swagger UI:

1. Call `/api/auth/login` to obtain a token.
2. Click **Authorize**.
3. Paste: `Bearer <token>`

---

## Troubleshooting / gotchas

- **FK create errors (`errno:150`)**: check signed vs unsigned ID types and ensure InnoDB.
- **403 on admin routes**: your JWT role isn’t `admin`.
- **JWT invalid**: server restarted with a different `JWT_SECRET`.
- **CORS**: ensure the Express app allows the frontend origin in development.
- **mysql2 promise usage**: export `pool.promise()` from `db.js` and `await pool.query(...)`.

---

## cURL examples

### Register

```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","display_name":"Admin","password":"changeme"}'
```

### Login

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"changeme"}'
# => { "token": "..." }
```

### Create character

```bash
curl -X POST http://localhost:3001/api/characters \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Alexios","clan":"Tremere","sheet":{"predatorType":"Siren"}}'
```

### Spend XP (discipline dot increase)

```bash
curl -X POST http://localhost:3001/api/characters/xp/spend \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "type":"discipline",
    "disciplineKind":"clan",
    "target":"Auspex",
    "currentLevel":1,
    "newLevel":2,
    "patchSheet":{ "disciplines": {"Auspex":2} }
  }'
```

### Admin: resolve a downtime

```bash
curl -X PATCH http://localhost:3001/api/admin/downtimes/12 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"status":"resolved","gm_resolution":"You tracked the ghoul and reclaimed the book."}'
```

---

## Production notes

- Run behind a reverse proxy (nginx) with TLS.
- Use a process manager (PM2/systemd).
- Keep DB backups.
- Rotate `JWT_SECRET` carefully (forces user re-login).
