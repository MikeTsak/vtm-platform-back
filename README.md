# Vampire LARP Platform — Backend (Express + MariaDB)

This is the **backend API** for the Vampire: the Masquerade V5 LARP platform. It’s a Node/Express server with MariaDB for persistence. Features include **auth**, **character creation (with XP)**, **downtimes (3 per month)**, **domains & membership**, **domain claims (claim a numbered division + hex color)**, and **admin tools**.

---

## Quick Start

### 1) Requirements
- **Node.js** 18+ (LTS recommended)
- **MariaDB** 10.6+
- **npm** 8+

### 2) Install
```bash
cd back
npm install
```
> If you previously saw `Cannot find module 'mysql2/promise'`, ensure `mysql2` is installed and you **require the promise API** in `db.js`.

### 3) Environment
Create a **`.env`** in the backend folder.

**Minimal template:**
```ini
# Server
PORT=3001
JWT_SECRET=supersecretjwtkey

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=vtm
```

**Example (MariaDB on linux159):**
```ini
PORT=3001
JWT_SECRET=supersecretjwtkey

DB_HOST=linux159.papaki.gr
DB_PORT=3306
DB_USER=cain
DB_PASSWORD=BbrGcRteay@93x^3
DB_NAME=vtm
```

> Keep secrets safe. Do not commit `.env`. See `.gitignore` in this repo.

### 4) Database Schema

Run these DDL statements once to create required tables (compatible with MariaDB 10.6). If a table already exists you can skip it.

```sql
-- USERS
CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NOT NULL UNIQUE,
  display_name VARCHAR(120) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('user','admin') NOT NULL DEFAULT 'user',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- CHARACTERS
CREATE TABLE IF NOT EXISTS characters (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  name VARCHAR(120) NOT NULL,
  clan VARCHAR(80) NOT NULL,
  sheet LONGTEXT NULL,                      -- JSON stored as text
  xp INT NOT NULL DEFAULT 50,               -- players start with 50 XP
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_char_user FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOWNTIMES (3 per calendar month per character)
CREATE TABLE IF NOT EXISTS downtimes (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  character_id INT UNSIGNED NOT NULL,
  title VARCHAR(200) NOT NULL,
  feeding_type VARCHAR(100) NULL,
  body TEXT NOT NULL,
  status ENUM('submitted','approved','rejected','resolved') NOT NULL DEFAULT 'submitted',
  gm_notes TEXT NULL,
  gm_resolution TEXT NULL,
  resolved_at TIMESTAMP NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_dt_char FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAINS
CREATE TABLE IF NOT EXISTS domains (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(120) NOT NULL UNIQUE,
  description VARCHAR(255) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAIN MEMBERS (many-to-many: domain <-> characters)
CREATE TABLE IF NOT EXISTS domain_members (
  domain_id INT UNSIGNED NOT NULL,
  character_id INT UNSIGNED NOT NULL,
  PRIMARY KEY (domain_id, character_id),
  CONSTRAINT fk_dm_domain FOREIGN KEY (domain_id) REFERENCES domains(id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_dm_character FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAIN CLAIMS (claim a numeric division + color)
-- Ensure the UNSIGNED type matches characters.id exactly
CREATE TABLE IF NOT EXISTS domain_claims (
  division INT NOT NULL PRIMARY KEY,
  owner_character_id INT UNSIGNED NULL,
  owner_name VARCHAR(100) NOT NULL,
  color CHAR(7) NOT NULL,                  -- '#RRGGBB'
  claimed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_owner_character_id (owner_character_id),
  CONSTRAINT fk_claim_char FOREIGN KEY (owner_character_id) REFERENCES characters(id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed example: “division 3 owned by FirstName Last Name”
INSERT INTO domain_claims (division, owner_name, color)
VALUES (3, 'FirstName Last Name', '#b40f1f')
ON DUPLICATE KEY UPDATE owner_name=VALUES(owner_name), color=VALUES(color);

-- XP LOG (optional)
CREATE TABLE IF NOT EXISTS xp_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  character_id INT UNSIGNED NOT NULL,
  action VARCHAR(50) NOT NULL,             -- e.g., attribute, skill, discipline, ritual
  target VARCHAR(120) NULL,
  from_level INT NULL,
  to_level INT NULL,
  cost INT NOT NULL,
  payload LONGTEXT NULL,                   -- JSON
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_xp_char FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```
> If you get `errno: 150` on a foreign key, ensure the referenced column type **matches exactly** (e.g., `INT UNSIGNED`).

### 5) Run
```bash
# Development
node server.js
# or with nodemon if installed
npx nodemon server.js
```
Server boots at: `http://localhost:${PORT}`

---

## Project Structure (backend)

```
back/
├─ server.js          # Express app, routes
├─ db.js              # mysql2 pool (promise)
├─ authMiddleware.js  # JWT auth + requireAdmin
├─ .env               # environment (not committed)
├─ package.json
└─ ...other files
```

### `db.js` (promise wrapper)
Make sure you’re using the promise API:
```js
// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: 10,
  supportBigNumbers: true,
  dateStrings: true
});

module.exports = pool;
```

---

## API Overview

> All JSON. Most routes require `Authorization: Bearer <JWT>` from `/api/auth/login`.

### Auth
- `POST /api/auth/register` → `{ email, display_name, password }` → `{ token }`
- `POST /api/auth/login` → `{ email, password }` → `{ token }`
- `GET /api/auth/me` → user payload from token

### Characters
- `GET /api/characters/me` → current user’s character (or `null`)
- `POST /api/characters` → `{ name, clan, sheet }` creates character with **xp=50**
- `PUT /api/characters` → update own character `{ name?, clan?, sheet? }`

### XP Spend
- `POST /api/characters/xp/spend`
  - Body (varies by type):
    - attributes: `{ type:'attribute', target, currentLevel, newLevel }` cost `new × 5`
    - skills: `{ type:'skill', target, currentLevel, newLevel }` cost `new × 3`
    - specialty: `{ type:'specialty', target }` cost `3`
    - discipline: `{ type:'discipline', disciplineKind:'clan'|'other'|'caitiff'|'select', target, currentLevel, newLevel, patchSheet? }`
      - clan: `new × 5`, other: `new × 7`, caitiff: `new × 6`
      - **select**: `newLevel === currentLevel`, **cost = 0**, only applies `patchSheet` with the specific power choice.
    - ritual: `{ type:'ritual', ritualLevel }` cost `level × 3`
    - thin blood formula: `{ type:'thin_blood_formula', formulaLevel }` cost `level × 3`
    - advantage: `{ type:'advantage', target, dots }` cost `dots × 3`
    - blood potency: `{ type:'blood_potency', currentLevel, newLevel }` cost `new × 10`
  - On success: `{ character, spent }`

### Downtimes
- `GET /api/downtimes/quota` → `{ used, limit: 3 }` per calendar month
- `GET /api/downtimes/mine` → list of my downtimes
- `POST /api/downtimes` → `{ title, body, feeding_type? }` (auto-completes feeding type from Predator if omitted)

### Domains
- `GET /api/domains` → all domains + members
- **Admin:**
  - `POST /api/admin/domains` → `{ name, description }`
  - `DELETE /api/admin/domains/:id`
  - `POST /api/admin/domains/:id/members` → `{ character_id }`
  - `DELETE /api/admin/domains/:id/members/:character_id`

### Domain Claims (divisions + hex color)
- `GET /api/domain-claims` → list all claims (division, owner_name, color, …)
- **Player** claim (first-come): `POST /api/domain-claims/claim` → `{ division:int, color:"#RRGGBB" }`
  - If the user has a character, `owner_character_id` is recorded; otherwise owner falls back to display name/email
- **Admin upsert/override**: `PATCH /api/admin/domain-claims/:division`
  - Body: `{ owner_name?, color?, owner_character_id? (null to unlink) }`
- **Admin unclaim**: `DELETE /api/admin/domain-claims/:division`

### Admin
- `GET /api/admin/users` → user list with linked character data if any
- `GET /api/admin/downtimes` → all downtimes (with character + player info)
- `PATCH /api/admin/downtimes/:id` → `{ status?, gm_notes?, gm_resolution? }`
- `PATCH /api/admin/characters/:id/xp` → `{ delta }`
- *(optional but wired in FE)* `PATCH /api/admin/users/:id` → `{ display_name?, email?, role? }`
- *(optional but wired in FE)* `PATCH /api/admin/characters/:id` → `{ name?, clan?, sheet? }`

---

## Logging (with emojis)

The server uses lightweight console logs around critical paths. Examples:
- 🧬 Auth events (login/register)
- 🧛 Character create/update
- 🧮 XP spend: start, insufficient XP, completion, XP log insert
- 🕰️ Downtimes: quota checks, creation
- 🏳️ Domains: create/delete/member changes
- 🗺️ Claims: claim/override/unclaim

Search for `log.auth`, `log.char`, `log.xp`, `log.dt`, `log.dom`, `log.claim`, `log.ok`, `log.warn`, `log.err` in `server.js`.

---

## Common Pitfalls & Fixes

**1) “Cannot find module 'mysql2/promise'”**  
Install `mysql2` and make sure you import the **promise** version:
```bash
npm i mysql2
```
```js
const mysql = require('mysql2/promise'); // in db.js
```

**2) “You have tried to call .then() on query that is not a promise”**  
You’re using the non-promise API. Ensure you created the pool via `mysql2/promise` and use `await pool.query(...)`.

**3) errno 150 (foreign key incorrectly formed)**  
Make sure FK column type **matches exactly** (e.g., `INT UNSIGNED`) and both tables are InnoDB.

**4) bcrypt build issues on Windows**  
Use `bcryptjs` (already in this project) to avoid native build steps.

---

## Sample cURL

```bash
# Register
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","display_name":"Tester","password":"secret"}'

# Login
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"secret"}'

# Create character (replace TOKEN)
curl -X POST http://localhost:3001/api/characters \
  -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Eirene","clan":"Toreador","sheet":{"predatorType":"Siren","disciplines":{"Presence":2,"Auspex":1}}}'
```

---

## License
Private project for LARP usage. © 2025
