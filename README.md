# Erebus Portal — Backend

> **The API server powering the Erebus Portal, a full-featured web platform for Vampire: The Masquerade V5 LARP (live-action role-play) chronicles.**

Production API: **<https://vtm.back.miketsak.gr>**  
Interactive docs: **<https://vtm.back.miketsak.gr/api-docs>**

---

## Table of Contents

1. [What Is This?](#what-is-this)
2. [Problem It Solves](#problem-it-solves)
3. [Key Capabilities](#key-capabilities)
4. [High-Level Architecture](#high-level-architecture)
5. [API Reference](#api-reference)
6. [Quick Start](#quick-start)
7. [Related Resources](#related-resources)

---

## What Is This?

The **Erebus Portal backend** is a Node.js/Express REST API backed by a MariaDB database. It is the data and logic layer for a private Vampire: The Masquerade V5 chronicle (LARP), providing everything a Storyteller and players need to manage a live chronicle online — from character creation and XP spending to in-character messaging, domain politics, and admin tooling.

The project is deliberately self-contained: all routes live in `server.js` with supporting modules for the database pool, JWT auth middleware, structured logging, and Swagger configuration.

---

## Problem It Solves

Running a VtM V5 LARP chronicle involves significant bookkeeping:

- Tracking dozens of player characters across sessions, each with a full character sheet, XP balance, disciplines, and predator type.
- Managing downtime actions (limited per month, reviewed by Storytellers).
- Assigning domain territories on a live map visible to all players.
- Enabling in-character communication (chat, email, NPC AI conversations) without leaking out-of-character information.
- Giving Storytellers powerful admin tools — NPC creation with a large XP budget, bulk XP grants, downtime resolution, and premonition delivery to Malkavian characters.

This backend centralises all of that in one deployable Node.js service with no external message broker or cache required.

---

## Key Capabilities

| Domain | Feature |
|---|---|
| **Auth** | JWT-based registration, login, token refresh, and password reset via email |
| **Characters** | Full V5 character sheet (JSON), XP economy with correct clan/discipline costs, rebuild flow |
| **Disciplines & XP** | Attribute, skill, specialty, discipline, ritual, ceremony, thin-blood formula, advantage, blood potency — all with V5 cost rules enforced server-side |
| **Downtimes** | Player submission (3 per calendar month), Storyteller review and resolution |
| **Domains & Claims** | Territory ownership stored per map division; powers the GeoJSON map in the frontend |
| **NPCs** | Admin-only NPC characters (10 000 XP budget) with full sheet/XP support |
| **In-character Chat** | Direct messages between players, group chats, NPC AI conversations powered by Google Gemini |
| **In-character Email** | Diegetic in-game email system (Nodemailer / EmailJS) |
| **Premonitions** | Storyteller uploads and delivers visions to Malkavian characters |
| **Coteries** | Coterie creation, membership, and shared XP pool |
| **Boons** | Boon tracking for the court (restricted to court-role users) |
| **Camarilla Roster** | Hierarchical Camarilla position management |
| **Dice Rolls** | Server-side dice rolling with full roll history |
| **News & Announcements** | In-portal news feed with media attachments |
| **Hunts** | Multi-step hunting scenarios with group formation, progression, and Storyteller review |
| **Discord Integration** | Discord.js bot: notifications, DMs, music playback, error reporting |
| **Web Push** | Browser push notification subscriptions and delivery |
| **Observability** | Structured emoji-tagged logger with JSON-lines mode, optional file sink, per-request HTTP logs |
| **Interactive API Docs** | Swagger UI at `/api-docs` (OpenAPI 3.0) |

---

## High-Level Architecture

```
+------------------------------------------+
|          React Frontend (SPA)            |
|  (separate repo — paired with this API)  |
+------------------+-----------------------+
                   | HTTPS / REST JSON
                   v
+------------------------------------------+
|         Express API  (server.js)         |
|                                          |
|  * JWT auth middleware (authMiddleware)  |
|  * 150+ REST routes                      |
|  * Structured logger  (logger.js)        |
|  * Swagger/OpenAPI   (swagger.config)    |
|  * Discord.js bot    (in-process)        |
|  * Google Gemini AI  (NPC chat)          |
|  * Web-push          (VAPID)             |
+-------------+----------------------------+
              | mysql2 connection pool (db.js)
              v
+------------------------------------------+
|       MariaDB 10.5+  (InnoDB)            |
|  Tables auto-created on first request   |
+------------------------------------------+
              | HTTP (Nodemailer / EmailJS)
              v
        External SMTP / EmailJS service
```

All tables are created lazily via `CREATE TABLE IF NOT EXISTS` when the relevant route group is first hit — no separate migration runner is required.

---

## API Reference

Interactive documentation (try-it-out enabled) is available at:

- **Development:** <http://localhost:3001/api-docs>
- **Production:** <https://vtm.back.miketsak.gr/api-docs>

The API is documented with OpenAPI 3.0 annotations in `server.js` and configured in `swagger.config.js`.

### Authentication

All protected endpoints require a `Bearer` token in the `Authorization` header:

```
Authorization: Bearer <jwt-token>
```

Obtain a token from `POST /api/auth/login` or `POST /api/auth/register`.

### Route Groups (summary)

| Prefix | Description |
|---|---|
| `/api/auth` | Register, login, refresh, forgot/reset password |
| `/api/characters` | Player character CRUD, XP spend, rebuild |
| `/api/downtimes` | Player downtime submissions and quota |
| `/api/domain-claims` | Map territory ownership |
| `/api/coteries` | Coterie management |
| `/api/boons` | Boon records (court role) |
| `/api/chat` | Direct/group messages, NPC AI chat, media uploads |
| `/api/emails` | In-character email inbox and compose |
| `/api/premonitions` | Malkavian premonition delivery |
| `/api/dice` | Dice rolls |
| `/api/news` | In-portal news and announcements |
| `/api/hunts` | Hunting scenarios |
| `/api/camarilla` | Camarilla roster |
| `/api/push` | Web push subscription management |
| `/api/health` | Health check |
| `/api/admin/*` | Admin-only variants of all the above |

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env   # then edit with your DB credentials, JWT secret, etc.

# 3. Start the server (tables are created automatically on first use)
npm run dev            # nodemon — auto-restarts on file changes
# or
npm start              # plain node

# 4. Verify
curl http://localhost:3001/api/health

# 5. Browse interactive docs
open http://localhost:3001/api-docs
```

> For full setup instructions, environment variable reference, schema details, and deployment notes, see **[README.dev.md](README.dev.md)**.

---

## Related Resources

- **Developer Guide:** [README.dev.md](README.dev.md) — prerequisites, env vars, schema, scripts, deployment
- **Interactive API Docs:** <https://vtm.back.miketsak.gr/api-docs>
- **Frontend repo:** *(link not yet available)*
- **License:** [LICENSE.txt](LICENSE.txt)
