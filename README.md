# SubnetPulse — Corporate Subnet Audit & IPAM Reconciliation Console

SubnetPulse is a Dockerized FastAPI + React/Tailwind application for scanning corporate IPv4 subnet scopes, tracking IP reachability state transitions over time, and reconciling live ICMP/TCP host discovery against IPAM allocations.

---

## Quick Start

```bash
docker compose up -d --build
```

- **Frontend Console:** `http://localhost:3000`
- **Backend API & Docs:** `http://localhost:8000/docs`

---

## Authentication, Role-Based Access & User Management

All inventory, reporting, CRUD, bulk-import, and scan-control endpoints require authentication (`Bearer` session token, `X-API-Key` header, HTTP Basic credentials, or `HttpOnly` session cookie).

### Initial Seeded Credentials (configurable via `.env` or [docker-compose.yml](file:///home/lordknightfall/gemini/SubnetPulse/docker-compose.yml))

On first boot, SubnetPulse seeds the initial administrator and auditor accounts into SQLite with salted PBKDF2-HMAC-SHA256 password hashes (`260,000` iterations) and SHA-256 API key digests:

| Role | Username | Password | Initial API Key (`X-API-Key`) | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `subnetpulse-admin` | `sp-admin-secret-key-2026` | Full CRUD, bulk import, manual scans, history reset, IP audit updates, user & API key management |
| **Viewer** | `auditor` | `subnetpulse-viewer` | `sp-viewer-readonly-key-2026` | Read-only access to sites, subnets, IP inventory, audit logs, and CSV/JSON exports |

---

## User & Security Features

### 1. Database-Backed Multi-User Management
- **SQLite `User` Store:** Stores operator accounts (`id`, `username`, `password_hash`, `role`, `is_active`, `created_at`, `last_login_at`) in [models.py](file:///home/lordknightfall/gemini/SubnetPulse/backend/models.py).
- **Admin Endpoints:** `GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}`, and `DELETE /api/users/{id}` in [main.py](file:///home/lordknightfall/gemini/SubnetPulse/backend/main.py) with self-lockout safeguards (preventing deletion, deactivation, or demotion of the last active administrator).
- **Admin UI Modal:** Accessible via the **Users** button in the top navigation bar ([App.jsx](file:///home/lordknightfall/gemini/SubnetPulse/frontend/src/App.jsx)) for creating accounts, switching `admin` / `viewer` roles, disabling accounts, resetting passwords, and issuing/revoking per-user API keys.

### 2. Self-Service Password Rotation
- **Endpoint:** `POST /api/auth/change-password` verifies the caller's current password and updates their salted PBKDF2 hash.
- **UI Modal:** Accessible to any authenticated operator via the **Password & Keys** button in the top navigation bar.

### 3. Per-User Scoped API Keys & Actor Attribution
- **Scoped API Keys (`UserAPIKey`):** Operators and administrators can generate and revoke named API keys (`sp_live_...`) with optional expiration windows (`GET /api/auth/api-keys`, `POST /api/auth/api-keys`, `DELETE /api/auth/api-keys/{key_id}`, and `/api/users/{user_id}/api-keys`). Only the SHA-256 hash and key prefix are stored in SQLite.
- **Operator Accountability (`actor_username`):** `AuditEventLog` entries record the acting operator's `username` across manual IP audit updates (`MANUAL_AUDIT_UPDATE`), manual subnet scan triggers (`MANUAL_SCAN_TRIGGER`), and subnet history resets (`HISTORY_RESET`), displayed as `by <username>` badges in the IP Audit History modal.
