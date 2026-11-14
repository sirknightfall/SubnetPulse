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

## Authentication & Authorization

All inventory, reporting, CRUD, bulk-import, and scan-control endpoints require authentication (`Bearer` session token, `X-API-Key` header, HTTP Basic credentials, or session cookie).

### Default Credentials (configurable via `.env` or [docker-compose.yml](file:///home/lordknightfall/gemini/SubnetPulse/docker-compose.yml))

| Role | Username | Password | API Key (`X-API-Key`) | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `subnetpulse-admin` | `sp-admin-secret-key-2026` | Full CRUD, bulk import, manual scans, history reset, IP audit updates |
| **Viewer** | `auditor` | `subnetpulse-viewer` | `sp-viewer-readonly-key-2026` | Read-only access to sites, subnets, IP inventory, audit logs, and CSV/JSON exports |

---

## Future Roadmap / Planned Features

### 1. Database-Backed Multi-User Management
- Add a `User` table in SQLite (`id`, `username`, `password_hash`, `role`, `is_active`, `created_at`, `last_login_at`) using salted password hashing (PBKDF2/Argon2/bcrypt).
- Seed the initial administrator account from `ADMIN_USERNAME` / `ADMIN_PASSWORD` on first boot while persisting subsequent user accounts in SQLite.
- Expose admin-only user management endpoints (`GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}`, `DELETE /api/users/{id}`) to create, disable, role-switch (`admin` / `viewer`), or remove accounts.
- Add an **Admin User Management Modal** in the React console so administrators can add/remove users and assign roles directly from the UI.

### 2. Self-Service Password Rotation
- Add `POST /api/auth/change-password` allowing any authenticated user to verify their current password and set a new password.
- Add a **Change Password** modal accessible from the top navigation bar next to the user badge.

### 3. Per-User Scoped API Keys & Actor Attribution
- Allow generating and revoking named API keys per user with optional expiration dates.
- Record the acting `username` on `AuditEventLog` entries (`MANUAL_AUDIT_UPDATE`, manual scan triggers, and history resets) for full operator accountability.
