import csv
import io
import ipaddress
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, text
from sqlalchemy.orm import Session, joinedload

from auth import (
    AUTH_TOKEN_TTL_SECONDS,
    SESSION_COOKIE_NAME,
    AuthPrincipal,
    authenticate_credentials,
    create_access_token,
    generate_scoped_api_key,
    get_optional_principal,
    hash_password,
    require_admin,
    require_authenticated,
    seed_initial_users,
    verify_password,
)
from database import Base, SessionLocal, engine, get_db
from models import (
    AuditEventLog,
    AuditFlag,
    IPRecord,
    IPStatus,
    ScanStatus,
    Site,
    SubnetScope,
    User,
    UserAPIKey,
    UserRole,
    compute_cidr_bounds,
    utcnow,
)
from scanner import scanner_worker
from schemas import (
    AuditEventLogRead,
    AuthTokenResponse,
    AuthUserRead,
    BulkSubnetImportItem,
    BulkSubnetImportRequest,
    BulkSubnetImportResult,
    ChangePasswordRequest,
    IPRecordDetailRead,
    IPRecordRead,
    IPRecordUpdate,
    LoginRequest,
    OrphanedOrUnusedIPReportItem,
    SiteCreate,
    SiteTreeRead,
    SubnetCreate,
    SubnetSummaryRead,
    SubnetUpdate,
    UserAPIKeyCreate,
    UserAPIKeyCreatedResponse,
    UserAPIKeyRead,
    UserCreate,
    UserRead,
    UserUpdate,
    cidrs_overlap,
)


def ensure_schema_compatibility() -> None:
    """
    Ensures existing SQLite databases created by earlier versions of SubnetPulse
    are migrated in-place (adding network bound columns on `subnets`, relaxing
    `NOT NULL` on `audit_event_logs.new_status`, adding `actor_username`, and
    seeding initial operator accounts).
    """
    Base.metadata.create_all(bind=engine)
    if str(engine.url).startswith("sqlite"):
        with engine.begin() as conn:
            subnet_cols = {
                row[1]: row for row in conn.execute(text("PRAGMA table_info(subnets)")).fetchall()
            }
            if subnet_cols:
                if "network_start_int" not in subnet_cols:
                    conn.execute(
                        text("ALTER TABLE subnets ADD COLUMN network_start_int INTEGER NOT NULL DEFAULT 0")
                    )
                if "broadcast_end_int" not in subnet_cols:
                    conn.execute(
                        text("ALTER TABLE subnets ADD COLUMN broadcast_end_int INTEGER NOT NULL DEFAULT 0")
                    )

                rows = conn.execute(text("SELECT id, cidr FROM subnets")).fetchall()
                for row_id, cidr_val in rows:
                    norm_cidr, start_int, end_int = compute_cidr_bounds(cidr_val)
                    conn.execute(
                        text(
                            "UPDATE subnets SET cidr = :c, network_start_int = :s, broadcast_end_int = :e "
                            "WHERE id = :id"
                        ),
                        {"c": norm_cidr, "s": start_int, "e": end_int, "id": row_id},
                    )

            audit_cols = {
                row[1]: row for row in conn.execute(text("PRAGMA table_info(audit_event_logs)")).fetchall()
            }
            if "new_status" in audit_cols and audit_cols["new_status"][3] == 1:
                # SQLite column `notnull` is 1; rebuild table with nullable `new_status` and `actor_username`
                has_actor = "actor_username" in audit_cols
                actor_select = "actor_username" if has_actor else "NULL"
                conn.execute(
                    text(
                        """
                        CREATE TABLE audit_event_logs_new (
                            id INTEGER NOT NULL PRIMARY KEY,
                            ip_record_id INTEGER NOT NULL REFERENCES ip_records (id) ON DELETE CASCADE,
                            previous_status VARCHAR(7),
                            new_status VARCHAR(7),
                            event_type VARCHAR(64) NOT NULL,
                            actor_username VARCHAR(120),
                            response_time_ms FLOAT,
                            details TEXT,
                            timestamp DATETIME NOT NULL
                        )
                        """
                    )
                )
                conn.execute(
                    text(
                        f"""
                        INSERT INTO audit_event_logs_new (
                            id, ip_record_id, previous_status, new_status,
                            event_type, actor_username, response_time_ms, details, timestamp
                        )
                        SELECT
                            id,
                            ip_record_id,
                            CASE WHEN event_type = 'MANUAL_AUDIT_UPDATE' THEN NULL ELSE previous_status END,
                            CASE WHEN event_type = 'MANUAL_AUDIT_UPDATE' THEN NULL ELSE new_status END,
                            event_type,
                            {actor_select},
                            CASE WHEN event_type = 'MANUAL_AUDIT_UPDATE' THEN NULL ELSE response_time_ms END,
                            details,
                            timestamp
                        FROM audit_event_logs
                        """
                    )
                )
                conn.execute(text("DROP TABLE audit_event_logs"))
                conn.execute(text("ALTER TABLE audit_event_logs_new RENAME TO audit_event_logs"))
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_audit_event_logs_id ON audit_event_logs (id)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_audit_event_logs_ip_record_id "
                        "ON audit_event_logs (ip_record_id)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_audit_event_logs_actor_username "
                        "ON audit_event_logs (actor_username)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_audit_event_logs_timestamp "
                        "ON audit_event_logs (timestamp)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_audit_logs_ip_timestamp "
                        "ON audit_event_logs (ip_record_id, timestamp)"
                    )
                )
            elif audit_cols:
                if "actor_username" not in audit_cols:
                    conn.execute(
                        text("ALTER TABLE audit_event_logs ADD COLUMN actor_username VARCHAR(120)")
                    )
                    conn.execute(
                        text(
                            "CREATE INDEX IF NOT EXISTS ix_audit_event_logs_actor_username "
                            "ON audit_event_logs (actor_username)"
                        )
                    )
                conn.execute(
                    text(
                        "UPDATE audit_event_logs "
                        "SET previous_status = NULL, new_status = NULL, response_time_ms = NULL "
                        "WHERE event_type = 'MANUAL_AUDIT_UPDATE' AND previous_status = new_status"
                    )
                )

    with SessionLocal() as db:
        seed_initial_users(db)


def find_overlapping_subnet(
    db: Session,
    cidr: str,
    exclude_subnet_id: Optional[int] = None,
) -> Optional[SubnetScope]:
    """
    Checks whether `cidr` is identical to or overlaps with any registered SubnetScope.
    Uses both integer boundary comparison and `ipaddress.ip_network.overlaps`.
    """
    normalized_cidr, start_int, end_int = compute_cidr_bounds(cidr)
    candidate_net = ipaddress.ip_network(normalized_cidr, strict=False)

    query = db.query(SubnetScope)
    if exclude_subnet_id is not None:
        query = query.filter(SubnetScope.id != exclude_subnet_id)

    bound_match = query.filter(
        SubnetScope.network_start_int <= end_int,
        SubnetScope.broadcast_end_int >= start_int,
    ).first()
    if bound_match is not None:
        return bound_match

    for existing in query.all():
        existing_net = ipaddress.ip_network(existing.cidr, strict=False)
        if candidate_net.overlaps(existing_net):
            return existing

    return None


def populate_subnet_ip_records(db: Session, subnet: SubnetScope) -> int:
    """
    Expands a subnet's CIDR block using Python's ipaddress module and bulk-inserts
    IPRecord rows for all usable host addresses in the range.
    """
    network = ipaddress.ip_network(subnet.cidr, strict=False)
    hosts = list(network.hosts())
    if not hosts:
        hosts = list(network)

    gateway_str = subnet.gateway_ip.strip() if subnet.gateway_ip else None
    records: List[IPRecord] = []

    for ip_obj in hosts:
        ip_str = str(ip_obj)
        is_gateway = gateway_str == ip_str
        records.append(
            IPRecord(
                subnet_id=subnet.id,
                ip_address=ip_str,
                ip_integer=int(ip_obj),
                hostname="gateway" if is_gateway else None,
                status=IPStatus.UNKNOWN,
                ipam_allocated=is_gateway,
                ipam_owner="Network Infrastructure" if is_gateway else None,
                audit_flag=AuditFlag.RESERVED_IPAM if is_gateway else AuditFlag.NONE,
                audit_notes="Default subnet gateway" if is_gateway else None,
            )
        )

    db.bulk_save_objects(records)
    subnet.total_hosts = len(records)
    subnet.unknown_count = len(records)
    subnet.online_count = 0
    subnet.offline_count = 0
    subnet.suspected_unused_count = 0
    db.commit()
    db.refresh(subnet)
    return len(records)


def seed_initial_corporate_data(db: Session) -> None:
    """
    Seeds initial corporate sites and subnets on first boot if the database is empty
    so the UI immediately showcases realistic enterprise data.
    """
    existing_site = db.query(Site).first()
    if existing_site is not None:
        return

    birmingham = Site(
        name="Birmingham Office",
        description="UK Midlands Corporate Headquarters & Core Server Facility",
    )
    london = Site(
        name="London Edge DC",
        description="Primary Production Workload & DMZ Interconnect",
    )
    manchester = Site(
        name="Manchester Branch",
        description="Regional Operations & VoIP Campus Network",
    )
    db.add_all([birmingham, london, manchester])
    db.commit()
    db.refresh(birmingham)
    db.refresh(london)
    db.refresh(manchester)

    seed_subnets = [
        SubnetScope(
            site_id=birmingham.id,
            cidr="10.50.20.0/28",
            label="Birmingham Office - Server VLAN",
            vlan_id=20,
            gateway_ip="10.50.20.1",
            scan_enabled=False,
            scan_interval_minutes=24 * 60,
            scan_cron_time="02:00",
        ),
        SubnetScope(
            site_id=birmingham.id,
            cidr="10.50.30.0/28",
            label="Birmingham Office - Corporate Printers & IoT",
            vlan_id=30,
            gateway_ip="10.50.30.1",
            scan_enabled=False,
            scan_interval_minutes=24 * 60,
        ),
        SubnetScope(
            site_id=london.id,
            cidr="172.16.100.0/28",
            label="London DC - Core Infrastructure Management",
            vlan_id=100,
            gateway_ip="172.16.100.1",
            scan_enabled=False,
            scan_interval_minutes=12 * 60,
            scan_cron_time="04:30",
        ),
        SubnetScope(
            site_id=manchester.id,
            cidr="192.168.88.0/28",
            label="Manchester Branch - Legacy Workstation Scope",
            vlan_id=88,
            gateway_ip="192.168.88.1",
            scan_enabled=False,
            scan_interval_minutes=24 * 60,
        ),
    ]

    for subnet in seed_subnets:
        db.add(subnet)
        db.commit()
        db.refresh(subnet)
        populate_subnet_ip_records(db, subnet)

    # Enrich the first seeded subnet (10.50.20.0/28) with realistic corporate IPAM & audit history
    primary_subnet = db.query(SubnetScope).filter(SubnetScope.cidr == "10.50.20.0/28").first()
    if primary_subnet:
        now = datetime.now(timezone.utc)
        ips = (
            db.query(IPRecord)
            .filter(IPRecord.subnet_id == primary_subnet.id)
            .order_by(IPRecord.ip_integer.asc())
            .all()
        )
        sample_profiles = {
            "10.50.20.1": ("gw-bhx-vlan20.corp.local", IPStatus.ONLINE, 0.84, True, "NetOps Core", AuditFlag.RESERVED_IPAM, "Core L3 SVI Gateway", 0),
            "10.50.20.2": ("dc01-bhx.corp.local", IPStatus.ONLINE, 1.12, True, "Identity & AD Team", AuditFlag.VERIFIED, "Primary Domain Controller", 0),
            "10.50.20.3": ("dc02-bhx.corp.local", IPStatus.ONLINE, 1.35, True, "Identity & AD Team", AuditFlag.VERIFIED, "Secondary Domain Controller", 0),
            "10.50.20.4": ("sql-erp-prod.corp.local", IPStatus.ONLINE, 2.05, True, "ERP Platform", AuditFlag.VERIFIED, "Production SQL Node", 0),
            "10.50.20.5": ("legacy-print-srv.corp.local", IPStatus.OFFLINE, None, True, "Workplace IT", AuditFlag.SUSPECTED_UNUSED, "Allocated in IPAM but offline for 5 sweeps - candidate for reclamation", 5),
            "10.50.20.6": ("decomm-app01.corp.local", IPStatus.ONLINE, 4.72, False, "Decommissioned (CHG-4092)", AuditFlag.GHOST_DEVICE, "Expected decommissioned in Q3 but still responding to ICMP", 0),
            "10.50.20.7": ("backup-nas01.corp.local", IPStatus.ONLINE, 1.90, True, "Storage Ops", AuditFlag.VERIFIED, "Veeam Repository Appliance", 0),
            "10.50.20.8": ("old-stage-vm.corp.local", IPStatus.OFFLINE, None, True, "DevOps Staging", AuditFlag.EXPECTED_DECOMMISSIONED, "VM powered down; awaiting DNS/IPAM cleanup", 4),
            "10.50.20.9": (None, IPStatus.ONLINE, 3.41, False, None, AuditFlag.GHOST_DEVICE, "Unallocated IP responding to ping - investigate rogue host", 0),
        }
        online_c = 0
        offline_c = 0
        unused_c = 0
        for rec in ips:
            rec.last_checked_at = now
            if rec.ip_address in sample_profiles:
                host, st, rtt, alloc, owner, flag, notes, off_scans = sample_profiles[rec.ip_address]
                rec.hostname = host
                rec.status = st
                rec.response_time_ms = rtt
                rec.ipam_allocated = alloc
                rec.ipam_owner = owner
                rec.audit_flag = flag
                rec.audit_notes = notes
                rec.consecutive_offline_scans = off_scans
                rec.state_change_count = 2 if off_scans > 0 else 1
                rec.first_seen_online_at = now
                if st == IPStatus.ONLINE:
                    rec.last_seen_online_at = now
                    online_c += 1
                else:
                    offline_c += 1
                db.add(
                    AuditEventLog(
                        ip_record_id=rec.id,
                        previous_status=IPStatus.UNKNOWN,
                        new_status=IPStatus.ONLINE,
                        event_type="STATE_TRANSITION",
                        response_time_ms=rtt or 1.45,
                        details="Initial discovery sweep: host responded to ICMP echo",
                        timestamp=now,
                    )
                )
                if st == IPStatus.OFFLINE:
                    db.add(
                        AuditEventLog(
                            ip_record_id=rec.id,
                            previous_status=IPStatus.ONLINE,
                            new_status=IPStatus.OFFLINE,
                            event_type="STATE_TRANSITION",
                            response_time_ms=None,
                            details=f"State transitioned from Online to Offline ({off_scans} consecutive failed sweeps)",
                            timestamp=now,
                        )
                    )
            else:
                rec.status = IPStatus.OFFLINE
                rec.consecutive_offline_scans = 1
                offline_c += 1

            if rec.first_seen_online_at is None and rec.status == IPStatus.OFFLINE:
                unused_c += 1

        primary_subnet.online_count = online_c
        primary_subnet.offline_count = offline_c
        primary_subnet.unknown_count = 0
        primary_subnet.suspected_unused_count = unused_c
        primary_subnet.scan_status = ScanStatus.COMPLETED
        primary_subnet.last_scanned_at = now
        primary_subnet.last_scan_duration_ms = 340
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_schema_compatibility()
    with SessionLocal() as db:
        seed_initial_corporate_data(db)
    await scanner_worker.start()
    try:
        yield
    finally:
        await scanner_worker.stop()


app = FastAPI(
    title="SubnetPulse - Corporate Subnet Audit & IPAM Reconciliation API",
    description="Asynchronous corporate subnet scanner, IP state transition logger, and IPAM reconciliation backend.",
    version="1.0.0",
    lifespan=lifespan,
)

cors_origins_env = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173",
)
allowed_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
allow_all_origins = allowed_origins == ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=not allow_all_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# Authentication, Self-Service & User Management Endpoints
# ==========================================
@app.post("/api/auth/login", response_model=AuthTokenResponse)
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    principal = authenticate_credentials(
        username=payload.username,
        password=payload.password,
        api_key=payload.api_key,
        db=db,
    )
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username, password, or API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        principal.username,
        principal.role,
        user_id=principal.user_id,
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=AUTH_TOKEN_TTL_SECONDS,
        httponly=True,
        samesite="lax",
    )
    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user_id=principal.user_id,
        username=principal.username,
        role=principal.role.value,
        expires_in=AUTH_TOKEN_TTL_SECONDS,
    )


@app.get("/api/auth/me", response_model=AuthUserRead)
def get_current_user(principal: AuthPrincipal = Depends(require_authenticated)):
    return AuthUserRead(
        user_id=principal.user_id,
        username=principal.username,
        role=principal.role.value,
        authenticated=True,
    )


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return {"status": "logged_out"}


@app.post("/api/auth/change-password")
def change_own_password(
    payload: ChangePasswordRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_authenticated),
):
    user = db.query(User).filter(User.username.ilike(principal.username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    user.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"status": "password_updated", "username": user.username}


def _create_api_key_for_user(
    db: Session,
    user: User,
    payload: UserAPIKeyCreate,
) -> UserAPIKeyCreatedResponse:
    raw_key, key_prefix, key_hash = generate_scoped_api_key()
    expires_at = payload.expires_at
    if expires_at is None and payload.expires_in_days is not None:
        expires_at = utcnow() + timedelta(days=payload.expires_in_days)
    elif expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    key_row = UserAPIKey(
        user_id=user.id,
        name=payload.name.strip(),
        key_prefix=key_prefix,
        key_hash=key_hash,
        is_active=True,
        expires_at=expires_at,
    )
    db.add(key_row)
    db.commit()
    db.refresh(key_row)

    return UserAPIKeyCreatedResponse(
        id=key_row.id,
        user_id=key_row.user_id,
        name=key_row.name,
        key_prefix=key_row.key_prefix,
        is_active=key_row.is_active,
        expires_at=key_row.expires_at,
        last_used_at=key_row.last_used_at,
        created_at=key_row.created_at,
        api_key=raw_key,
    )


@app.get("/api/auth/api-keys", response_model=List[UserAPIKeyRead])
def list_own_api_keys(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_authenticated),
):
    user = db.query(User).filter(User.username.ilike(principal.username)).first()
    if not user:
        return []
    return (
        db.query(UserAPIKey)
        .filter(UserAPIKey.user_id == user.id)
        .order_by(UserAPIKey.created_at.desc())
        .all()
    )


@app.post("/api/auth/api-keys", response_model=UserAPIKeyCreatedResponse, status_code=201)
def create_own_api_key(
    payload: UserAPIKeyCreate,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_authenticated),
):
    user = db.query(User).filter(User.username.ilike(principal.username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")
    return _create_api_key_for_user(db, user, payload)


@app.delete("/api/auth/api-keys/{key_id}", status_code=204)
def revoke_own_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_authenticated),
):
    user = db.query(User).filter(User.username.ilike(principal.username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    key_row = db.query(UserAPIKey).filter(UserAPIKey.id == key_id).first()
    if not key_row or (key_row.user_id != user.id and principal.role != UserRole.ADMIN):
        raise HTTPException(status_code=404, detail="API key not found.")

    db.delete(key_row)
    db.commit()
    return None


@app.get("/api/users", response_model=List[UserRead])
def list_users(
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    return (
        db.query(User)
        .options(joinedload(User.api_keys))
        .order_by(User.id.asc())
        .all()
    )


@app.post("/api/users", response_model=UserRead, status_code=201)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    username_clean = payload.username.strip()
    existing = db.query(User).filter(User.username.ilike(username_clean)).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"User '{username_clean}' already exists.",
        )

    user = User(
        username=username_clean,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.patch("/api/users/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    user = (
        db.query(User)
        .options(joinedload(User.api_keys))
        .filter(User.id == user_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    update_data = payload.model_dump(exclude_unset=True)
    new_role = update_data.get("role", user.role)
    new_active = update_data.get("is_active", user.is_active)

    # Prevent an admin from deactivating or demoting their own active session
    if user.username.lower() == admin.username.lower():
        if not new_active:
            raise HTTPException(
                status_code=400,
                detail="You cannot disable your own active administrator account.",
            )
        if new_role != UserRole.ADMIN:
            raise HTTPException(
                status_code=400,
                detail="You cannot demote your own active administrator account.",
            )

    # Prevent removing or disabling the last active admin
    if user.role == UserRole.ADMIN and user.is_active and (
        new_role != UserRole.ADMIN or not new_active
    ):
        other_active_admins = (
            db.query(User)
            .filter(
                User.id != user.id,
                User.role == UserRole.ADMIN,
                User.is_active.is_(True),
            )
            .count()
        )
        if other_active_admins == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote or disable the last active administrator account.",
            )

    if "role" in update_data and update_data["role"] is not None:
        user.role = update_data["role"]
    if "is_active" in update_data and update_data["is_active"] is not None:
        user.is_active = update_data["is_active"]
    if "password" in update_data and update_data["password"]:
        user.password_hash = hash_password(update_data["password"])

    db.commit()
    db.refresh(user)
    return user


@app.delete("/api/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.username.lower() == admin.username.lower():
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own active administrator account.",
        )

    if user.role == UserRole.ADMIN and user.is_active:
        other_active_admins = (
            db.query(User)
            .filter(
                User.id != user.id,
                User.role == UserRole.ADMIN,
                User.is_active.is_(True),
            )
            .count()
        )
        if other_active_admins == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last active administrator account.",
            )

    db.delete(user)
    db.commit()
    return None


@app.get("/api/users/{user_id}/api-keys", response_model=List[UserAPIKeyRead])
def list_user_api_keys(
    user_id: int,
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return (
        db.query(UserAPIKey)
        .filter(UserAPIKey.user_id == user.id)
        .order_by(UserAPIKey.created_at.desc())
        .all()
    )


@app.post(
    "/api/users/{user_id}/api-keys",
    response_model=UserAPIKeyCreatedResponse,
    status_code=201,
)
def create_user_api_key(
    user_id: int,
    payload: UserAPIKeyCreate,
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return _create_api_key_for_user(db, user, payload)


@app.delete("/api/users/{user_id}/api-keys/{key_id}", status_code=204)
def revoke_user_api_key(
    user_id: int,
    key_id: int,
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    key_row = (
        db.query(UserAPIKey)
        .filter(UserAPIKey.id == key_id, UserAPIKey.user_id == user_id)
        .first()
    )
    if not key_row:
        raise HTTPException(status_code=404, detail="API key not found for this user.")
    db.delete(key_row)
    db.commit()
    return None


# ==========================================
# Health & Navigation Tree Endpoints
# ==========================================
@app.get("/api/health")
async def health_check(principal: Optional[AuthPrincipal] = Depends(get_optional_principal)):
    payload = {
        "status": "healthy",
        "scanner_running": scanner_worker.is_running,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if principal is not None:
        payload["active_scans"] = list(scanner_worker.active_subnet_scans)
    return payload


@app.get("/api/tree", response_model=List[SiteTreeRead])
def get_navigation_tree(
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    """
    Returns the complete hierarchy of Sites and their nested Subnets with real-time
    utilization metrics for the persistent left-hand navigation tree.
    """
    sites = (
        db.query(Site)
        .options(joinedload(Site.subnets))
        .order_by(Site.name.asc())
        .all()
    )
    return sites


# ==========================================
# Site / Location CRUD Endpoints
# ==========================================
@app.get("/api/sites", response_model=List[SiteTreeRead])
def list_sites(
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    return (
        db.query(Site)
        .options(joinedload(Site.subnets))
        .order_by(Site.name.asc())
        .all()
    )


@app.post("/api/sites", response_model=SiteTreeRead, status_code=201)
def create_site(
    payload: SiteCreate,
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    existing = db.query(Site).filter(Site.name.ilike(payload.name.strip())).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Site '{payload.name}' already exists.")

    site = Site(
        name=payload.name.strip(),
        description=payload.description.strip() if payload.description else None,
    )
    db.add(site)
    db.commit()
    db.refresh(site)
    return site


@app.delete("/api/sites/{site_id}", status_code=204)
def delete_site(
    site_id: int,
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    site = db.query(Site).filter(Site.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found.")
    for sub in site.subnets:
        scanner_worker.reset_subnet_state(sub.id)
    db.delete(site)
    db.commit()
    return None


# ==========================================
# Subnet Scope CRUD & Manual Scan Endpoints
# ==========================================
@app.get("/api/subnets", response_model=List[SubnetSummaryRead])
def list_subnets(
    site_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    query = db.query(SubnetScope)
    if site_id is not None:
        query = query.filter(SubnetScope.site_id == site_id)
    return query.order_by(SubnetScope.cidr.asc()).all()


@app.get("/api/subnets/{subnet_id}", response_model=SubnetSummaryRead)
def get_subnet(
    subnet_id: int,
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")
    return subnet


@app.post("/api/subnets", response_model=SubnetSummaryRead, status_code=201)
async def create_subnet(
    payload: SubnetCreate,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    site = db.query(Site).filter(Site.id == payload.site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail=f"Site ID {payload.site_id} does not exist.")

    overlapping = find_overlapping_subnet(db, payload.cidr)
    if overlapping is not None:
        if overlapping.cidr == payload.cidr:
            raise HTTPException(
                status_code=409,
                detail=f"Subnet CIDR '{payload.cidr}' is already registered.",
            )
        raise HTTPException(
            status_code=409,
            detail=(
                f"Subnet CIDR '{payload.cidr}' overlaps with existing subnet "
                f"'{overlapping.cidr}' ({overlapping.label})."
            ),
        )

    subnet = SubnetScope(
        site_id=payload.site_id,
        cidr=payload.cidr,
        label=payload.label.strip(),
        vlan_id=payload.vlan_id,
        gateway_ip=payload.gateway_ip.strip() if payload.gateway_ip else None,
        scan_enabled=payload.scan_enabled,
        scan_interval_minutes=payload.scan_interval_hours * 60,
        scan_cron_time=payload.scan_cron_time,
        scan_status=ScanStatus.IDLE,
    )
    db.add(subnet)
    db.commit()
    db.refresh(subnet)

    populate_subnet_ip_records(db, subnet)
    scanner_worker.schedule_immediate_scan(subnet.id, actor_username=admin.username)
    return subnet


@app.patch("/api/subnets/{subnet_id}", response_model=SubnetSummaryRead)
def update_subnet(
    subnet_id: int,
    payload: SubnetUpdate,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")

    update_data = payload.model_dump(exclude_unset=True)
    if "gateway_ip" in update_data:
        gw_val = update_data["gateway_ip"]
        if gw_val and gw_val.strip():
            try:
                gw_ip = ipaddress.ip_address(gw_val.strip())
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=f"Invalid gateway IP '{gw_val}': {exc}") from exc
            net = ipaddress.ip_network(subnet.cidr, strict=False)
            if gw_ip not in net:
                raise HTTPException(
                    status_code=422,
                    detail=f"Gateway IP '{gw_val}' does not belong to subnet CIDR '{subnet.cidr}'.",
                )
            update_data["gateway_ip"] = str(gw_ip)
        else:
            update_data["gateway_ip"] = None

    if "scan_interval_hours" in update_data:
        hours_val = update_data.pop("scan_interval_hours")
        if hours_val is not None:
            subnet.scan_interval_minutes = int(hours_val) * 60
    for field, value in update_data.items():
        setattr(subnet, field, value)

    db.commit()
    db.refresh(subnet)

    if subnet.scan_enabled and subnet.last_scanned_at is None:
        scanner_worker.schedule_immediate_scan(subnet.id, actor_username=admin.username)

    return subnet


@app.delete("/api/subnets/{subnet_id}", status_code=204)
def delete_subnet(
    subnet_id: int,
    db: Session = Depends(get_db),
    _admin: AuthPrincipal = Depends(require_admin),
):
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")
    scanner_worker.reset_subnet_state(subnet_id)
    db.delete(subnet)
    db.commit()
    return None


def _select_subnet_anchor_ip(db: Session, subnet: SubnetScope) -> Optional[IPRecord]:
    """
    Returns the gateway IPRecord (or first IPRecord in the subnet) for attaching
    subnet-level operator audit events (manual scan triggers and history resets).
    """
    if subnet.gateway_ip:
        gw_rec = (
            db.query(IPRecord)
            .filter(
                IPRecord.subnet_id == subnet.id,
                IPRecord.ip_address == subnet.gateway_ip,
            )
            .first()
        )
        if gw_rec is not None:
            return gw_rec
    return (
        db.query(IPRecord)
        .filter(IPRecord.subnet_id == subnet.id)
        .order_by(IPRecord.ip_integer.asc())
        .first()
    )


@app.post("/api/subnets/{subnet_id}/scan", response_model=SubnetSummaryRead)
async def trigger_manual_subnet_scan(
    subnet_id: int,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    """
    Immediate 'Rescan Now' endpoint at the subnet level. Launches an asynchronous
    non-blocking sweep of the subnet's IP range and logs operator attribution.
    """
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")

    anchor_ip = _select_subnet_anchor_ip(db, subnet)
    if anchor_ip is not None:
        db.add(
            AuditEventLog(
                ip_record_id=anchor_ip.id,
                previous_status=None,
                new_status=None,
                event_type="MANUAL_SCAN_TRIGGER",
                actor_username=admin.username,
                response_time_ms=None,
                details=f"Manual subnet sweep triggered for {subnet.cidr} by {admin.username}",
            )
        )

    if subnet.id not in scanner_worker.active_subnet_scans:
        subnet.scan_status = ScanStatus.SCANNING
        db.commit()
        db.refresh(subnet)
        scanner_worker.schedule_immediate_scan(subnet.id, actor_username=admin.username)
    else:
        db.commit()
        db.refresh(subnet)

    return subnet


@app.delete("/api/subnets/{subnet_id}/history", response_model=SubnetSummaryRead)
def clear_subnet_history(
    subnet_id: int,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    """
    Clears all state transition / audit event logs for every IP record in the subnet,
    resets historical timestamps and sweep counters, and records operator attribution.
    """
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")

    ip_records = (
        db.query(IPRecord)
        .filter(IPRecord.subnet_id == subnet_id)
        .order_by(IPRecord.ip_integer.asc())
        .all()
    )
    ip_ids = [rec.id for rec in ip_records]

    if ip_ids:
        db.query(AuditEventLog).filter(AuditEventLog.ip_record_id.in_(ip_ids)).delete(
            synchronize_session=False
        )

    for rec in ip_records:
        rec.status = IPStatus.UNKNOWN
        rec.response_time_ms = None
        rec.first_seen_online_at = None
        rec.last_seen_online_at = None
        rec.last_checked_at = None
        rec.consecutive_offline_scans = 0
        rec.state_change_count = 0

    anchor_ip = _select_subnet_anchor_ip(db, subnet)
    if anchor_ip is not None:
        db.add(
            AuditEventLog(
                ip_record_id=anchor_ip.id,
                previous_status=None,
                new_status=None,
                event_type="HISTORY_RESET",
                actor_username=admin.username,
                response_time_ms=None,
                details=f"Subnet scan and audit history cleared for {subnet.cidr} by {admin.username}",
            )
        )

    subnet.online_count = 0
    subnet.offline_count = 0
    subnet.unknown_count = len(ip_records)
    subnet.last_scanned_at = None
    subnet.last_scan_duration_ms = None
    subnet.scan_status = ScanStatus.IDLE
    subnet.suspected_unused_count = 0

    scanner_worker.reset_subnet_state(subnet_id)

    db.commit()
    db.refresh(subnet)
    return subnet


# ==========================================
# Bulk Subnet Import (JSON & CSV)
# ==========================================
def _execute_bulk_import(
    items: List[BulkSubnetImportItem],
    trigger_initial_scan: bool,
    db: Session,
    actor_username: Optional[str] = None,
) -> BulkSubnetImportResult:
    # 1. Pre-flight validation for intra-batch and database CIDR overlap before mutating state
    accepted_batch_cidrs: List[tuple[str, str]] = []
    for item in items:
        for prev_cidr, prev_label in accepted_batch_cidrs:
            if cidrs_overlap(item.cidr, prev_cidr) and item.cidr != prev_cidr:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Overlapping CIDR blocks in import batch: '{item.cidr}' ({item.label}) "
                        f"overlaps with '{prev_cidr}' ({prev_label})."
                    ),
                )
        overlapping_db = find_overlapping_subnet(db, item.cidr)
        if overlapping_db is not None and overlapping_db.cidr != item.cidr:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Subnet CIDR '{item.cidr}' overlaps with existing subnet "
                    f"'{overlapping_db.cidr}' ({overlapping_db.label})."
                ),
            )
        accepted_batch_cidrs.append((item.cidr, item.label))

    created_sites = 0
    created_subnets = 0
    skipped_cidrs: List[str] = []
    imported_subnet_ids: List[int] = []

    for item in items:
        site_name_clean = item.site_name.strip()
        site = db.query(Site).filter(Site.name.ilike(site_name_clean)).first()
        if not site:
            site = Site(name=site_name_clean)
            db.add(site)
            db.commit()
            db.refresh(site)
            created_sites += 1

        overlapping = find_overlapping_subnet(db, item.cidr)
        if overlapping is not None:
            if overlapping.cidr == item.cidr:
                skipped_cidrs.append(item.cidr)
                continue
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Subnet CIDR '{item.cidr}' overlaps with existing subnet "
                    f"'{overlapping.cidr}' ({overlapping.label})."
                ),
            )

        new_subnet = SubnetScope(
            site_id=site.id,
            cidr=item.cidr,
            label=item.label.strip(),
            vlan_id=item.vlan_id,
            gateway_ip=item.gateway_ip.strip() if item.gateway_ip else None,
            scan_enabled=item.scan_enabled,
            scan_interval_minutes=item.scan_interval_hours * 60,
            scan_cron_time=item.scan_cron_time,
            scan_status=ScanStatus.IDLE,
        )
        db.add(new_subnet)
        db.commit()
        db.refresh(new_subnet)

        populate_subnet_ip_records(db, new_subnet)
        created_subnets += 1
        imported_subnet_ids.append(new_subnet.id)

        if trigger_initial_scan:
            scanner_worker.schedule_immediate_scan(new_subnet.id, actor_username=actor_username)

    return BulkSubnetImportResult(
        created_sites=created_sites,
        created_subnets=created_subnets,
        skipped_existing_cidrs=skipped_cidrs,
        imported_subnet_ids=imported_subnet_ids,
    )


@app.post("/api/subnets/bulk-import", response_model=BulkSubnetImportResult, status_code=201)
async def bulk_import_subnets_json(
    payload: BulkSubnetImportRequest,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    """
    Bulk-imports sites, subnet CIDR scopes, and scan intervals from structured JSON.
    """
    if not payload.subnets:
        raise HTTPException(status_code=400, detail="No subnet entries provided for import.")
    return _execute_bulk_import(
        payload.subnets,
        payload.trigger_initial_scan,
        db,
        actor_username=admin.username,
    )


@app.post("/api/subnets/bulk-import-csv", response_model=BulkSubnetImportResult, status_code=201)
async def bulk_import_subnets_csv(
    file: UploadFile = File(...),
    trigger_initial_scan: bool = Query(False),
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    """
    Bulk-imports subnets from an uploaded CSV file with columns:
    site_name,cidr,label,vlan_id,gateway_ip,scan_interval_hours,scan_cron_time
    """
    raw_bytes = await file.read()
    try:
        decoded = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV file must be UTF-8 encoded.") from exc

    reader = csv.DictReader(io.StringIO(decoded))
    items: List[BulkSubnetImportItem] = []

    try:
        for row_num, row in enumerate(reader, start=2):
            if not row or not (row.get("cidr") and row.get("site_name")):
                continue
            vlan_raw = (row.get("vlan_id") or "").strip()
            interval_raw = (row.get("scan_interval_hours") or "24").strip()
            scan_enabled_raw = str(row.get("scan_enabled", "false")).strip().lower()
            items.append(
                BulkSubnetImportItem(
                    site_name=row["site_name"].strip(),
                    cidr=row["cidr"].strip(),
                    label=(row.get("label") or row["cidr"]).strip(),
                    vlan_id=int(vlan_raw) if vlan_raw.isdigit() else None,
                    gateway_ip=(row.get("gateway_ip") or "").strip() or None,
                    scan_enabled=scan_enabled_raw in ("true", "1", "yes"),
                    scan_interval_hours=int(interval_raw) if interval_raw.isdigit() else 24,
                    scan_cron_time=(row.get("scan_cron_time") or "").strip() or None,
                )
            )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"CSV validation error: {exc}") from exc

    if not items:
        raise HTTPException(
            status_code=400,
            detail="No valid subnet rows found in CSV. Required columns: site_name, cidr, label.",
        )

    return _execute_bulk_import(items, trigger_initial_scan, db, actor_username=admin.username)


# ==========================================
# IP Inventory & Audit Trail Endpoints
# ==========================================
@app.get("/api/subnets/{subnet_id}/ips", response_model=List[IPRecordRead])
def list_subnet_ips(
    subnet_id: int,
    status: Optional[IPStatus] = Query(None),
    audit_flag: Optional[AuditFlag] = Query(None),
    q: Optional[str] = Query(None, description="Search filter for IP, hostname, owner, or notes"),
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")

    query = db.query(IPRecord).filter(IPRecord.subnet_id == subnet_id)
    if status is not None:
        query = query.filter(IPRecord.status == status)
    if audit_flag is not None:
        query = query.filter(IPRecord.audit_flag == audit_flag)
    if q and q.strip():
        pattern = f"%{q.strip()}%"
        query = query.filter(
            or_(
                IPRecord.ip_address.ilike(pattern),
                IPRecord.hostname.ilike(pattern),
                IPRecord.ipam_owner.ilike(pattern),
                IPRecord.audit_notes.ilike(pattern),
            )
        )

    return query.order_by(IPRecord.ip_integer.asc()).all()


@app.get("/api/ips/{ip_id}", response_model=IPRecordDetailRead)
def get_ip_record_detail(
    ip_id: int,
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    ip_record = (
        db.query(IPRecord)
        .options(joinedload(IPRecord.audit_logs))
        .filter(IPRecord.id == ip_id)
        .first()
    )
    if not ip_record:
        raise HTTPException(status_code=404, detail="IP record not found.")
    return ip_record


@app.patch("/api/ips/{ip_id}", response_model=IPRecordDetailRead)
def update_ip_record_audit(
    ip_id: int,
    payload: IPRecordUpdate,
    db: Session = Depends(get_db),
    admin: AuthPrincipal = Depends(require_admin),
):
    ip_record = (
        db.query(IPRecord)
        .options(joinedload(IPRecord.audit_logs))
        .filter(IPRecord.id == ip_id)
        .first()
    )
    if not ip_record:
        raise HTTPException(status_code=404, detail="IP record not found.")

    changes: List[str] = []
    update_data = payload.model_dump(exclude_unset=True)

    if "audit_flag" in update_data and update_data["audit_flag"] != ip_record.audit_flag:
        changes.append(f"Audit flag changed from '{ip_record.audit_flag.value}' to '{update_data['audit_flag'].value}'")
    if "audit_notes" in update_data and update_data["audit_notes"] != ip_record.audit_notes:
        changes.append("Audit notes updated")
    if "ipam_allocated" in update_data and update_data["ipam_allocated"] != ip_record.ipam_allocated:
        state_label = "Allocated" if update_data["ipam_allocated"] else "Unallocated"
        changes.append(f"IPAM status marked as {state_label}")
    if "ipam_owner" in update_data and update_data["ipam_owner"] != ip_record.ipam_owner:
        changes.append(f"IPAM owner set to '{update_data['ipam_owner'] or 'Unassigned'}'")
    if "hostname" in update_data and update_data["hostname"] != ip_record.hostname:
        changes.append(f"Hostname set to '{update_data['hostname'] or 'None'}'")

    for field, value in update_data.items():
        setattr(ip_record, field, value)

    if changes:
        # Manual metadata updates do not transition host reachability status;
        # leave previous_status and new_status unset so the audit log only
        # reflects status transitions when reachability actually changes.
        audit_entry = AuditEventLog(
            ip_record_id=ip_record.id,
            previous_status=None,
            new_status=None,
            event_type="MANUAL_AUDIT_UPDATE",
            actor_username=admin.username,
            response_time_ms=None,
            details="; ".join(changes),
        )
        db.add(audit_entry)

    db.commit()

    # Recompute suspected_unused_count on parent subnet (hosts that have never responded to ping)
    subnet = db.query(SubnetScope).filter(SubnetScope.id == ip_record.subnet_id).first()
    if subnet:
        unused_cnt = (
            db.query(IPRecord)
            .filter(
                IPRecord.subnet_id == subnet.id,
                IPRecord.first_seen_online_at.is_(None),
                IPRecord.status == IPStatus.OFFLINE,
            )
            .count()
        )
        subnet.suspected_unused_count = unused_cnt
        db.commit()

    db.refresh(ip_record)
    return ip_record


@app.get("/api/ips/{ip_id}/logs", response_model=List[AuditEventLogRead])
def get_ip_audit_logs(
    ip_id: int,
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    ip_record = db.query(IPRecord).filter(IPRecord.id == ip_id).first()
    if not ip_record:
        raise HTTPException(status_code=404, detail="IP record not found.")
    return (
        db.query(AuditEventLog)
        .filter(AuditEventLog.ip_record_id == ip_id)
        .order_by(AuditEventLog.timestamp.desc())
        .all()
    )


# ==========================================
# Suspected Unused & Orphaned IP Reporting
# ==========================================
def _compile_unused_and_orphaned_ips(
    db: Session,
    site_id: Optional[int] = None,
    subnet_id: Optional[int] = None,
) -> List[OrphanedOrUnusedIPReportItem]:
    """
    Returns only IP records that have NEVER responded to a ping
    (first_seen_online_at is None and status != Online), scoped to the requested subnet.
    """
    query = (
        db.query(IPRecord, SubnetScope, Site)
        .join(SubnetScope, IPRecord.subnet_id == SubnetScope.id)
        .join(Site, SubnetScope.site_id == Site.id)
        .filter(
            IPRecord.first_seen_online_at.is_(None),
            IPRecord.status != IPStatus.ONLINE,
        )
    )

    if site_id is not None:
        query = query.filter(Site.id == site_id)
    if subnet_id is not None:
        query = query.filter(SubnetScope.id == subnet_id)

    rows = query.order_by(Site.name.asc(), SubnetScope.cidr.asc(), IPRecord.ip_integer.asc()).all()
    report_items: List[OrphanedOrUnusedIPReportItem] = []

    for ip_rec, subnet, site in rows:
        if ip_rec.consecutive_offline_scans > 0:
            reason = f"Never responded to ping ({ip_rec.consecutive_offline_scans} sweep(s) completed)"
        else:
            reason = "Never responded to ping (awaiting initial sweep)"

        report_items.append(
            OrphanedOrUnusedIPReportItem(
                ip_id=ip_rec.id,
                ip_address=ip_rec.ip_address,
                hostname=ip_rec.hostname,
                status=ip_rec.status,
                subnet_id=subnet.id,
                subnet_cidr=subnet.cidr,
                subnet_label=subnet.label,
                site_name=site.name,
                first_seen_online_at=ip_rec.first_seen_online_at,
                last_seen_online_at=ip_rec.last_seen_online_at,
                consecutive_offline_scans=ip_rec.consecutive_offline_scans,
                ipam_allocated=ip_rec.ipam_allocated,
                ipam_owner=ip_rec.ipam_owner,
                audit_flag=ip_rec.audit_flag,
                audit_notes=ip_rec.audit_notes,
                classification_reason=reason,
            )
        )

    return report_items


@app.get("/api/reports/unused-ips", response_model=List[OrphanedOrUnusedIPReportItem])
def get_unused_ip_report(
    site_id: Optional[int] = Query(None),
    subnet_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    """
    Compiles a cross-subnet audit report of suspected unused, stale, or orphaned IPs
    for IPAM reconciliation.
    """
    return _compile_unused_and_orphaned_ips(db, site_id=site_id, subnet_id=subnet_id)


@app.get("/api/reports/unused-ips/export")
def export_unused_ip_report(
    format: str = Query("csv", pattern="^(csv|json)$"),
    site_id: Optional[int] = Query(None),
    subnet_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    _principal: AuthPrincipal = Depends(require_authenticated),
):
    """
    Exports the suspected unused / orphaned IP audit report as downloadable CSV or JSON.
    """
    items = _compile_unused_and_orphaned_ips(db, site_id=site_id, subnet_id=subnet_id)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if format.lower() == "json":
        payload = [item.model_dump(mode="json") for item in items]
        json_bytes = json.dumps(payload, indent=2).encode("utf-8")
        return StreamingResponse(
            io.BytesIO(json_bytes),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="subnetpulse_audit_{timestamp_str}.json"'
            },
        )

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(
        [
            "Site Name",
            "Subnet CIDR",
            "Subnet Label",
            "IP Address",
            "Hostname",
            "Current Status",
            "IPAM Allocated",
            "IPAM Owner",
            "Audit Flag",
            "Consecutive Offline Sweeps",
            "First Seen Online (UTC)",
            "Last Seen Online (UTC)",
            "Classification Reason",
            "Audit Notes",
        ]
    )
    for item in items:
        writer.writerow(
            [
                item.site_name,
                item.subnet_cidr,
                item.subnet_label,
                item.ip_address,
                item.hostname or "",
                item.status.value,
                "Yes" if item.ipam_allocated else "No",
                item.ipam_owner or "",
                item.audit_flag.value,
                item.consecutive_offline_scans,
                item.first_seen_online_at.isoformat() if item.first_seen_online_at else "",
                item.last_seen_online_at.isoformat() if item.last_seen_online_at else "",
                item.classification_reason,
                item.audit_notes or "",
            ]
        )

    return StreamingResponse(
        io.BytesIO(csv_buffer.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="subnetpulse_audit_{timestamp_str}.csv"'
        },
    )
