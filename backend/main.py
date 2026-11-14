import csv
import io
import ipaddress
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from database import Base, SessionLocal, engine, get_db
from models import AuditEventLog, AuditFlag, IPRecord, IPStatus, ScanStatus, Site, SubnetScope
from scanner import scanner_worker
from schemas import (
    AuditEventLogRead,
    BulkSubnetImportItem,
    BulkSubnetImportRequest,
    BulkSubnetImportResult,
    IPRecordDetailRead,
    IPRecordRead,
    IPRecordUpdate,
    OrphanedOrUnusedIPReportItem,
    SiteCreate,
    SiteTreeRead,
    SubnetCreate,
    SubnetSummaryRead,
    SubnetUpdate,
)


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
            scan_enabled=True,
            scan_interval_minutes=30,
            scan_cron_time="02:00",
        ),
        SubnetScope(
            site_id=birmingham.id,
            cidr="10.50.30.0/28",
            label="Birmingham Office - Corporate Printers & IoT",
            vlan_id=30,
            gateway_ip="10.50.30.1",
            scan_enabled=True,
            scan_interval_minutes=60,
        ),
        SubnetScope(
            site_id=london.id,
            cidr="172.16.100.0/28",
            label="London DC - Core Infrastructure Management",
            vlan_id=100,
            gateway_ip="172.16.100.1",
            scan_enabled=True,
            scan_interval_minutes=15,
            scan_cron_time="04:30",
        ),
        SubnetScope(
            site_id=manchester.id,
            cidr="192.168.88.0/28",
            label="Manchester Branch - Legacy Workstation Scope",
            vlan_id=88,
            gateway_ip="192.168.88.1",
            scan_enabled=True,
            scan_interval_minutes=120,
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

            if rec.audit_flag in (
                AuditFlag.SUSPECTED_UNUSED,
                AuditFlag.GHOST_DEVICE,
                AuditFlag.EXPECTED_DECOMMISSIONED,
            ) or (rec.ipam_allocated and rec.status != IPStatus.ONLINE):
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
    Base.metadata.create_all(bind=engine)
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
    "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000"
)
allowed_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# Health & Navigation Tree Endpoints
# ==========================================
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "scanner_running": scanner_worker.is_running,
        "active_scans": list(scanner_worker.active_subnet_scans),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/tree", response_model=List[SiteTreeRead])
def get_navigation_tree(db: Session = Depends(get_db)):
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
def list_sites(db: Session = Depends(get_db)):
    return (
        db.query(Site)
        .options(joinedload(Site.subnets))
        .order_by(Site.name.asc())
        .all()
    )


@app.post("/api/sites", response_model=SiteTreeRead, status_code=201)
def create_site(payload: SiteCreate, db: Session = Depends(get_db)):
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
def delete_site(site_id: int, db: Session = Depends(get_db)):
    site = db.query(Site).filter(Site.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found.")
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
):
    query = db.query(SubnetScope)
    if site_id is not None:
        query = query.filter(SubnetScope.site_id == site_id)
    return query.order_by(SubnetScope.cidr.asc()).all()


@app.get("/api/subnets/{subnet_id}", response_model=SubnetSummaryRead)
def get_subnet(subnet_id: int, db: Session = Depends(get_db)):
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")
    return subnet


@app.post("/api/subnets", response_model=SubnetSummaryRead, status_code=201)
async def create_subnet(
    payload: SubnetCreate,
    db: Session = Depends(get_db),
):
    site = db.query(Site).filter(Site.id == payload.site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail=f"Site ID {payload.site_id} does not exist.")

    existing = db.query(SubnetScope).filter(SubnetScope.cidr == payload.cidr).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Subnet CIDR '{payload.cidr}' is already registered.")

    subnet = SubnetScope(
        site_id=payload.site_id,
        cidr=payload.cidr,
        label=payload.label.strip(),
        vlan_id=payload.vlan_id,
        gateway_ip=payload.gateway_ip.strip() if payload.gateway_ip else None,
        scan_enabled=payload.scan_enabled,
        scan_interval_minutes=payload.scan_interval_minutes,
        scan_cron_time=payload.scan_cron_time,
        scan_status=ScanStatus.IDLE,
    )
    db.add(subnet)
    db.commit()
    db.refresh(subnet)

    populate_subnet_ip_records(db, subnet)
    scanner_worker.schedule_immediate_scan(subnet.id)
    return subnet


@app.patch("/api/subnets/{subnet_id}", response_model=SubnetSummaryRead)
def update_subnet(
    subnet_id: int,
    payload: SubnetUpdate,
    db: Session = Depends(get_db),
):
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(subnet, field, value)

    db.commit()
    db.refresh(subnet)
    return subnet


@app.delete("/api/subnets/{subnet_id}", status_code=204)
def delete_subnet(subnet_id: int, db: Session = Depends(get_db)):
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")
    db.delete(subnet)
    db.commit()
    return None


@app.post("/api/subnets/{subnet_id}/scan", response_model=SubnetSummaryRead)
async def trigger_manual_subnet_scan(subnet_id: int, db: Session = Depends(get_db)):
    """
    Immediate 'Rescan Now' endpoint at the subnet level. Launches an asynchronous
    non-blocking sweep of the subnet's IP range.
    """
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")

    if subnet.id not in scanner_worker.active_subnet_scans:
        subnet.scan_status = ScanStatus.SCANNING
        db.commit()
        db.refresh(subnet)
        scanner_worker.schedule_immediate_scan(subnet.id)

    return subnet


@app.delete("/api/subnets/{subnet_id}/history", response_model=SubnetSummaryRead)
def clear_subnet_history(subnet_id: int, db: Session = Depends(get_db)):
    """
    Clears all state transition / audit event logs for every IP record in the subnet
    and resets historical timestamps and sweep counters.
    """
    subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
    if not subnet:
        raise HTTPException(status_code=404, detail="Subnet not found.")

    ip_records = db.query(IPRecord).filter(IPRecord.subnet_id == subnet_id).all()
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

    subnet.online_count = 0
    subnet.offline_count = 0
    subnet.unknown_count = len(ip_records)
    subnet.last_scanned_at = None
    subnet.last_scan_duration_ms = None
    subnet.scan_status = ScanStatus.IDLE

    unused_cnt = sum(
        1
        for rec in ip_records
        if rec.audit_flag
        in (
            AuditFlag.SUSPECTED_UNUSED,
            AuditFlag.GHOST_DEVICE,
            AuditFlag.EXPECTED_DECOMMISSIONED,
        )
    )
    subnet.suspected_unused_count = unused_cnt
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
) -> BulkSubnetImportResult:
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

        existing_subnet = db.query(SubnetScope).filter(SubnetScope.cidr == item.cidr).first()
        if existing_subnet:
            skipped_cidrs.append(item.cidr)
            continue

        new_subnet = SubnetScope(
            site_id=site.id,
            cidr=item.cidr,
            label=item.label.strip(),
            vlan_id=item.vlan_id,
            gateway_ip=item.gateway_ip.strip() if item.gateway_ip else None,
            scan_enabled=item.scan_enabled,
            scan_interval_minutes=item.scan_interval_minutes,
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
            scanner_worker.schedule_immediate_scan(new_subnet.id)

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
):
    """
    Bulk-imports sites, subnet CIDR scopes, and scan intervals from structured JSON.
    """
    if not payload.subnets:
        raise HTTPException(status_code=400, detail="No subnet entries provided for import.")
    return _execute_bulk_import(payload.subnets, payload.trigger_initial_scan, db)


@app.post("/api/subnets/bulk-import-csv", response_model=BulkSubnetImportResult, status_code=201)
async def bulk_import_subnets_csv(
    file: UploadFile = File(...),
    trigger_initial_scan: bool = Query(False),
    db: Session = Depends(get_db),
):
    """
    Bulk-imports subnets from an uploaded CSV file with columns:
    site_name,cidr,label,vlan_id,gateway_ip,scan_interval_minutes,scan_cron_time
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
            interval_raw = (row.get("scan_interval_minutes") or "60").strip()
            items.append(
                BulkSubnetImportItem(
                    site_name=row["site_name"].strip(),
                    cidr=row["cidr"].strip(),
                    label=(row.get("label") or row["cidr"]).strip(),
                    vlan_id=int(vlan_raw) if vlan_raw.isdigit() else None,
                    gateway_ip=(row.get("gateway_ip") or "").strip() or None,
                    scan_enabled=str(row.get("scan_enabled", "true")).lower() not in ("false", "0", "no"),
                    scan_interval_minutes=int(interval_raw) if interval_raw.isdigit() else 60,
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

    return _execute_bulk_import(items, trigger_initial_scan, db)


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
def get_ip_record_detail(ip_id: int, db: Session = Depends(get_db)):
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
        audit_entry = AuditEventLog(
            ip_record_id=ip_record.id,
            previous_status=ip_record.status,
            new_status=ip_record.status,
            event_type="MANUAL_AUDIT_UPDATE",
            response_time_ms=ip_record.response_time_ms,
            details="; ".join(changes),
        )
        db.add(audit_entry)

    db.commit()

    # Recompute suspected_unused_count on parent subnet
    subnet = db.query(SubnetScope).filter(SubnetScope.id == ip_record.subnet_id).first()
    if subnet:
        unused_cnt = (
            db.query(IPRecord)
            .filter(
                IPRecord.subnet_id == subnet.id,
                or_(
                    IPRecord.audit_flag.in_(
                        [
                            AuditFlag.SUSPECTED_UNUSED,
                            AuditFlag.GHOST_DEVICE,
                            AuditFlag.EXPECTED_DECOMMISSIONED,
                        ]
                    ),
                    (IPRecord.ipam_allocated.is_(True) & (IPRecord.status != IPStatus.ONLINE)),
                ),
            )
            .count()
        )
        subnet.suspected_unused_count = unused_cnt
        db.commit()

    db.refresh(ip_record)
    return ip_record


@app.get("/api/ips/{ip_id}/logs", response_model=List[AuditEventLogRead])
def get_ip_audit_logs(ip_id: int, db: Session = Depends(get_db)):
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
    query = (
        db.query(IPRecord, SubnetScope, Site)
        .join(SubnetScope, IPRecord.subnet_id == SubnetScope.id)
        .join(Site, SubnetScope.site_id == Site.id)
    )

    if site_id is not None:
        query = query.filter(Site.id == site_id)
    if subnet_id is not None:
        query = query.filter(SubnetScope.id == subnet_id)

    rows = query.order_by(Site.name.asc(), SubnetScope.cidr.asc(), IPRecord.ip_integer.asc()).all()
    report_items: List[OrphanedOrUnusedIPReportItem] = []

    for ip_rec, subnet, site in rows:
        reasons: List[str] = []

        if ip_rec.audit_flag == AuditFlag.SUSPECTED_UNUSED:
            reasons.append("Flagged as Suspected Unused")
        elif ip_rec.audit_flag == AuditFlag.GHOST_DEVICE:
            reasons.append("Flagged as Ghost Device (unexpected active host)")
        elif ip_rec.audit_flag == AuditFlag.EXPECTED_DECOMMISSIONED and ip_rec.status == IPStatus.ONLINE:
            reasons.append("Expected Decommissioned host still responding to ping")
        elif ip_rec.audit_flag == AuditFlag.EXPECTED_DECOMMISSIONED:
            reasons.append("Marked Expected Decommissioned (ready for IPAM reclamation)")

        if ip_rec.ipam_allocated and ip_rec.status == IPStatus.OFFLINE:
            reasons.append(
                f"Allocated in IPAM ({ip_rec.ipam_owner or 'Unassigned'}) but Offline ({ip_rec.consecutive_offline_scans} consecutive sweeps)"
            )
        elif not ip_rec.ipam_allocated and ip_rec.status == IPStatus.ONLINE:
            reasons.append("Orphaned Active IP: Responding to ping but unallocated in IPAM")
        elif (
            ip_rec.first_seen_online_at is not None
            and ip_rec.status == IPStatus.OFFLINE
            and ip_rec.consecutive_offline_scans >= 2
        ):
            reasons.append(
                f"Previously online host now stale/offline for {ip_rec.consecutive_offline_scans} sweeps"
            )

        if reasons:
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
                    classification_reason=" | ".join(reasons),
                )
            )

    return report_items


@app.get("/api/reports/unused-ips", response_model=List[OrphanedOrUnusedIPReportItem])
def get_unused_ip_report(
    site_id: Optional[int] = Query(None),
    subnet_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
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
