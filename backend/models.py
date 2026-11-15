import enum
import ipaddress
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
     Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    select,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def compute_cidr_bounds(cidr: str) -> tuple[str, int, int]:
    """
    Normalizes an IPv4 CIDR string and returns (normalized_cidr, network_start_int, broadcast_end_int).
    """
    network = ipaddress.ip_network(cidr.strip(), strict=False)
    if network.version != 4:
        raise ValueError("Only IPv4 CIDR blocks are supported.")
    return str(network), int(network.network_address), int(network.broadcast_address)


class IPStatus(str, enum.Enum):
    ONLINE = "Online"
    OFFLINE = "Offline"
    UNKNOWN = "Unknown"


class AuditFlag(str, enum.Enum):
    NONE = "None"
    VERIFIED = "Verified Active"
    SUSPECTED_UNUSED = "Suspected Unused"
    GHOST_DEVICE = "Ghost Device"
    EXPECTED_DECOMMISSIONED = "Expected Decommissioned"
    RESERVED_IPAM = "Reserved in IPAM"


class ScanStatus(str, enum.Enum):
    IDLE = "Idle"
    SCANNING = "Scanning"
    COMPLETED = "Completed"
    FAILED = "Failed"


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


class User(Base):
    """
    Operator user account stored in SQLite with salted PBKDF2 password hash
    and role-based access control (admin / viewer).
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), default=UserRole.VIEWER, nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    api_keys: Mapped[List["UserAPIKey"]] = relationship(
        "UserAPIKey",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="UserAPIKey.created_at.desc()",
    )


class UserAPIKey(Base):
    """
    Per-user scoped API key with SHA-256 digest storage and optional expiration timestamp.
    """
    __tablename__ = "user_api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="api_keys")


class Site(Base):
    """
    1. Site / Location (Top Level) -> Has many Subnets.
    Represents a physical office, data center, or logical department.
    """
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    code: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    subnets: Mapped[List["SubnetScope"]] = relationship(
        "SubnetScope",
        back_populates="site",
        cascade="all, delete-orphan",
        order_by="SubnetScope.cidr",
    )


class SubnetScope(Base):
    """
    2. Subnet Scope (Mid Level) -> Belongs to a Site, defines the CIDR block,
    scanning schedule configurations, and historical scan metadata. Has many IP Addresses.
    """
    __tablename__ = "subnets"
    __table_args__ = (
        UniqueConstraint("network_start_int", "broadcast_end_int", name="uq_subnet_network_bounds"),
        Index("ix_subnets_network_bounds", "network_start_int", "broadcast_end_int"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    site_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cidr: Mapped[str] = mapped_column(String(43), unique=True, nullable=False, index=True)
    network_start_int: Mapped[int] = mapped_column(Integer, nullable=False, index=True, default=0)
    broadcast_end_int: Mapped[int] = mapped_column(Integer, nullable=False, index=True, default=0)
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    vlan_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    gateway_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Scheduling & Automated Sweep Configuration
    scan_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scan_interval_minutes: Mapped[int] = mapped_column(Integer, default=1440, nullable=False)
    scan_cron_time: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True, doc="Optional HH:MM daily execution time in UTC"
    )

    # Scan state & telemetry
    scan_status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.IDLE, nullable=False
    )
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    online_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    offline_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unknown_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspected_unused_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    site: Mapped["Site"] = relationship("Site", back_populates="subnets")
    ip_records: Mapped[List["IPRecord"]] = relationship(
        "IPRecord",
        back_populates="subnet",
        cascade="all, delete-orphan",
        order_by="IPRecord.ip_integer",
    )

    @validates("cidr")
    def _validate_and_normalize_cidr(self, key: str, value: str) -> str:
        normalized_cidr, start_int, end_int = compute_cidr_bounds(value)
        self.network_start_int = start_int
        self.broadcast_end_int = end_int
        return normalized_cidr


@event.listens_for(SubnetScope, "before_insert")
@event.listens_for(SubnetScope, "before_update")
def _enforce_non_overlapping_subnet(mapper, connection, target: SubnetScope) -> None:
    normalized_cidr, start_int, end_int = compute_cidr_bounds(target.cidr)
    target.cidr = normalized_cidr
    target.network_start_int = start_int
    target.broadcast_end_int = end_int

    subnets_table = SubnetScope.__table__
    stmt = select(subnets_table.c.id, subnets_table.c.cidr, subnets_table.c.label).where(
        subnets_table.c.network_start_int <= end_int,
        subnets_table.c.broadcast_end_int >= start_int,
    )
    if target.id is not None:
        stmt = stmt.where(subnets_table.c.id != target.id)

    conflict = connection.execute(stmt).first()
    if conflict is not None:
        raise ValueError(
            f"Subnet CIDR '{target.cidr}' overlaps with existing subnet '{conflict.cidr}' ({conflict.label})."
        )


class IPRecord(Base):
    """
    3. IP Address Record (Low Level) -> Belongs to a Subnet Scope, tracking individual
    host IPs, current status (Online, Offline, Unknown), historical state changes,
    last-seen timestamps, IPAM expectations, and audit notes.
    """
    __tablename__ = "ip_records"
    __table_args__ = (
        UniqueConstraint("subnet_id", "ip_address", name="uq_subnet_ip_address"),
        UniqueConstraint("ip_address", name="uq_ip_records_ip_address"),
        UniqueConstraint("ip_integer", name="uq_ip_records_ip_integer"),
        Index("ix_ip_records_subnet_status", "subnet_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    subnet_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    ip_integer: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    status: Mapped[IPStatus] = mapped_column(
        Enum(IPStatus), default=IPStatus.UNKNOWN, nullable=False, index=True
    )
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Historical presence tracking
    first_seen_online_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_online_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_offline_scans: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    state_change_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # IPAM Reconciliation & Manual Audit Metadata
    ipam_allocated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ipam_owner: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    audit_flag: Mapped[AuditFlag] = mapped_column(
        Enum(AuditFlag), default=AuditFlag.NONE, nullable=False, index=True
    )
    audit_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    subnet: Mapped["SubnetScope"] = relationship("SubnetScope", back_populates="ip_records")
    audit_logs: Mapped[List["AuditEventLog"]] = relationship(
        "AuditEventLog",
        back_populates="ip_record",
        cascade="all, delete-orphan",
        order_by="AuditEventLog.timestamp.desc()",
    )


class AuditEventLog(Base):
    """
    4. Audit Event Log (Related to IP Records) -> Tracks state transition history
    (e.g., Offline -> Online, Unknown -> Online) and manual audit metadata updates
    for investigating lingering ghost devices and verifying stale IP cleanup over time.
    """
    __tablename__ = "audit_event_logs"
    __table_args__ = (
        Index("ix_audit_logs_ip_timestamp", "ip_record_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_record_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ip_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    previous_status: Mapped[Optional[IPStatus]] = mapped_column(Enum(IPStatus), nullable=True)
    new_status: Mapped[Optional[IPStatus]] = mapped_column(Enum(IPStatus), nullable=True)
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="STATE_TRANSITION"
    )
    actor_username: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    ip_record: Mapped["IPRecord"] = relationship("IPRecord", back_populates="audit_logs")
