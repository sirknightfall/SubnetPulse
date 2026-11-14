import enum
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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    site_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cidr: Mapped[str] = mapped_column(String(43), unique=True, nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    vlan_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    gateway_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # Scheduling & Automated Sweep Configuration
    scan_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scan_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
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


class IPRecord(Base):
    """
    3. IP Address Record (Low Level) -> Belongs to a Subnet Scope, tracking individual
    host IPs, current status (Online, Offline, Unknown), historical state changes,
    last-seen timestamps, IPAM expectations, and audit notes.
    """
    __tablename__ = "ip_records"
    __table_args__ = (
        UniqueConstraint("subnet_id", "ip_address", name="uq_subnet_ip_address"),
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
    (e.g., Offline -> Online, Unknown -> Online, Manual Flag Update) for auditing
    lingering ghost devices and verifying stale IP cleanup over time.
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
    new_status: Mapped[IPStatus] = mapped_column(Enum(IPStatus), nullable=False)
    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="STATE_TRANSITION"
    )
    response_time_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    ip_record: Mapped["IPRecord"] = relationship("IPRecord", back_populates="audit_logs")
