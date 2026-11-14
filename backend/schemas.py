import ipaddress
import re
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from models import AuditFlag, IPStatus, ScanStatus


# ==========================================
# Audit Event Log Schemas
# ==========================================
class AuditEventLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_record_id: int
    previous_status: Optional[IPStatus] = None
    new_status: IPStatus
    event_type: str
    response_time_ms: Optional[float] = None
    details: Optional[str] = None
    timestamp: datetime


# ==========================================
# IP Address Record Schemas
# ==========================================
class IPRecordUpdate(BaseModel):
    hostname: Optional[str] = Field(None, max_length=255)
    ipam_allocated: Optional[bool] = None
    ipam_owner: Optional[str] = Field(None, max_length=120)
    audit_flag: Optional[AuditFlag] = None
    audit_notes: Optional[str] = None


class IPRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    subnet_id: int
    ip_address: str
    ip_integer: int
    hostname: Optional[str] = None
    status: IPStatus
    response_time_ms: Optional[float] = None
    first_seen_online_at: Optional[datetime] = None
    last_seen_online_at: Optional[datetime] = None
    last_checked_at: Optional[datetime] = None
    consecutive_offline_scans: int
    state_change_count: int
    ipam_allocated: bool
    ipam_owner: Optional[str] = None
    audit_flag: AuditFlag
    audit_notes: Optional[str] = None
    updated_at: datetime


class IPRecordDetailRead(IPRecordRead):
    audit_logs: List[AuditEventLogRead] = []


# ==========================================
# Subnet Scope Schemas
# ==========================================
class SubnetBase(BaseModel):
    cidr: str = Field(..., examples=["10.50.20.0/24"])
    label: str = Field(..., min_length=1, max_length=160, examples=["Birmingham Office - Server VLAN"])
    vlan_id: Optional[int] = Field(None, ge=1, le=4094)
    gateway_ip: Optional[str] = None
    scan_enabled: bool = True
    scan_interval_minutes: int = Field(default=60, ge=1, le=10080)
    scan_cron_time: Optional[str] = Field(
        default=None, description="Optional daily HH:MM schedule in 24h format"
    )

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        cleaned = value.strip()
        try:
            network = ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR block '{value}': {exc}") from exc
        if network.version != 4:
            raise ValueError("Only IPv4 CIDR blocks are supported for subnet sweeps.")
        if network.prefixlen < 20:
            raise ValueError(
                "Subnet prefix must be /20 or narrower (e.g., /24) to prevent excessive broadcast sweeps."
            )
        return str(network)

    @field_validator("scan_cron_time")
    @classmethod
    def validate_cron_time(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value.strip() == "":
            return None
        cleaned = value.strip()
        if not re.match(r"^([01]\d|2[0-3]):([0-5]\d)$", cleaned):
            raise ValueError("scan_cron_time must be in HH:MM (24-hour) format.")
        return cleaned


class SubnetCreate(SubnetBase):
    site_id: int


class SubnetUpdate(BaseModel):
    label: Optional[str] = Field(None, min_length=1, max_length=160)
    vlan_id: Optional[int] = Field(None, ge=1, le=4094)
    gateway_ip: Optional[str] = None
    scan_enabled: Optional[bool] = None
    scan_interval_minutes: Optional[int] = Field(None, ge=1, le=10080)
    scan_cron_time: Optional[str] = None


class SubnetSummaryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    site_id: int
    cidr: str
    label: str
    vlan_id: Optional[int] = None
    gateway_ip: Optional[str] = None
    scan_enabled: bool
    scan_interval_minutes: int
    scan_cron_time: Optional[str] = None
    scan_status: ScanStatus
    last_scanned_at: Optional[datetime] = None
    last_scan_duration_ms: Optional[int] = None
    total_hosts: int
    online_count: int
    offline_count: int
    unknown_count: int
    suspected_unused_count: int

    @property
    def utilization_percent(self) -> float:
        if self.total_hosts <= 0:
            return 0.0
        return round((self.online_count / self.total_hosts) * 100.0, 1)


# ==========================================
# Site / Location Schemas
# ==========================================
class SiteBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=120, examples=["Birmingham Office"])
    description: Optional[str] = Field(None, max_length=255)


class SiteCreate(SiteBase):
    pass


class SiteTreeRead(SiteBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    subnets: List[SubnetSummaryRead] = []


# ==========================================
# Bulk Import & Audit Reporting Schemas
# ==========================================
class BulkSubnetImportItem(BaseModel):
    site_name: str = Field(..., min_length=1, max_length=120)
    cidr: str
    label: str = Field(..., min_length=1, max_length=160)
    vlan_id: Optional[int] = Field(None, ge=1, le=4094)
    gateway_ip: Optional[str] = None
    scan_enabled: bool = True
    scan_interval_minutes: int = Field(default=60, ge=1, le=10080)
    scan_cron_time: Optional[str] = None

    @field_validator("cidr")
    @classmethod
    def validate_item_cidr(cls, value: str) -> str:
        return SubnetBase.validate_cidr(value)


class BulkSubnetImportRequest(BaseModel):
    subnets: List[BulkSubnetImportItem]
    trigger_initial_scan: bool = False


class BulkSubnetImportResult(BaseModel):
    created_sites: int
    created_subnets: int
    skipped_existing_cidrs: List[str]
    imported_subnet_ids: List[int]


class OrphanedOrUnusedIPReportItem(BaseModel):
    ip_id: int
    ip_address: str
    hostname: Optional[str] = None
    status: IPStatus
    subnet_id: int
    subnet_cidr: str
    subnet_label: str
    site_name: str
    first_seen_online_at: Optional[datetime] = None
    last_seen_online_at: Optional[datetime] = None
    consecutive_offline_scans: int
    ipam_allocated: bool
    ipam_owner: Optional[str] = None
    audit_flag: AuditFlag
    audit_notes: Optional[str] = None
    classification_reason: str
