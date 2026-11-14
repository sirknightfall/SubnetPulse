import asyncio
import ipaddress
import logging
import os
import platform
import re
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from database import SessionLocal
from models import AuditEventLog, AuditFlag, IPRecord, IPStatus, ScanStatus, SubnetScope

logger = logging.getLogger("subnetpulse.scanner")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

PING_CONCURRENCY = int(os.getenv("PING_CONCURRENCY", "128"))
PING_TIMEOUT_SECONDS = float(os.getenv("PING_TIMEOUT_SECONDS", "1.5"))
SCHEDULER_TICK_SECONDS = int(os.getenv("SCHEDULER_TICK_SECONDS", "15"))

RTT_REGEX = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


async def async_icmp_ping(ip_address: str, timeout: float = PING_TIMEOUT_SECONDS) -> Tuple[bool, Optional[float]]:
    """
    Executes a non-blocking system ICMP echo request against a single IPv4 host
    and extracts round-trip latency in milliseconds if reachable.
    Falls back to a non-blocking TCP handshake probe on port 80/443/22 if raw ICMP is restricted.
    """
    # Validate IP address using Python's ipaddress module
    ip_obj = ipaddress.ip_address(ip_address)
    ip_str = str(ip_obj)

    system_name = platform.system().lower()
    timeout_arg = str(max(1, int(round(timeout))))
    if system_name == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip_str]
    elif system_name == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip_str]
    else:
        cmd = ["ping", "-c", "1", "-W", timeout_arg, ip_str]

    start_ns = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False, None

        elapsed_ms = round((time.perf_counter() - start_ns) * 1000.0, 2)
        if proc.returncode == 0:
            output_text = stdout_bytes.decode("utf-8", errors="ignore")
            match = RTT_REGEX.search(output_text)
            rtt_ms = float(match.group(1)) if match else elapsed_ms
            return True, rtt_ms
    except FileNotFoundError:
        logger.warning("System 'ping' binary not found; falling back to async TCP socket probe.")
    except Exception as exc:
        logger.debug("ICMP ping error for %s: %s", ip_str, exc)

    # Secondary non-blocking TCP SYN probe on common management ports (443, 80, 22)
    for port in (443, 80, 22):
        probe_start = time.perf_counter()
        try:
            conn_coro = asyncio.open_connection(ip_str, port)
            _, writer = await asyncio.wait_for(conn_coro, timeout=min(0.6, timeout))
            writer.close()
            await writer.wait_closed()
            rtt = round((time.perf_counter() - probe_start) * 1000.0, 2)
            return True, rtt
        except (asyncio.TimeoutError, OSError):
            continue

    return False, None


async def async_reverse_dns(ip_address: str) -> Optional[str]:
    """
    Performs a non-blocking reverse PTR lookup using the default executor.
    """
    loop = asyncio.get_running_loop()
    try:
        hostname, _, _ = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip_address),
            timeout=1.0,
        )
        return hostname
    except Exception:
        return None


class SubnetScannerWorker:
    """
    Asynchronous background worker managing scheduled (interval & daily HH:MM cron)
    and on-demand subnet sweeps, IP state transition detection, and audit event logging.
    """

    def __init__(self, concurrency: int = PING_CONCURRENCY):
        self._semaphore = asyncio.Semaphore(concurrency)
        self._scheduler_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
        self.active_subnet_scans: Set[int] = set()
        self._background_tasks: Set[asyncio.Task] = set()
        self._last_cron_trigger_date: Dict[int, str] = {}

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._loop = asyncio.get_running_loop()
        self._scheduler_task = asyncio.create_task(self._scheduler_loop(), name="subnetpulse-scheduler")
        logger.info("SubnetScannerWorker started (concurrency=%d).", PING_CONCURRENCY)

    async def stop(self) -> None:
        self._running = False
        if self._scheduler_task and not self._scheduler_task.done():
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass

        if self._background_tasks:
            for task in list(self._background_tasks):
                task.cancel()
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        logger.info("SubnetScannerWorker stopped cleanly.")

    def _create_scan_task(self, subnet_id: int) -> None:
        if subnet_id in self.active_subnet_scans:
            return
        task = asyncio.create_task(self.scan_subnet(subnet_id))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def schedule_immediate_scan(self, subnet_id: int) -> None:
        """
        Schedules an immediate non-blocking subnet scan task safely from either
        an async coroutine or a synchronous worker thread.
        """
        if subnet_id in self.active_subnet_scans:
            return
        try:
            running_loop = asyncio.get_running_loop()
            if running_loop.is_running():
                self._create_scan_task(subnet_id)
                return
        except RuntimeError:
            pass

        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._create_scan_task, subnet_id)

    async def trigger_subnet_scan(self, subnet_id: int) -> None:
        """
        Entrypoint compatible with FastAPI BackgroundTasks.
        """
        await self.scan_subnet(subnet_id)

    async def _probe_single_ip(
        self, ip_id: int, ip_address: str, existing_hostname: Optional[str]
    ) -> Tuple[int, bool, Optional[float], Optional[str]]:
        async with self._semaphore:
            is_online, rtt_ms = await async_icmp_ping(ip_address)
            resolved_hostname = existing_hostname
            if is_online and not existing_hostname:
                resolved_hostname = await async_reverse_dns(ip_address)
            return ip_id, is_online, rtt_ms, resolved_hostname

    async def scan_subnet(self, subnet_id: int) -> None:
        """
        Sweeps all IP records belonging to a SubnetScope concurrently, records state
        transitions in AuditEventLog, and updates subnet utilization counters.
        """
        if subnet_id in self.active_subnet_scans:
            logger.info("Subnet %d is already being scanned; skipping duplicate trigger.", subnet_id)
            return

        self.active_subnet_scans.add(subnet_id)
        sweep_start = time.perf_counter()

        try:
            with SessionLocal() as db:
                subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
                if not subnet:
                    return

                subnet.scan_status = ScanStatus.SCANNING
                db.commit()

                ip_rows = (
                    db.query(IPRecord)
                    .filter(IPRecord.subnet_id == subnet_id)
                    .order_by(IPRecord.ip_integer.asc())
                    .all()
                )
                probe_targets = [(row.id, row.ip_address, row.hostname) for row in ip_rows]
                subnet_cidr = subnet.cidr

            logger.info("Starting async sweep for subnet %s (%d hosts)...", subnet_cidr, len(probe_targets))

            # Execute all host probes concurrently via asyncio.gather
            probe_tasks = [
                self._probe_single_ip(ip_id, ip_str, hostname)
                for ip_id, ip_str, hostname in probe_targets
            ]
            results = await asyncio.gather(*probe_tasks)
            result_map: Dict[int, Tuple[bool, Optional[float], Optional[str]]] = {
                ip_id: (is_online, rtt_ms, resolved_host)
                for ip_id, is_online, rtt_ms, resolved_host in results
            }

            now_utc = datetime.now(timezone.utc)
            duration_ms = int(round((time.perf_counter() - sweep_start) * 1000.0))

            with SessionLocal() as db:
                self._reconcile_scan_results(db, subnet_id, result_map, now_utc, duration_ms)

            logger.info("Completed sweep for subnet %s in %d ms.", subnet_cidr, duration_ms)

        except Exception as exc:
            logger.exception("Error scanning subnet ID %d: %s", subnet_id, exc)
            with SessionLocal() as db:
                subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
                if subnet:
                    subnet.scan_status = ScanStatus.FAILED
                    db.commit()
        finally:
            self.active_subnet_scans.discard(subnet_id)

    def _reconcile_scan_results(
        self,
        db: Session,
        subnet_id: int,
        result_map: Dict[int, Tuple[bool, Optional[float], Optional[str]]],
        now_utc: datetime,
        duration_ms: int,
    ) -> None:
        subnet = db.query(SubnetScope).filter(SubnetScope.id == subnet_id).first()
        if not subnet:
            return

        ip_records = db.query(IPRecord).filter(IPRecord.subnet_id == subnet_id).all()
        new_audit_logs: List[AuditEventLog] = []

        online_count = 0
        offline_count = 0
        unknown_count = 0

        for record in ip_records:
            probe_outcome = result_map.get(record.id)
            if probe_outcome is None:
                unknown_count += 1
                continue

            is_online, rtt_ms, resolved_hostname = probe_outcome
            previous_status = record.status
            new_status = IPStatus.ONLINE if is_online else IPStatus.OFFLINE

            record.last_checked_at = now_utc
            record.response_time_ms = rtt_ms
            if resolved_hostname and not record.hostname:
                record.hostname = resolved_hostname

            if is_online:
                online_count += 1
                if record.first_seen_online_at is None:
                    record.first_seen_online_at = now_utc
                record.last_seen_online_at = now_utc
                record.consecutive_offline_scans = 0

                # Flag unexpected ghost device if marked Expected Decommissioned or unallocated
                if record.audit_flag == AuditFlag.EXPECTED_DECOMMISSIONED:
                    record.audit_flag = AuditFlag.GHOST_DEVICE
                    new_audit_logs.append(
                        AuditEventLog(
                            ip_record_id=record.id,
                            previous_status=previous_status,
                            new_status=new_status,
                            event_type="GHOST_DEVICE_DETECTED",
                            response_time_ms=rtt_ms,
                            details=(
                                f"Hostmarked Expected Decommissioned responded to ICMP ping ({rtt_ms} ms); "
                                "auto-escalated to Ghost Device."
                            ),
                            timestamp=now_utc,
                        )
                    )
            else:
                offline_count += 1
                record.consecutive_offline_scans += 1

                # Auto-flag IPAM-allocated addresses that repeatedly fail sweeps as Suspected Unused
                if (
                    record.ipam_allocated
                    and record.consecutive_offline_scans >= 3
                    and record.audit_flag == AuditFlag.NONE
                ):
                    record.audit_flag = AuditFlag.SUSPECTED_UNUSED
                    new_audit_logs.append(
                        AuditEventLog(
                            ip_record_id=record.id,
                            previous_status=previous_status,
                            new_status=new_status,
                            event_type="AUTO_FLAG_SUSPECTED_UNUSED",
                            response_time_ms=None,
                            details=(
                                f"IPAM-allocated host offline for {record.consecutive_offline_scans} "
                                "consecutive sweeps; flagged as Suspected Unused."
                            ),
                            timestamp=now_utc,
                        )
                    )

            # Log every state transition (e.g., Unknown -> Online, Offline -> Online, Online -> Offline)
            if previous_status != new_status:
                record.status = new_status
                record.state_change_count += 1
                transition_detail = (
                    f"State transitioned from {previous_status.value} to {new_status.value}"
                    + (f" (RTT {rtt_ms} ms)" if rtt_ms is not None else " (No ICMP/TCP response)")
                )
                new_audit_logs.append(
                    AuditEventLog(
                        ip_record_id=record.id,
                        previous_status=previous_status,
                        new_status=new_status,
                        event_type="STATE_TRANSITION",
                        response_time_ms=rtt_ms,
                        details=transition_detail,
                        timestamp=now_utc,
                    )
                )

        if new_audit_logs:
            db.add_all(new_audit_logs)

        db.flush()

        suspected_unused_count = (
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

        subnet.total_hosts = len(ip_records)
        subnet.online_count = online_count
        subnet.offline_count = offline_count
        subnet.unknown_count = unknown_count
        subnet.suspected_unused_count = suspected_unused_count
        subnet.last_scanned_at = now_utc
        subnet.last_scan_duration_ms = duration_ms
        subnet.scan_status = ScanStatus.COMPLETED
        db.commit()

    async def _scheduler_loop(self) -> None:
        """
        Periodic scheduler evaluating both interval-based sweeps (scan_interval_minutes)
        and daily cron-time sweeps (scan_cron_time in HH:MM UTC).
        """
        while self._running:
            try:
                now_utc = datetime.now(timezone.utc)
                current_hhmm = now_utc.strftime("%H:%M")
                current_date_str = now_utc.strftime("%Y-%m-%d")

                due_subnet_ids: List[int] = []

                with SessionLocal() as db:
                    enabled_subnets = (
                        db.query(SubnetScope)
                        .filter(SubnetScope.scan_enabled.is_(True))
                        .all()
                    )

                    for subnet in enabled_subnets:
                        if subnet.id in self.active_subnet_scans:
                            continue

                        # 1. Check daily HH:MM cron schedule if configured
                        if subnet.scan_cron_time and subnet.scan_cron_time == current_hhmm:
                            last_fired_date = self._last_cron_trigger_date.get(subnet.id)
                            if last_fired_date != current_date_str:
                                self._last_cron_trigger_date[subnet.id] = current_date_str
                                due_subnet_ids.append(subnet.id)
                                continue

                        # 2. Check interval-based schedule
                        if subnet.last_scanned_at is None:
                            continue

                        last_scan = subnet.last_scanned_at
                        if last_scan.tzinfo is None:
                            last_scan = last_scan.replace(tzinfo=timezone.utc)

                        next_due = last_scan + timedelta(minutes=max(1, subnet.scan_interval_minutes))
                        if now_utc >= next_due:
                            due_subnet_ids.append(subnet.id)

                for subnet_id in due_subnet_ids:
                    self.schedule_immediate_scan(subnet_id)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("Error in SubnetScannerWorker scheduler loop: %s", exc)

            await asyncio.sleep(SCHEDULER_TICK_SECONDS)


scanner_worker = SubnetScannerWorker()
