import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Building2,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Download,
  Edit3,
  FileSpreadsheet,
  FileText,
  Filter,
  History,
  Layers,
  Network,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Trash2,
  Upload,
  Wifi,
  WifiOff,
  X
} from "lucide-react";
import { api } from "./api";

const AUDIT_FLAG_OPTIONS = [
  "None",
  "Verified Active",
  "Suspected Unused",
  "Ghost Device",
  "Expected Decommissioned",
  "Reserved in IPAM"
];

const SAMPLE_BULK_JSON = JSON.stringify(
  [
    {
      site_name: "Birmingham Office",
      cidr: "10.50.40.0/29",
      label: "Birmingham - Security & Badge Controllers",
      vlan_id: 40,
      gateway_ip: "10.50.40.1",
      scan_enabled: false,
      scan_interval_hours: 24,
      scan_cron_time: "03:15"
    },
    {
      site_name: "Bristol Lab",
      cidr: "172.22.10.0/29",
      label: "Bristol R&D Hardware Testbench",
      vlan_id: 210,
      gateway_ip: "172.22.10.1",
      scan_enabled: false,
      scan_interval_hours: 12,
      scan_cron_time: null
    }
  ],
  null,
  2
);

function formatTimestamp(isoString) {
  if (!isoString) return "Never";
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return "Invalid date";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function StatusBadge({ status, rttMs }) {
  if (status === "Online") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
        Online
        {rttMs !== null && rttMs !== undefined && (
          <span className="text-[11px] font-mono text-emerald-400/90 ml-0.5">
            {Number(rttMs).toFixed(1)}ms
          </span>
        )}
      </span>
    );
  }
  if (status === "Offline") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/15 text-rose-300 border border-rose-500/30">
        <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
        Offline
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-700/60 text-slate-300 border border-slate-600">
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
      Unknown
    </span>
  );
}

function AuditFlagBadge({ flag }) {
  const styles = {
    None: "bg-slate-800/80 text-slate-400 border-slate-700",
    "Verified Active": "bg-sky-500/15 text-sky-300 border-sky-500/30",
    "Suspected Unused": "bg-amber-500/15 text-amber-300 border-amber-500/30",
    "Ghost Device": "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30",
    "Expected Decommissioned": "bg-orange-500/15 text-orange-300 border-orange-500/30",
    "Reserved in IPAM": "bg-indigo-500/15 text-indigo-300 border-indigo-500/30"
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${
        styles[flag] || styles.None
      }`}
    >
      {flag}
    </span>
  );
}

export default function App() {
  const [tree, setTree] = useState([]);
  const [selectedSubnetId, setSelectedSubnetId] = useState(null);
  const [activeView, setActiveView] = useState("inventory"); // "inventory" | "report"
  const [expandedSites, setExpandedSites] = useState({});
  const [sidebarSearch, setSidebarSearch] = useState("");

  // IP Inventory State
  const [ipRecords, setIpRecords] = useState([]);
  const [ipLoading, setIpLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState("");
  const [flagFilter, setFlagFilter] = useState("");
  const [ipSearchQuery, setIpSearchQuery] = useState("");

  // Modals & Drawers
  const [historyModalIp, setHistoryModalIp] = useState(null);
  const [editingIpRecord, setEditingIpRecord] = useState(null);
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [bulkModalInitialTab, setBulkModalInitialTab] = useState("json");
  const [bulkModalInitialSite, setBulkModalInitialSite] = useState("");
  const [showScheduleModal, setShowScheduleModal] = useState(false);

  // Unused / Orphaned Report State
  const [reportItems, setReportItems] = useState([]);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportSiteFilter, setReportSiteFilter] = useState("");

  // Notifications / Banner
  const [banner, setBanner] = useState(null);

  const showToast = useCallback((message, type = "info") => {
    setBanner({ message, type });
    setTimeout(() => {
      setBanner((prev) => (prev?.message === message ? null : prev));
    }, 4500);
  }, []);

  const loadTree = useCallback(async () => {
    try {
      const data = await api.getTree();
      setTree(data);

      setExpandedSites((prev) => {
        const next = { ...prev };
        for (const site of data) {
          if (next[site.id] === undefined) {
            next[site.id] = true;
          }
        }
        return next;
      });

      setSelectedSubnetId((currentId) => {
        if (currentId) {
          const stillExists = data.some((site) =>
            site.subnets.some((sub) => sub.id === currentId)
          );
          if (stillExists) return currentId;
        }
        for (const site of data) {
          if (site.subnets.length > 0) {
            return site.subnets[0].id;
          }
        }
        return null;
      });
    } catch (err) {
      showToast(err.message, "error");
    }
  }, [showToast]);

  const selectedSubnetContext = useMemo(() => {
    for (const site of tree) {
      for (const subnet of site.subnets) {
        if (subnet.id === selectedSubnetId) {
          return { site, subnet };
        }
      }
    }
    return null;
  }, [tree, selectedSubnetId]);

  const loadSubnetIps = useCallback(async () => {
    if (!selectedSubnetId) {
      setIpRecords([]);
      return;
    }
    try {
      setIpLoading(true);
      const records = await api.getSubnetIps(selectedSubnetId, {
        status: statusFilter || undefined,
        audit_flag: flagFilter || undefined,
        q: ipSearchQuery || undefined
      });
      setIpRecords(records);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setIpLoading(false);
    }
  }, [selectedSubnetId, statusFilter, flagFilter, ipSearchQuery, showToast]);

  const loadUnusedReport = useCallback(async () => {
    if (!selectedSubnetId) {
      setReportItems([]);
      return;
    }
    try {
      setReportLoading(true);
      const data = await api.getUnusedIpReport({
        subnet_id: selectedSubnetId
      });
      setReportItems(data);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setReportLoading(false);
    }
  }, [selectedSubnetId, showToast]);

  useEffect(() => {
    loadTree();
  }, [loadTree]);

  useEffect(() => {
    if (activeView === "inventory") {
      loadSubnetIps();
    } else {
      loadUnusedReport();
    }
  }, [activeView, loadSubnetIps, loadUnusedReport]);

  // Poll while any subnet has an active scan running
  useEffect(() => {
    const anyScanning = tree.some((site) =>
      site.subnets.some((sub) => sub.scan_status === "Scanning")
    );
    const intervalMs = anyScanning ? 2000 : 10000;
    const timer = setInterval(() => {
      loadTree();
      if (anyScanning && activeView === "inventory" && selectedSubnetId) {
        loadSubnetIps();
      }
    }, intervalMs);

    return () => clearInterval(timer);
  }, [tree, activeView, selectedSubnetId, loadTree, loadSubnetIps]);

  const handleManualRescan = async (subnetId) => {
    try {
      await api.triggerSubnetScan(subnetId);
      showToast("Async ICMP/TCP sweep initiated for subnet.", "success");
      await loadTree();
      setTimeout(() => {
        loadTree();
        loadSubnetIps();
      }, 1800);
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const handleDeleteSubnet = async (subnet, e) => {
    if (e) e.stopPropagation();
    const confirmed = window.confirm(
      `Delete subnet ${subnet.cidr} (${subnet.label}) and all ${subnet.total_hosts} IP records?`
    );
    if (!confirmed) return;

    try {
      await api.deleteSubnet(subnet.id);
      showToast(`Deleted subnet ${subnet.cidr}.`, "info");
      if (selectedSubnetId === subnet.id) {
        setSelectedSubnetId(null);
      }
      await loadTree();
      if (activeView === "report") {
        loadUnusedReport();
      }
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const handleDeleteSite = async (site, e) => {
    if (e) e.stopPropagation();
    const confirmed = window.confirm(
      `Delete site '${site.name}' and all ${site.subnets.length} subnet(s) inside it?`
    );
    if (!confirmed) return;

    try {
      await api.deleteSite(site.id);
      showToast(`Deleted site '${site.name}'.`, "info");
      await loadTree();
      if (activeView === "report") {
        loadUnusedReport();
      }
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const handleToggleSubnetPeriodicScan = async (subnet, e) => {
    if (e) e.stopPropagation();
    const nextEnabled = !subnet.scan_enabled;
    try {
      await api.updateSubnet(subnet.id, { scan_enabled: nextEnabled });
      showToast(
        `Periodic scan ${nextEnabled ? "enabled" : "disabled"} for ${subnet.cidr}.`,
        "success"
      );
      await loadTree();
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const handleClearSubnetHistory = async (subnet, e) => {
    if (e) e.stopPropagation();
    const confirmed = window.confirm(
      `Clear all audit event logs and reset scan history for ${subnet.cidr} (${subnet.label})?`
    );
    if (!confirmed) return;

    try {
      await api.clearSubnetHistory(subnet.id);
      showToast(`Cleared scan & audit history for ${subnet.cidr}.`, "info");
      await loadTree();
      if (selectedSubnetId === subnet.id) {
        loadSubnetIps();
      }
      if (activeView === "report") {
        loadUnusedReport();
      }
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const handleQuickFlagChange = async (ipRec, newFlag) => {
    try {
      await api.updateIpRecord(ipRec.id, { audit_flag: newFlag });
      showToast(`Updated ${ipRec.ip_address} flag to '${newFlag}'.`, "success");
      loadSubnetIps();
      loadTree();
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const handleQuickIpamToggle = async (ipRec) => {
    try {
      const nextAllocated = !ipRec.ipam_allocated;
      await api.updateIpRecord(ipRec.id, { ipam_allocated: nextAllocated });
      showToast(
        `${ipRec.ip_address} marked as ${nextAllocated ? "IPAM Allocated" : "Unallocated"}.`,
        "success"
      );
      loadSubnetIps();
      loadTree();
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const openHistoryModal = async (ipId) => {
    try {
      const detail = await api.getIpDetail(ipId);
      setHistoryModalIp(detail);
    } catch (err) {
      showToast(err.message, "error");
    }
  };

  const filteredTree = useMemo(() => {
    if (!sidebarSearch.trim()) return tree;
    const q = sidebarSearch.toLowerCase();
    return tree
      .map((site) => {
        const siteMatches = site.name.toLowerCase().includes(q);
        const matchingSubnets = site.subnets.filter(
          (s) =>
            siteMatches ||
            s.cidr.toLowerCase().includes(q) ||
            s.label.toLowerCase().includes(q)
        );
        return { ...site, subnets: matchingSubnets };
      })
      .filter((site) => site.subnets.length > 0);
  }, [tree, sidebarSearch]);

  const globalSummary = useMemo(() => {
    let totalSubnets = 0;
    let totalHosts = 0;
    let totalOnline = 0;
    let totalSuspectedUnused = 0;

    for (const site of tree) {
      totalSubnets += site.subnets.length;
      for (const sub of site.subnets) {
        totalHosts += sub.total_hosts;
        totalOnline += sub.online_count;
        totalSuspectedUnused += sub.suspected_unused_count;
      }
    }
    return { totalSubnets, totalHosts, totalOnline, totalSuspectedUnused };
  }, [tree]);

  return (
    <div className="h-screen w-screen flex flex-col bg-slate-950 text-slate-100 select-none">
      {/* Top Global Bar */}
      <header className="h-14 shrink-0 border-b border-slate-800 bg-slate-900/90 px-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-sky-500/15 border border-sky-500/40 flex items-center justify-center text-sky-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-tight text-slate-100 text-base">
                SubnetPulse
              </span>
              <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-sky-400 border border-slate-700">
                IPAM Reconciler
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Corporate Subnet Sweep &amp; Ghost/Orphaned IP Audit Console
            </p>
          </div>
        </div>

        {/* Global KPI Pills */}
        <div className="hidden lg:flex items-center gap-3 text-xs">
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-slate-400">Subnets:</span>
            <span className="font-mono font-semibold text-slate-100">
              {globalSummary.totalSubnets}
            </span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <Wifi className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">Active Hosts:</span>
            <span className="font-mono font-semibold text-emerald-300">
              {globalSummary.totalOnline} / {globalSummary.totalHosts}
            </span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-400">Audit Discrepancies:</span>
            <span className="font-mono font-semibold text-amber-300">
              {globalSummary.totalSuspectedUnused}
            </span>
          </div>
        </div>

        {/* View Mode Switcher & Bulk Import CTA */}
        <div className="flex items-center gap-2">
          <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800">
            <button
              onClick={() => setActiveView("inventory")}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition flex items-center gap-1.5 ${
                activeView === "inventory"
                  ? "bg-sky-500 text-slate-950 font-semibold shadow-sm"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              Subnet Inventory
            </button>
            <button
              onClick={() => setActiveView("report")}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition flex items-center gap-1.5 ${
                activeView === "report"
                  ? "bg-amber-500 text-slate-950 font-semibold shadow-sm"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Unused Report
              {selectedSubnetContext && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-950/30">
                  {selectedSubnetContext.subnet.suspected_unused_count}
                </span>
              )}
            </button>
          </div>

          <button
            onClick={() => {
              setBulkModalInitialTab("json");
              setBulkModalInitialSite("");
              setShowBulkModal(true);
            }}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition flex items-center gap-1.5"
          >
            <Upload className="w-3.5 h-3.5 text-sky-400" />
            Bulk Import
          </button>
        </div>
      </header>

      {/* Toast Notification Banner */}
      {banner && (
        <div
          className={`px-4 py-2 text-xs font-medium flex items-center justify-between border-b ${
            banner.type === "error"
              ? "bg-rose-950/90 text-rose-200 border-rose-800"
              : "bg-sky-950/90 text-sky-200 border-sky-800"
          }`}
        >
          <span>{banner.message}</span>
          <button
            onClick={() => setBanner(null)}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Split-Pane Body: Persistent Left Subnet Tree + Right Main Audit Panel */}
      <div className="flex-1 flex min-h-0">
        {/* LEFT PANE: Persistent Subnet Navigation Tree */}
        <aside className="w-80 xl:w-96 shrink-0 border-r border-slate-800 bg-slate-900/50 flex flex-col">
          <div className="p-3 border-b border-slate-800 flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={sidebarSearch}
                onChange={(e) => setSidebarSearch(e.target.value)}
                placeholder="Filter sites, CIDRs, or VLANs..."
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>
            <button
              type="button"
              onClick={() => {
                setBulkModalInitialTab("single");
                setBulkModalInitialSite(
                  selectedSubnetContext?.site?.name || tree[0]?.name || ""
                );
                setShowBulkModal(true);
              }}
              title="Quick add a single subnet"
              className="px-2.5 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs flex items-center gap-1 shrink-0 transition shadow-sm"
            >
              <Plus className="w-4 h-4 stroke-[2.5]" />
              <span>Subnet</span>
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-2.5 space-y-2">
            {filteredTree.length === 0 ? (
              <div className="text-center py-10 px-4 text-xs text-slate-500">
                No matching sites or subnets found.
              </div>
            ) : (
              filteredTree.map((site) => {
                const isExpanded = expandedSites[site.id] !== false;
                return (
                  <div
                    key={site.id}
                    className="rounded-xl border border-slate-800/90 bg-slate-900/70 overflow-hidden"
                  >
                    <div
                      onClick={() =>
                        setExpandedSites((prev) => ({
                          ...prev,
                          [site.id]: !isExpanded
                        }))
                      }
                      className="w-full px-3 py-2 flex items-center justify-between text-left hover:bg-slate-800/50 transition cursor-pointer group/site"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        )}
                        <Building2 className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                        <span className="text-xs font-semibold text-slate-200 truncate">
                          {site.name}
                        </span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="text-[11px] font-mono text-slate-400 mr-0.5">
                          {site.subnets.length}
                        </span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setBulkModalInitialTab("single");
                            setBulkModalInitialSite(site.name);
                            setShowBulkModal(true);
                          }}
                          title={`Add subnet to ${site.name}`}
                          className="p-1 rounded hover:bg-sky-500/20 text-slate-400 hover:text-sky-300 transition"
                        >
                          <Plus className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleDeleteSite(site, e)}
                          title={`Delete site ${site.name}`}
                          className="opacity-0 group-hover/site:opacity-100 p-1 rounded hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 transition"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="divide-y divide-slate-800/60 border-t border-slate-800/80">
                        {site.subnets.map((subnet) => {
                          const isSelected = selectedSubnetId === subnet.id;
                          const onlinePct =
                            subnet.total_hosts > 0
                              ? Math.round(
                                  (subnet.online_count / subnet.total_hosts) * 100
                                )
                              : 0;
                          const unusedPct =
                            subnet.total_hosts > 0
                              ? Math.min(
                                  100 - onlinePct,
                                  Math.round(
                                    (subnet.suspected_unused_count /
                                      subnet.total_hosts) *
                                      100
                                  )
                                )
                              : 0;

                          return (
                            <div
                              key={subnet.id}
                              onClick={() => {
                                setSelectedSubnetId(subnet.id);
                              }}
                              className={`p-3 cursor-pointer transition group/subnet ${
                                isSelected
                                  ? "bg-sky-500/10 border-l-2 border-l-sky-400"
                                  : "hover:bg-slate-800/40"
                              }`}
                            >
                              <div className="flex items-center justify-between gap-2">
                                <div className="flex items-center gap-1.5">
                                  <span className="font-mono text-xs font-bold text-slate-100">
                                    {subnet.cidr}
                                  </span>
                                  {subnet.vlan_id && (
                                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-sky-300 border border-slate-700">
                                      VLAN {subnet.vlan_id}
                                    </span>
                                  )}
                                </div>
                                <div className="flex items-center gap-1">
                                  <button
                                    type="button"
                                    onClick={(e) =>
                                      handleToggleSubnetPeriodicScan(subnet, e)
                                    }
                                    title={
                                      subnet.scan_enabled
                                        ? `Periodic scan ON (every ${subnet.scan_interval_hours}h) — click to disable`
                                        : `Periodic scan OFF (every ${subnet.scan_interval_hours}h) — click to enable`
                                    }
                                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-medium border transition ${
                                      subnet.scan_enabled
                                        ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/25"
                                        : "bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200"
                                    }`}
                                  >
                                    {subnet.scan_enabled ? "Auto: ON" : "Auto: OFF"}
                                  </button>

                                  <button
                                    type="button"
                                    onClick={(e) =>
                                      handleClearSubnetHistory(subnet, e)
                                    }
                                    title={`Clear history for ${subnet.cidr}`}
                                    className="opacity-0 group-hover/subnet:opacity-100 p-1 rounded hover:bg-amber-500/20 text-slate-400 hover:text-amber-300 transition"
                                  >
                                    <History className="w-3 h-3" />
                                  </button>

                                  <button
                                    type="button"
                                    onClick={(e) => handleDeleteSubnet(subnet, e)}
                                    title={`Delete subnet ${subnet.cidr}`}
                                    className="opacity-0 group-hover/subnet:opacity-100 p-1 rounded hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 transition"
                                  >
                                    <Trash2 className="w-3 h-3" />
                                  </button>
                                </div>
                              </div>

                              <div className="flex items-center justify-between gap-2 mt-0.5">
                                <p className="text-xs text-slate-300 truncate">
                                  {subnet.label}
                                </p>
                                {subnet.scan_status === "Scanning" ? (
                                  <span className="inline-flex items-center gap-1 text-[10px] font-medium text-sky-400 shrink-0">
                                    <RefreshCw className="w-3 h-3 animate-spin" />
                                    Sweeping
                                  </span>
                                ) : (
                                  <span className="font-mono text-[11px] text-slate-400 shrink-0">
                                    {onlinePct}% used
                                  </span>
                                )}
                              </div>

                              {/* Visual Utilization Progress Bar: Online vs Suspected Unused */}
                              <div className="mt-2 h-1.5 w-full rounded-full bg-slate-800 overflow-hidden flex">
                                <div
                                  style={{ width: `${onlinePct}%` }}
                                  className="bg-emerald-500 transition-all duration-300"
                                  title={`Online: ${subnet.online_count} hosts`}
                                />
                                <div
                                  style={{ width: `${unusedPct}%` }}
                                  className="bg-amber-400 transition-all duration-300"
                                  title={`Suspected Unused / Discrepancy: ${subnet.suspected_unused_count} hosts`}
                                />
                              </div>

                              <div className="mt-1.5 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                                <span className="text-emerald-400">
                                  {subnet.online_count} online
                                </span>
                                <span>{subnet.offline_count} offline</span>
                                {subnet.suspected_unused_count > 0 && (
                                  <span className="text-amber-400">
                                    {subnet.suspected_unused_count} unused
                                  </span>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </aside>

        {/* RIGHT PANE: Main Content Area */}
        <main className="flex-1 flex flex-col min-w-0 bg-slate-950">
          {activeView === "report" && selectedSubnetContext ? (
            <UnusedIpReportPanel
              subnetContext={selectedSubnetContext}
              reportItems={reportItems}
              loading={reportLoading}
              onRefresh={loadUnusedReport}
              onSelectIpHistory={openHistoryModal}
              onSwitchToInventory={() => setActiveView("inventory")}
            />
          ) : selectedSubnetContext ? (
            <>
              {/* Selected Subnet Header & Controls */}
              <div className="p-4 border-b border-slate-800 bg-slate-900/40 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2.5">
                      <h1 className="text-lg font-bold font-mono text-white">
                        {selectedSubnetContext.subnet.cidr}
                      </h1>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {selectedSubnetContext.site.name}
                      </span>
                      {selectedSubnetContext.subnet.vlan_id && (
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/30">
                          VLAN {selectedSubnetContext.subnet.vlan_id}
                        </span>
                      )}
                      {selectedSubnetContext.subnet.gateway_ip && (
                        <span className="text-xs font-mono text-slate-400">
                          GW: {selectedSubnetContext.subnet.gateway_ip}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-300 mt-0.5">
                      {selectedSubnetContext.subnet.label}
                    </p>
                  </div>

                  {/* Schedule Info, Delete Button & Manual Rescan Trigger */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setShowScheduleModal(true)}
                      className="px-3 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 flex items-center gap-1.5 transition"
                      title="Configure automated sweep interval or daily cron time"
                    >
                      <Clock className="w-3.5 h-3.5 text-sky-400" />
                      <span>
                        {selectedSubnetContext.subnet.scan_enabled
                          ? `Auto: Every ${selectedSubnetContext.subnet.scan_interval_hours}h`
                          : `Auto: Off (${selectedSubnetContext.subnet.scan_interval_hours}h)`}
                        {selectedSubnetContext.subnet.scan_cron_time
                          ? ` • Cron ${selectedSubnetContext.subnet.scan_cron_time} UTC`
                          : ""}
                      </span>
                    </button>

                    <button
                      onClick={(e) =>
                        handleClearSubnetHistory(
                          selectedSubnetContext.subnet,
                          e
                        )
                      }
                      className="px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition flex items-center gap-1.5"
                      title="Clear all state transition logs and reset scan history for this subnet"
                    >
                      <History className="w-3.5 h-3.5" />
                      Clear History
                    </button>

                    <button
                      onClick={(e) =>
                        handleDeleteSubnet(selectedSubnetContext.subnet, e)
                      }
                      className="px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition flex items-center gap-1.5"
                      title="Delete this subnet scope and its IP inventory"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Delete
                    </button>

                    <button
                      onClick={() =>
                        handleManualRescan(selectedSubnetContext.subnet.id)
                      }
                      disabled={
                        selectedSubnetContext.subnet.scan_status === "Scanning"
                      }
                      className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 transition flex items-center gap-1.5 shadow-sm"
                    >
                      <RefreshCw
                        className={`w-3.5 h-3.5 ${
                          selectedSubnetContext.subnet.scan_status === "Scanning"
                            ? "animate-spin"
                            : ""
                        }`}
                      />
                      {selectedSubnetContext.subnet.scan_status === "Scanning"
                        ? "Scanning..."
                        : "Rescan Now"}
                    </button>
                  </div>
                </div>

                {/* Filter & Search Toolbar */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    {[
                      {
                        label: `All (${selectedSubnetContext.subnet.total_hosts})`,
                        value: ""
                      },
                      {
                        label: `Online (${selectedSubnetContext.subnet.online_count})`,
                        value: "Online"
                      },
                      {
                        label: `Offline (${selectedSubnetContext.subnet.offline_count})`,
                        value: "Offline"
                      },
                      {
                        label: `Unknown (${selectedSubnetContext.subnet.unknown_count})`,
                        value: "Unknown"
                      }
                    ].map((pill) => (
                      <button
                        key={pill.label}
                        onClick={() => setStatusFilter(pill.value)}
                        className={`px-2.5 py-1 rounded-md font-medium transition ${
                          statusFilter === pill.value
                            ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                            : "bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200"
                        }`}
                      >
                        {pill.label}
                      </button>
                    ))}

                    <select
                      value={flagFilter}
                      onChange={(e) => setFlagFilter(e.target.value)}
                      className="ml-2 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-sky-500"
                    >
                      <option value="">All Audit Flags</option>
                      {AUDIT_FLAG_OPTIONS.map((f) => (
                        <option key={f} value={f}>
                          Flag: {f}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className="text-[11px] text-slate-400 hidden sm:inline">
                      Last sweep:{" "}
                      <strong className="text-slate-300 font-mono">
                        {formatTimestamp(
                          selectedSubnetContext.subnet.last_scanned_at
                        )}
                      </strong>
                      {selectedSubnetContext.subnet.last_scan_duration_ms
                        ? ` (${selectedSubnetContext.subnet.last_scan_duration_ms}ms)`
                        : ""}
                    </span>

                    <div className="relative w-64">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        value={ipSearchQuery}
                        onChange={(e) => setIpSearchQuery(e.target.value)}
                        placeholder="Search IP, host, owner, notes..."
                        className="w-full pl-8 pr-3 py-1 text-xs bg-slate-900 border border-slate-800 rounded-md text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Scannable IP Inventory Table */}
              <div className="flex-1 overflow-auto">
                <table className="w-full text-left border-collapse">
                  <thead className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    <tr>
                      <th className="py-2.5 px-4">IP Address &amp; Hostname</th>
                      <th className="py-2.5 px-3">Current Status</th>
                      <th className="py-2.5 px-3">IPAM Status &amp; Owner</th>
                      <th className="py-2.5 px-3">First / Last Seen Online</th>
                      <th className="py-2.5 px-3">Audit Flag &amp; Notes</th>
                      <th className="py-2.5 px-4 text-right">Audit Trail</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs">
                    {ipLoading ? (
                      <tr>
                        <td
                          colSpan={6}
                          className="py-12 text-center text-slate-400"
                        >
                          Loading IP inventory...
                        </td>
                      </tr>
                    ) : ipRecords.length === 0 ? (
                      <tr>
                        <td
                          colSpan={6}
                          className="py-12 text-center text-slate-500"
                        >
                          No IP records match the current filter criteria.
                        </td>
                      </tr>
                    ) : (
                      ipRecords.map((ip) => (
                        <tr
                          key={ip.id}
                          className="hover:bg-slate-900/60 transition group"
                        >
                          {/* IP Address & Hostname */}
                          <td className="py-2.5 px-4">
                            <div className="font-mono font-semibold text-slate-100">
                              {ip.ip_address}
                            </div>
                            <div className="text-[11px] text-slate-400 truncate max-w-[200px]">
                              {ip.hostname || "—"}
                            </div>
                          </td>

                          {/* Current Status */}
                          <td className="py-2.5 px-3">
                            <StatusBadge
                              status={ip.status}
                              rttMs={ip.response_time_ms}
                            />
                            {ip.status === "Offline" &&
                              ip.consecutive_offline_scans > 0 && (
                                <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                                  {ip.consecutive_offline_scans} missed sweep
                                  {ip.consecutive_offline_scans === 1 ? "" : "s"}
                                </div>
                              )}
                          </td>

                          {/* IPAM Allocation & Owner */}
                          <td className="py-2.5 px-3">
                            <div className="flex items-center gap-1.5">
                              <button
                                onClick={() => handleQuickIpamToggle(ip)}
                                className={`px-2 py-0.5 rounded text-[11px] font-medium border transition ${
                                  ip.ipam_allocated
                                    ? "bg-sky-500/15 text-sky-300 border-sky-500/30 hover:bg-sky-500/25"
                                    : "bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200"
                                }`}
                                title="Click to toggle IPAM allocation status"
                              >
                                {ip.ipam_allocated
                                  ? "IPAM Allocated"
                                  : "Unallocated"}
                              </button>
                            </div>
                            {ip.ipam_owner && (
                              <div className="text-[11px] text-slate-400 mt-0.5 truncate max-w-[160px]">
                                {ip.ipam_owner}
                              </div>
                            )}
                          </td>

                          {/* First / Last Seen Timestamps */}
                          <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                            <div>
                              <span className="text-slate-500">Last: </span>
                              {formatTimestamp(ip.last_seen_online_at)}
                            </div>
                            <div className="text-slate-400">
                              <span className="text-slate-500">First: </span>
                              {formatTimestamp(ip.first_seen_online_at)}
                            </div>
                          </td>

                          {/* Audit Flags & Operational Notes */}
                          <td className="py-2.5 px-3">
                            <div className="flex items-center gap-2">
                              <select
                                value={ip.audit_flag}
                                onChange={(e) =>
                                  handleQuickFlagChange(ip, e.target.value)
                                }
                                className="bg-slate-900 border border-slate-800 rounded px-2 py-0.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                              >
                                {AUDIT_FLAG_OPTIONS.map((opt) => (
                                  <option key={opt} value={opt}>
                                    {opt}
                                  </option>
                                ))}
                              </select>
                              <button
                                onClick={() => setEditingIpRecord(ip)}
                                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-sky-400 transition"
                                title="Edit hostname, IPAM owner, and operational audit notes"
                              >
                                <Edit3 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                            {ip.audit_notes && (
                              <p className="text-[11px] text-amber-300/90 mt-1 line-clamp-1 max-w-xs">
                                {ip.audit_notes}
                              </p>
                            )}
                          </td>

                          {/* State Transition History Button */}
                          <td className="py-2.5 px-4 text-right">
                            <button
                              onClick={() => openHistoryModal(ip.id)}
                              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 text-xs font-mono transition"
                            >
                              <History className="w-3.5 h-3.5 text-sky-400" />
                              <span>Logs ({ip.state_change_count})</span>
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-sm text-slate-500">
              Select a subnet from the left navigation tree or import a subnet
              scope to begin.
            </div>
          )}
        </main>
      </div>

      {/* MODAL 1: IP State Transition & Audit Event Log History */}
      {historyModalIp && (
        <AuditHistoryModal
          ipDetail={historyModalIp}
          onClose={() => setHistoryModalIp(null)}
        />
      )}

      {/* MODAL 2: Edit IP Audit Metadata (Hostname, IPAM Owner, Notes) */}
      {editingIpRecord && (
        <EditIpAuditModal
          ipRecord={editingIpRecord}
          onClose={() => setEditingIpRecord(null)}
          onSaved={() => {
            setEditingIpRecord(null);
            loadSubnetIps();
            loadTree();
            if (activeView === "report") loadUnusedReport();
            showToast("IP audit record saved.", "success");
          }}
        />
      )}

      {/* MODAL 3: Bulk Subnet Import (JSON / CSV / Single Entry) */}
      {showBulkModal && (
        <BulkImportModal
          sites={tree}
          initialTab={bulkModalInitialTab}
          initialSiteName={bulkModalInitialSite}
          onClose={() => setShowBulkModal(false)}
          onImported={(msg) => {
            setShowBulkModal(false);
            loadTree();
            showToast(msg, "success");
          }}
        />
      )}

      {/* MODAL 4: Subnet Automated Schedule Configuration */}
      {showScheduleModal && selectedSubnetContext && (
        <SubnetScheduleModal
          subnet={selectedSubnetContext.subnet}
          onClose={() => setShowScheduleModal(false)}
          onSaved={() => {
            setShowScheduleModal(false);
            loadTree();
            showToast("Subnet sweep schedule updated.", "success");
          }}
        />
      )}
    </div>
  );
}

/* ============================================================================
 * Dedicated Unused IP Report View (Per Scan Range — Never Responded to Ping)
 * ============================================================================ */
function UnusedIpReportPanel({
  subnetContext,
  reportItems,
  loading,
  onRefresh,
  onSelectIpHistory,
  onSwitchToInventory
}) {
  const { site, subnet } = subnetContext;

  return (
    <div className="flex-1 flex flex-col min-h-0">
      <div className="p-4 border-b border-slate-800 bg-slate-900/40 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <h1 className="text-base font-bold font-mono text-white">
              {subnet.cidr} — Unused IP Report
            </h1>
            <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {site.name}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
              {reportItems.length} Never Responded
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            {subnet.label} — Showing only IP addresses in this scan range that have never responded to a ping.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onSwitchToInventory}
            className="px-3 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 flex items-center gap-1.5"
          >
            <Server className="w-3.5 h-3.5 text-sky-400" />
            Full Subnet Inventory
          </button>

          <button
            onClick={onRefresh}
            className="px-3 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>

          <a
            href={api.getUnusedIpExportUrl("csv", {
              subnet_id: subnet.id
            })}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center gap-1.5 transition"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            Export CSV
          </a>

          <a
            href={api.getUnusedIpExportUrl("json", {
              subnet_id: subnet.id
            })}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-400 text-slate-950 flex items-center gap-1.5 transition"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </a>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-slate-900/95 border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            <tr>
              <th className="py-2.5 px-4">IP Address &amp; Hostname</th>
              <th className="py-2.5 px-3">Current Status</th>
              <th className="py-2.5 px-3">First / Last Seen Online</th>
              <th className="py-2.5 px-3">Audit Flag</th>
              <th className="py-2.5 px-3">Unused Status</th>
              <th className="py-2.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {loading ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-400">
                  Loading unused IP addresses for {subnet.cidr}...
                </td>
              </tr>
            ) : reportItems.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500">
                  Every IP in {subnet.cidr} has responded to a ping at least once.
                </td>
              </tr>
            ) : (
              reportItems.map((item) => (
                <tr key={item.ip_id} className="hover:bg-slate-900/60">
                  <td className="py-2.5 px-4">
                    <div className="font-mono font-semibold text-white">
                      {item.ip_address}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      {item.hostname || "—"}
                    </div>
                  </td>
                  <td className="py-2.5 px-3">
                    <StatusBadge status={item.status} />
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                    Never seen online
                  </td>
                  <td className="py-2.5 px-3">
                    <AuditFlagBadge flag={item.audit_flag} />
                  </td>
                  <td className="py-2.5 px-3 max-w-md">
                    <div className="text-amber-300 font-medium">
                      {item.classification_reason}
                    </div>
                    {item.audit_notes && (
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Note: {item.audit_notes}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      onClick={() => onSelectIpHistory(item.ip_id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-200"
                    >
                      <History className="w-3.5 h-3.5 text-sky-400" />
                      Audit Log
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ============================================================================
 * Modal: Lightweight Audit Log / State Transition History
 * ============================================================================ */
function AuditHistoryModal({ ipDetail, onClose }) {
  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden flex flex-col max-h-[82vh]">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2.5">
              <History className="w-4 h-4 text-sky-400" />
              <h2 className="text-sm font-bold font-mono text-white">
                {ipDetail.ip_address} — State Transition &amp; Audit History
              </h2>
              <StatusBadge
                status={ipDetail.status}
                rttMs={ipDetail.response_time_ms}
              />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Hostname: {ipDetail.hostname || "Unresolved"} • IPAM Owner:{" "}
              {ipDetail.ipam_owner || "Unassigned"}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto space-y-3">
          {ipDetail.audit_logs.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500">
              No state transitions or audit events recorded for this IP yet.
              Trigger a subnet sweep to log initial discovery.
            </div>
          ) : (
            ipDetail.audit_logs.map((log) => (
              <div
                key={log.id}
                className="p-3 rounded-lg border border-slate-800 bg-slate-950/70 flex items-start justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700">
                      {log.event_type}
                    </span>
                    {log.previous_status && (
                      <div className="flex items-center gap-1.5 font-mono text-xs">
                        <span className="text-slate-400">
                          {log.previous_status}
                        </span>
                        <ArrowRight className="w-3 h-3 text-slate-500" />
                        <span
                          className={
                            log.new_status === "Online"
                              ? "text-emerald-400 font-semibold"
                              : "text-rose-400 font-semibold"
                          }
                        >
                          {log.new_status}
                        </span>
                      </div>
                    )}
                  </div>
                  <p className="text-xs text-slate-200">{log.details}</p>
                </div>
                <div className="text-right font-mono text-[11px] text-slate-400 shrink-0">
                  {formatTimestamp(log.timestamp)}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

/* ============================================================================
 * Modal: Edit IP Record Audit Notes & IPAM Metadata
 * ============================================================================ */
function EditIpAuditModal({ ipRecord, onClose, onSaved }) {
  const [hostname, setHostname] = useState(ipRecord.hostname || "");
  const [ipamAllocated, setIpamAllocated] = useState(ipRecord.ipam_allocated);
  const [ipamOwner, setIpamOwner] = useState(ipRecord.ipam_owner || "");
  const [auditFlag, setAuditFlag] = useState(ipRecord.audit_flag);
  const [auditNotes, setAuditNotes] = useState(ipRecord.audit_notes || "");
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.updateIpRecord(ipRecord.id, {
        hostname: hostname.trim() || null,
        ipam_allocated: ipamAllocated,
        ipam_owner: ipamOwner.trim() || null,
        audit_flag: auditFlag,
        audit_notes: auditNotes.trim() || null
      });
      onSaved();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden"
      >
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold font-mono text-white">
            Audit IP Record — {ipRecord.ip_address}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1">DNS / Hostname</label>
            <input
              type="text"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="e.g. app-srv02.corp.local"
              className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>

          <div className="flex items-center justify-between py-1">
            <label className="text-slate-300 font-medium">
              Allocated in Corporate IPAM
            </label>
            <input
              type="checkbox"
              checked={ipamAllocated}
              onChange={(e) => setIpamAllocated(e.target.checked)}
              className="w-4 h-4 accent-sky-500"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">
              IPAM Owner / Department
            </label>
            <input
              type="text"
              value={ipamOwner}
              onChange={(e) => setIpamOwner(e.target.value)}
              placeholder="e.g. Core Infrastructure Team"
              className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Audit Flag</label>
            <select
              value={auditFlag}
              onChange={(e) => setAuditFlag(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            >
              {AUDIT_FLAG_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">
              Operational Audit Notes
            </label>
            <textarea
              rows={3}
              value={auditNotes}
              onChange={(e) => setAuditNotes(e.target.value)}
              placeholder="e.g. Expected decommissioned - investigate lingering ghost ARP/ICMP response"
              className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>
        </div>

        <div className="px-5 py-3 bg-slate-950/60 border-t border-slate-800 flex justify-end gap-2 text-xs">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className="px-4 py-1.5 rounded-lg font-semibold bg-sky-500 text-slate-950"
          >
            {saving ? "Saving..." : "Save Audit Changes"}
          </button>
        </div>
      </form>
    </div>
  );
}

/* ============================================================================
 * Modal: Bulk Subnet Import (JSON / CSV / Single Form)
 * ============================================================================ */
function BulkImportModal({
  initialTab = "json",
  initialSiteName = "",
  onClose,
  onImported
}) {
  const [tab, setTab] = useState(initialTab); // "json" | "csv" | "single"
  const [jsonText, setJsonText] = useState(SAMPLE_BULK_JSON);
  const [csvFile, setCsvFile] = useState(null);
  const [triggerScan, setTriggerScan] = useState(true);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  // Single Subnet Quick Form State
  const [siteName, setSiteName] = useState(
    initialSiteName || "Birmingham Office"
  );
  const [cidr, setCidr] = useState("127.0.0.0/29");
  const [label, setLabel] = useState("Localhost Loopback Verification Scope");
  const [vlanId, setVlanId] = useState("99");
  const [intervalHours, setIntervalHours] = useState("24");
  const [repeatScanEnabled, setRepeatScanEnabled] = useState(false);

  const handleImportSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      if (tab === "json") {
        const parsed = JSON.parse(jsonText);
        const subnetsArray = Array.isArray(parsed) ? parsed : parsed.subnets;
        const res = await api.bulkImportJson({
          subnets: subnetsArray,
          trigger_initial_scan: triggerScan
        });
        onImported(
          `Imported ${res.created_subnets} subnet(s) across ${res.created_sites} new site(s).`
        );
      } else if (tab === "csv") {
        if (!csvFile) {
          throw new Error("Please select a UTF-8 CSV file to upload.");
        }
        const res = await api.bulkImportCsv(csvFile, triggerScan);
        onImported(
          `CSV Import complete: ${res.created_subnets} subnet(s) created.`
        );
      } else {
        const res = await api.bulkImportJson({
          subnets: [
            {
              site_name: siteName,
              cidr,
              label,
              vlan_id: vlanId ? Number(vlanId) : null,
              scan_enabled: repeatScanEnabled,
              scan_interval_hours: Number(intervalHours) || 24
            }
          ],
          trigger_initial_scan: triggerScan
        });
        onImported(
          res.created_subnets > 0
            ? `Created subnet ${cidr} and populated host inventory.`
            : `Subnet ${cidr} already exists.`
        );
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <form
        onSubmit={handleImportSubmit}
        className="w-full max-w-xl rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden"
      >
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Upload className="w-4 h-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white">
              Bulk Subnet Import &amp; Scope Provisioning
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 pt-3 border-b border-slate-800 flex gap-2 text-xs">
          {[
            { id: "json", label: "Bulk JSON" },
            { id: "csv", label: "CSV Upload" },
            { id: "single", label: "Single Subnet Form" }
          ].map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`px-3 py-2 border-b-2 font-medium transition ${
                tab === t.id
                  ? "border-sky-400 text-sky-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-3 text-xs">
          {error && (
            <div className="p-2.5 rounded-lg bg-rose-950/90 border border-rose-800 text-rose-200">
              {error}
            </div>
          )}

          {tab === "json" && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-slate-400">
                  Paste JSON Array of Subnets
                </label>
                <button
                  type="button"
                  onClick={() => setJsonText(SAMPLE_BULK_JSON)}
                  className="text-sky-400 hover:underline"
                >
                  Reset Sample JSON
                </button>
              </div>
              <textarea
                rows={10}
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                className="w-full p-3 font-mono text-xs rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
              />
            </div>
          )}

          {tab === "csv" && (
            <div className="space-y-2">
              <p className="text-slate-400">
                Upload a CSV file with headers:{" "}
                <code className="text-sky-300 font-mono">
                  site_name,cidr,label,vlan_id,gateway_ip,scan_interval_hours,scan_cron_time
                </code>
              </p>
              <input
                type="file"
                accept=".csv,text/csv"
                onChange={(e) => setCsvFile(e.target.files?.[0] || null)}
                className="w-full p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200"
              />
            </div>
          )}

          {tab === "single" && (
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <label className="block text-slate-400 mb-1">Site Name</label>
                <input
                  type="text"
                  required
                  value={siteName}
                  onChange={(e) => setSiteName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">
                  CIDR Range (/20 to /32)
                </label>
                <input
                  type="text"
                  required
                  value={cidr}
                  onChange={(e) => setCidr(e.target.value)}
                  className="w-full px-3 py-1.5 font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">VLAN ID</label>
                <input
                  type="number"
                  value={vlanId}
                  onChange={(e) => setVlanId(e.target.value)}
                  className="w-full px-3 py-1.5 font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
                />
              </div>
              <div className="col-span-2">
                <label className="block text-slate-400 mb-1">
                  Subnet Description / Label
                </label>
                <input
                  type="text"
                  required
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">
                  Repeat Scan Interval (Hours)
                </label>
                <input
                  type="number"
                  min={1}
                  max={720}
                  value={intervalHours}
                  onChange={(e) => setIntervalHours(e.target.value)}
                  className="w-full px-3 py-1.5 font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
                />
              </div>
              <div className="flex items-end pb-1.5">
                <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={repeatScanEnabled}
                    onChange={(e) => setRepeatScanEnabled(e.target.checked)}
                    className="w-4 h-4 accent-sky-500"
                  />
                  <span>Enable Repeat Scan</span>
                </label>
              </div>
            </div>
          )}

          <label className="flex items-center gap-2 pt-2 text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={triggerScan}
              onChange={(e) => setTriggerScan(e.target.checked)}
              className="w-4 h-4 accent-sky-500"
            />
            <span>Immediately launch async ICMP sweep after import</span>
          </label>
        </div>

        <div className="px-5 py-3 bg-slate-950/60 border-t border-slate-800 flex justify-end gap-2 text-xs">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="px-4 py-1.5 rounded-lg font-semibold bg-sky-500 text-slate-950"
          >
            {submitting ? "Importing..." : "Import Subnets"}
          </button>
        </div>
      </form>
    </div>
  );
}

/* ============================================================================
 * Modal: Configure Automated Interval & Cron Sweep Schedule
 * ============================================================================ */
function SubnetScheduleModal({ subnet, onClose, onSaved }) {
  const [scanEnabled, setScanEnabled] = useState(subnet.scan_enabled);
  const [intervalHours, setIntervalHours] = useState(
    subnet.scan_interval_hours || 24
  );
  const [cronTime, setCronTime] = useState(subnet.scan_cron_time || "");
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.updateSubnet(subnet.id, {
        scan_enabled: scanEnabled,
        scan_interval_hours: Number(intervalHours) || 24,
        scan_cron_time: cronTime.trim() || null
      });
      onSaved();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden"
      >
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold text-white">
            Sweep Schedule — {subnet.cidr}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-3 text-xs">
          <label className="flex items-center justify-between">
            <span className="text-slate-300 font-medium">
              Enable Automated Repeat Scans
            </span>
            <input
              type="checkbox"
              checked={scanEnabled}
              onChange={(e) => setScanEnabled(e.target.checked)}
              className="w-4 h-4 accent-sky-500"
            />
          </label>

          <div>
            <label className="block text-slate-400 mb-1">
              Repeat Scan Interval (Hours)
            </label>
            <input
              type="number"
              min={1}
              max={720}
              value={intervalHours}
              onChange={(e) => setIntervalHours(e.target.value)}
              className="w-full px-3 py-1.5 font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">
              Optional Daily Cron Sweep Time (24h UTC HH:MM)
            </label>
            <input
              type="text"
              placeholder="e.g. 02:30"
              value={cronTime}
              onChange={(e) => setCronTime(e.target.value)}
              className="w-full px-3 py-1.5 font-mono rounded-lg bg-slate-950 border border-slate-800 text-slate-100"
            />
          </div>
        </div>

        <div className="px-5 py-3 bg-slate-950/60 border-t border-slate-800 flex justify-end gap-2 text-xs">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className="px-4 py-1.5 rounded-lg font-semibold bg-sky-500 text-slate-950"
          >
            {saving ? "Saving..." : "Save Schedule"}
          </button>
        </div>
      </form>
    </div>
  );
}
