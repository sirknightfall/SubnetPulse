const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(options.headers || {})
    },
    ...options
  });

  if (!response.ok) {
    let errorMessage = `Request failed (${response.status})`;
    try {
      const errorData = await response.json();
      if (typeof errorData.detail === "string") {
        errorMessage = errorData.detail;
      } else if (Array.isArray(errorData.detail)) {
        errorMessage = errorData.detail.map((e) => e.msg || JSON.stringify(e)).join("; ");
      }
    } catch {
      // Fallback to status text
    }
    throw new Error(errorMessage);
  }

  if (response.status === 204) {
    return null;
  }
  return response.json();
}

export const api = {
  getHealth: () => request("/health"),
  getTree: () => request("/tree"),
  createSite: (payload) =>
    request("/sites", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  deleteSite: (siteId) =>
    request(`/sites/${siteId}`, {
      method: "DELETE"
    }),
  createSubnet: (payload) =>
    request("/subnets", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  updateSubnet: (subnetId, payload) =>
    request(`/subnets/${subnetId}`, {
      method: "PATCH",
      body: JSON.stringify(payload)
    }),
  deleteSubnet: (subnetId) =>
    request(`/subnets/${subnetId}`, {
      method: "DELETE"
    }),
  triggerSubnetScan: (subnetId) =>
    request(`/subnets/${subnetId}/scan`, {
      method: "POST"
    }),
  clearSubnetHistory: (subnetId) =>
    request(`/subnets/${subnetId}/history`, {
      method: "DELETE"
    }),
  bulkImportJson: (payload) =>
    request("/subnets/bulk-import", {
      method: "POST",
      body: JSON.stringify(payload)
    }),
  bulkImportCsv: (file, triggerInitialScan = false) => {
    const formData = new FormData();
    formData.append("file", file);
    return request(`/subnets/bulk-import-csv?trigger_initial_scan=${triggerInitialScan}`, {
      method: "POST",
      body: formData
    });
  },
  getSubnetIps: (subnetId, filters = {}) => {
    const params = new URLSearchParams();
    if (filters.status) params.set("status", filters.status);
    if (filters.audit_flag) params.set("audit_flag", filters.audit_flag);
    if (filters.q) params.set("q", filters.q);
    const qs = params.toString();
    return request(`/subnets/${subnetId}/ips${qs ? `?${qs}` : ""}`);
  },
  getIpDetail: (ipId) => request(`/ips/${ipId}`),
  updateIpRecord: (ipId, payload) =>
    request(`/ips/${ipId}`, {
      method: "PATCH",
      body: JSON.stringify(payload)
    }),
  getUnusedIpReport: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.site_id) params.set("site_id", filters.site_id);
    if (filters.subnet_id) params.set("subnet_id", filters.subnet_id);
    const qs = params.toString();
    return request(`/reports/unused-ips${qs ? `?${qs}` : ""}`);
  },
  getUnusedIpExportUrl: (format = "csv", filters = {}) => {
    const params = new URLSearchParams({ format });
    if (filters.site_id) params.set("site_id", filters.site_id);
    if (filters.subnet_id) params.set("subnet_id", filters.subnet_id);
    return `${API_BASE}/reports/unused-ips/export?${params.toString()}`;
  }
};
