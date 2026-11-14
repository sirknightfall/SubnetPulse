const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";
const TOKEN_STORAGE_KEY = "subnetpulse_auth_token";
const USER_STORAGE_KEY = "subnetpulse_auth_user";
const API_KEY_STORAGE_KEY = "subnetpulse_api_key";

export function getStoredAuth() {
  try {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY) || "";
    const apiKey =
      localStorage.getItem(API_KEY_STORAGE_KEY) ||
      import.meta.env.VITE_API_KEY ||
      "";
    const rawUser = localStorage.getItem(USER_STORAGE_KEY);
    const user = rawUser ? JSON.parse(rawUser) : null;
    return { token, apiKey, user };
  } catch {
    return { token: "", apiKey: "", user: null };
  }
}

export function saveStoredAuth({ token = "", apiKey = "", user = null }) {
  try {
    if (token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
    if (apiKey) {
      localStorage.setItem(API_KEY_STORAGE_KEY, apiKey);
    } else {
      localStorage.removeItem(API_KEY_STORAGE_KEY);
    }
    if (user) {
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
    } else {
      localStorage.removeItem(USER_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors in restricted contexts
  }
}

export function clearStoredAuth() {
  saveStoredAuth({ token: "", apiKey: "", user: null });
}

function buildAuthHeaders(extraHeaders = {}) {
  const { token, apiKey } = getStoredAuth();
  const headers = { ...extraHeaders };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  return headers;
}

async function request(path, options = {}) {
  const defaultContentType =
    options.body instanceof FormData ? {} : { "Content-Type": "application/json" };

  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    ...options,
    headers: buildAuthHeaders({
      ...defaultContentType,
      ...(options.headers || {})
    })
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
    if (response.status === 401 && path !== "/auth/login") {
      window.dispatchEvent(new CustomEvent("subnetpulse:unauthorized"));
    }
    const err = new Error(errorMessage);
    err.status = response.status;
    throw err;
  }

  if (response.status === 204) {
    return null;
  }
  return response.json();
}

export const api = {
  getHealth: () => request("/health"),
  login: async (payload) => {
    const data = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    saveStoredAuth({
      token: data.access_token,
      apiKey: payload.api_key || "",
      user: { username: data.username, role: data.role }
    });
    return data;
  },
  logout: async () => {
    try {
      await request("/auth/logout", { method: "POST" });
    } finally {
      clearStoredAuth();
    }
  },
  getMe: () => request("/auth/me"),
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
  },
  downloadUnusedIpExport: async (format = "csv", filters = {}) => {
    const url = api.getUnusedIpExportUrl(format, filters);
    const response = await fetch(url, {
      credentials: "include",
      headers: buildAuthHeaders()
    });
    if (!response.ok) {
      throw new Error(`Export failed (${response.status})`);
    }
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/i);
    const filename = match ? match[1] : `subnetpulse_audit.${format}`;
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
  }
};
