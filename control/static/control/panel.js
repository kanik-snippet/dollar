(() => {
  "use strict";

  const app = document.getElementById("panel-app");
  const content = document.getElementById("panel-content");
  const pageTitle = document.getElementById("page-title");
  const breadcrumb = document.getElementById("page-breadcrumb");
  const refreshButton = document.getElementById("refresh-button");
  const syncLabel = document.getElementById("sync-label");
  const dialog = document.getElementById("detail-dialog");
  const detailTitle = document.getElementById("detail-title");
  const detailContent = document.getElementById("detail-content");

  const endpoints = {
    overview: app.dataset.overviewUrl,
    devices: app.dataset.devicesUrl,
    subadmins: app.dataset.subadminsUrl,
    domains: app.dataset.domainUrl,
    suspicious: app.dataset.suspiciousUrl,
    export: app.dataset.domainExportUrl,
    resource: app.dataset.resourceUrl,
  };
  const labels = {
    overview: ["Overview", "Operations overview"],
    domains: ["Domain activity", "Domain activity intelligence"],
    suspicious: ["Suspicious activity", "Monitored-domain alerts"],
    devices: ["Devices", "Devices and access"],
    subadmins: ["Sub-admin access", "Office, group and domain visibility"],
    configurations: ["Config bundles", "Configuration bundles"],
    groups: ["Browser groups", "Browser group mapping"],
    providers: ["Providers", "Proxy providers"],
    "proxy-catalog": ["Proxy catalog", "Country proxy catalog"],
    extensions: ["Extensions", "Managed extensions"],
    "proxy-pools": ["Proxy pools", "Proxy pool health"],
    "proxy-inventory": ["Proxy inventory", "Proxy inventory"],
    "proxy-jobs": ["Generation jobs", "Proxy generation jobs"],
    reservations: ["Reservations", "Proxy reservations"],
    "profile-activity": ["Profile activity", "Profile lifecycle activity"],
    "access-audit": ["Access audit", "Bootstrap access audit"],
  };
  const state = {
    route: "overview",
    resourcePage: 1,
    resourceQuery: "",
    auditCursor: "",
    auditCursorStack: [],
    auditFilters: { page_size: "25" },
    proxyFilters: { bundle: "", provider: "", country: "", status: "" },
    domainPage: 1,
    devicePage: 1,
    deviceFilters: { page_size: "25" },
    domainFilters: { range: "7d", sort: "last_seen", page_size: "25" },
  };

  const e = (value) => String(value ?? "").replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]),
  );
  const number = (value) => new Intl.NumberFormat("en-IN").format(Number(value || 0));
  const formatDate = (value) => {
    if (!value) return "?";
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return e(value);
    return new Intl.DateTimeFormat("en-IN", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    }).format(parsed);
  };
  const duration = (seconds) => {
    const total = Number(seconds || 0);
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const rest = total % 60;
    return [hours ? `${hours}h` : "", minutes ? `${minutes}m` : "", `${rest}s`]
      .filter(Boolean).join(" ");
  };
  const truncate = (value, length = 34) => {
    const text = String(value ?? "");
    return text.length > length ? `${text.slice(0, length)}?` : text;
  };
  const statusClass = (value) => {
    const text = String(value ?? "").toLowerCase();
    if (["true", "active", "available", "ready", "completed", "profile_opened", "allowed"].includes(text)) return "is-success";
    if (["false", "failed", "error", "denied", "inactive"].includes(text)) return "is-danger";
    if (["queued", "pending", "reserved", "generating", "partial"].includes(text)) return "is-warning";
    return "is-neutral";
  };
  const statusPill = (value) => {
    const label = typeof value === "boolean" ? (value ? "Yes" : "No") : (value || "Unknown");
    return `<span class="status-pill ${statusClass(value)}">${e(label)}</span>`;
  };

  async function api(url) {
    syncLabel.textContent = "Refreshing";
    const response = await fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (response.redirected && response.url.includes("login")) {
      window.location.assign(response.url);
      throw new Error("Session expired");
    }
    const type = response.headers.get("content-type") || "";
    if (!response.ok || !type.includes("application/json")) {
      throw new Error(`Request failed with status ${response.status}`);
    }
    const payload = await response.json();
    syncLabel.textContent = "Live data";
    return payload;
  }

  async function writeApi(url, payload) {
    syncLabel.textContent = "Saving";
    const csrf = document.querySelector("#panel-csrf-token input[name=csrfmiddlewaretoken]")?.value || "";
    const response = await fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { Accept: "application/json", "Content-Type": "application/json", "X-CSRFToken": csrf },
      body: JSON.stringify(payload),
    });
    if (response.redirected && response.url.includes("login")) { window.location.assign(response.url); throw new Error("Session expired"); }
    const data = await response.json().catch(() => ({}));
    syncLabel.textContent = response.ok && data.ok !== false ? "Saved" : "Save failed";
    if (!response.ok || data.ok === false) throw new Error(data.message || `Request failed with status ${response.status}`);
    return data;
  }
  function loading() {
    content.innerHTML = `
      <div class="loading-state">
        <div class="loading-line"></div>
        <div class="loading-grid">
          <div class="loading-card"></div><div class="loading-card"></div>
          <div class="loading-card"></div><div class="loading-card"></div>
        </div>
        <div class="loading-table"></div>
      </div>`;
  }

  function showError(error) {
    syncLabel.textContent = "Load failed";
    const template = document.getElementById("error-template");
    content.replaceChildren(template.content.cloneNode(true));
    content.querySelector("[data-retry]")?.addEventListener("click", loadCurrent);
    console.error(error);
  }

  function metricCard(label, value, note) {
    return `
      <article class="metric-card">
        <div class="metric-label">${e(label)}</div>
        <div class="metric-value">${number(value)}</div>
        <div class="metric-note">${e(note)}</div>
      </article>`;
  }

  function domainTable(rows, compact = false) {
    if (!rows.length) {
      return `<div class="empty-state"><h2>No domain activity found</h2><p>No records match the selected period and filters.</p></div>`;
    }
    return `
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr>
            <th>Domain</th><th>Device</th><th>Office</th><th>Profile</th>
            ${compact ? "" : "<th>Group</th><th>Session</th>"}
            <th>Visits</th><th>Last visited</th><th></th>
          </tr></thead>
          <tbody>
            ${rows.map((row) => `
              <tr>
                <td><span class="cell-primary">${e(row.domain)}</span></td>
                <td title="${e(row.device_id)}">
                  <span class="cell-primary">${e(row.client_name)}</span>
                  <div class="cell-muted">${e(row.ipv4)}</div>
                </td>
                <td>${e(row.office_name)} / sys_${e(row.system_number)}</td>
                <td title="${e(row.profile_id)}">
                  <span class="cell-primary">${e(row.profile_name || "Unnamed")}</span>
                  <div class="cell-muted mono">${e(truncate(row.profile_id, 22))}</div>
                </td>
                ${compact ? "" : `
                  <td><span class="mono">${e(row.group_id || "?")}</span></td>
                  <td><span class="mono">${e(truncate(row.session_id, 17))}</span></td>`}
                <td>${number(row.visit_count)}</td>
                <td>${formatDate(row.last_visited_at)}</td>
                <td><button class="link-button" data-domain-detail="${row.id}">Details</button></td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>`;
  }

  function bindDomainDetails() {
    content.querySelectorAll("[data-domain-detail]").forEach((button) => {
      button.addEventListener("click", () => showDomainDetail(button.dataset.domainDetail));
    });
  }

  async function loadOverview() {
    const data = await api(endpoints.overview);
    const jobs = Object.entries(data.job_status || {});
    const pools = Object.entries(data.pool_status || {});
    content.innerHTML = `
      <div class="page-intro">
        <div>
          <span class="eyebrow">Live control plane</span>
          <h2>Everything important, at a glance</h2>
          <p>Device authorization, profile execution, domain evidence and proxy capacity from the last 24 hours.</p>
        </div>
        <span class="cell-muted">Updated ${formatDate(data.generated_at)}</span>
      </div>
      <div class="metric-grid">
        ${metricCard("Active devices", data.cards.active_devices, `${number(data.cards.online_24h)} seen in 24 hours`)}
        ${metricCard("Profiles opened", data.cards.profiles_opened_24h, "Completed in the last 24 hours")}
        ${metricCard("Domain visits", data.cards.domain_visits_24h, `${number(data.cards.unique_domains_24h)} unique domains`)}
        ${metricCard("Available proxies", data.cards.available_proxies, "Ready in managed pools")}
        ${metricCard("Suspicious activity", data.cards.suspicious_activity_24h, "Monitored-domain matches")}
      </div>
      <div class="dashboard-grid">
        <div class="dashboard-stack">
          <article class="panel-card">
            <div class="panel-header">
              <div><h3>Recent domain activity</h3><p>Latest profile browsing evidence</p></div>
              <button class="link-button" data-go="domains">View all</button>
            </div>
            <div class="panel-body-flush">${domainTable(data.recent_domains, true)}</div>
          </article>
          <article class="panel-card">
            <div class="panel-header"><div><h3>Management</h3><p>Core configuration areas</p></div></div>
            <div class="panel-body management-grid">
              ${data.management.map((item) => `
                <button class="management-card" data-go="${e(item.key)}">
                  <div><strong>${e(item.label)}</strong><span>${e(item.description)}</span></div>
                  <strong>${number(item.count)}</strong>
                </button>`).join("")}
            </div>
          </article>
        </div>
        <div class="dashboard-stack">
          <article class="panel-card">
            <div class="panel-header"><div><h3>Offices</h3><p>Authorized device coverage</p></div></div>
            <div class="panel-body office-list">
              ${data.offices.length ? data.offices.map((office) => `
                <div class="office-row">
                  <div><strong>${e(office.office_name)}</strong><span>${number(office.active_devices)} active of ${number(office.devices)}</span></div>
                  <span>${office.last_seen_at ? formatDate(office.last_seen_at) : "Never seen"}</span>
                </div>`).join("") : "<div class='cell-muted'>No offices configured.</div>"}
            </div>
          </article>
          <article class="panel-card">
            <div class="panel-header"><div><h3>System health</h3><p>Jobs, inventory and access</p></div></div>
            <div class="panel-body status-list">
              ${jobs.map(([key, value]) => `<div class="status-row"><span>Jobs ? ${e(key)}</span><strong>${number(value)}</strong></div>`).join("") || "<div class='status-row'><span>Jobs</span><strong>0</strong></div>"}
              ${pools.map(([key, value]) => `<div class="status-row"><span>Proxies ? ${e(key)}</span><strong>${number(value)}</strong></div>`).join("")}
              <div class="status-row"><span>Access allowed ? 24h</span><strong>${number(data.bootstrap_status.allowed)}</strong></div>
              <div class="status-row"><span>Access denied ? 24h</span><strong>${number(data.bootstrap_status.denied)}</strong></div>
            </div>
          </article>
        </div>
      </div>`;
    bindDomainDetails();
    content.querySelectorAll("[data-go]").forEach((item) => {
      item.addEventListener("click", () => navigate(item.dataset.go));
    });
  }

  function domainParams() {
    const params = new URLSearchParams();
    Object.entries(state.domainFilters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    params.set("page", String(state.domainPage));
    return params;
  }

  function dateFilterOptions(filters) {
    return '<div class="field"><label>From date & time</label><input type="datetime-local" name="from" value="' + e(filters.from || "") + '"></div><div class="field"><label>To date & time</label><input type="datetime-local" name="to" value="' + e(filters.to || "") + '"></div>';
  }

  function filterOptions(data) {
    const filters = state.domainFilters;
    return `
      <div class="field field-wide"><label>Search everything</label><input name="q" value="${e(filters.q || "")}" placeholder="Domain, device, IP, profile or session"></div>
      <div class="field"><label>Office</label><select name="office"><option value="">All offices</option>
        ${data.options.offices.map((value) => `<option value="${e(value)}" ${filters.office === value ? "selected" : ""}>${e(value)}</option>`).join("")}
      </select></div>
      <div class="field"><label>Device</label><select name="client"><option value="">All devices</option>
        ${data.options.clients.map((row) => `<option value="${row.id}" ${String(filters.client || "") === String(row.id) ? "selected" : ""}>${e(row.office_name)} ? sys_${e(row.system_number)} ? ${e(row.name)}</option>`).join("")}
      </select></div>
      <div class="field"><label>Group</label><select name="group"><option value="">All groups</option>
        ${data.options.groups.map((value) => `<option value="${e(value)}" ${filters.group === value ? "selected" : ""}>${e(value)}</option>`).join("")}
      </select></div>
      <div class="field"><label>Domain contains</label><input name="domain" value="${e(filters.domain || "")}" placeholder="example.com"></div>
      ${dateFilterOptions(filters)}
      <div class="field"><label>Sort by</label><select name="sort">
        ${[["last_seen","Latest visit"],["visits","Most visits"],["domain","Domain A?Z"],["device","Device"],["first_seen","First visit"]].map(([value,label]) => `<option value="${value}" ${filters.sort === value ? "selected" : ""}>${label}</option>`).join("")}
      </select></div>
      <button class="button button-primary" type="submit">Apply filters</button>
      <button class="button button-secondary" type="button" data-clear-filters>Clear</button>`;
  }

  async function loadDomains() {
    const params = domainParams();
    const data = await api(`${endpoints.domains}?${params}`);
    const maxVisits = Math.max(1, ...data.top_domains.map((row) => Number(row.visits || 0)));
    content.innerHTML = `
      <div class="page-intro">
        <div>
          <span class="eyebrow">Audit intelligence</span>
          <h2>Domain activity</h2>
          <p>Precise domain-level evidence by office, device, profile, group and browser session. Query strings and sensitive URL paths are never stored here.</p>
        </div>
        <a class="button button-secondary" href="${endpoints.export}?${params}">Export CSV</a>
      </div>
      <div class="subnav" role="group" aria-label="Date range">
        ${[["24h","24 hours"],["7d","7 days"],["30d","30 days"],["90d","90 days"]].map(([value,label]) => `<button data-range="${value}" class="${state.domainFilters.range === value ? "is-active" : ""}">${label}</button>`).join("")}
      </div>
      <form class="toolbar" id="domain-filters">${filterOptions(data)}</form>
      <div class="metric-grid">
        ${metricCard("Total visits", data.metrics.visits, `${number(data.metrics.records)} stored records`)}
        ${metricCard("Unique domains", data.metrics.unique_domains, "Across the filtered period")}
        ${metricCard("Devices", data.metrics.devices, `${number(data.metrics.profiles)} profiles`)}
        ${metricCard("Profiles opened", data.metrics.profiles_opened_today, "Same last-24-hour count as Overview")}
        ${metricCard("Sessions", data.metrics.sessions, "Distinct browsing sessions")}
      </div>
      <div class="domain-layout">
        <article class="panel-card">
          <div class="panel-header"><div><h3>Activity records</h3><p>${number(data.pagination.total)} matching records</p></div></div>
          <div class="panel-body-flush">${domainTable(data.rows)}</div>
          ${pagination(data.pagination, "domains")}
        </article>
        <article class="panel-card">
          <div class="panel-header"><div><h3>Top domains</h3><p>Ranked by visits</p></div></div>
          <div class="panel-body ranking-list">
            ${data.top_domains.length ? data.top_domains.map((row) => `
              <div class="ranking-row">
                <div class="ranking-copy"><strong title="${e(row.domain)}">${e(row.domain)}</strong><span>${number(row.sessions)} sessions ? ${number(row.clients)} devices</span></div>
                <div class="ranking-value">${number(row.visits)}</div>
                <div class="ranking-bar"><span style="width:${Math.max(3, Math.round(Number(row.visits || 0) / maxVisits * 100))}%"></span></div>
              </div>`).join("") : "<div class='cell-muted'>No data in this period.</div>"}
          </div>
        </article>
      </div>`;
    bindDomainDetails();
    document.querySelectorAll("[data-range]").forEach((button) => {
      button.addEventListener("click", () => {
        state.domainFilters.range = button.dataset.range;
        delete state.domainFilters.from;
        delete state.domainFilters.to;
        state.domainPage = 1;
        loadCurrent();
      });
    });
    document.getElementById("domain-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      const values = new FormData(event.currentTarget);
      ["q", "office", "client", "group", "domain", "from", "to", "sort"].forEach((key) => {
        const value = String(values.get(key) || "").trim();
        if (value) state.domainFilters[key] = value;
        else delete state.domainFilters[key];
      });
      state.domainPage = 1;
      loadCurrent();
    });
    document.querySelectorAll("#domain-filters select, #domain-filters input[name=\"domain\"], #domain-filters input[name=\"from\"], #domain-filters input[name=\"to\"]").forEach((field) => {
      field.addEventListener("change", () => document.getElementById("domain-filters").requestSubmit());
    });
    content.querySelector("[data-clear-filters]").addEventListener("click", () => {
      state.domainFilters = { range: "7d", sort: "last_seen", page_size: "25" };
      state.domainPage = 1;
      loadCurrent();
    });
    bindPagination("domains");
  }

  function pagination(data, type) {
    const knownTotal = data.total !== null && data.total !== undefined;
    const pageLabel = knownTotal
      ? `Page ${number(data.page)} of ${number(data.pages)} · ${number(data.total)} records`
      : `Page ${number(data.page)} · more pages available`;
    return `
      <div class="pagination">
        <span>${pageLabel}</span>
        <div class="pagination-actions">
          <button class="button button-secondary" data-page-type="${type}" data-page="${data.page - 1}" ${data.has_previous ? "" : "disabled"}>Previous</button>
          <button class="button button-secondary" data-page-type="${type}" data-page="${data.page + 1}" ${data.has_next ? "" : "disabled"}>Next</button>
        </div>
      </div>`;
  }

  function bindPagination(type) {
    content.querySelectorAll(`[data-page-type="${type}"]`).forEach((button) => {
      button.addEventListener("click", () => {
        const value = Number(button.dataset.page);
        if (type === "domains" || type === "suspicious") state.domainPage = value;
        else if (type === "devices") state.devicePage = value;
        else state.resourcePage = value;
        loadCurrent();
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    });
  }

  function renderResourceCell(row, column) {
    const value = row[column.key];
    if (column.type === "date") return formatDate(value);
    if (column.type === "status") return statusPill(value);
    if (column.type === "action") return `<a class="link-button" href="${e(value)}">Manage</a>`;
    const mono = /(^id$|_id$|device_id|ipv4|exit_ip)/.test(column.key) ? " mono" : "";
    return `<span class="${mono}" title="${e(value)}">${e(value === "" || value == null ? "?" : truncate(value, 55))}</span>`;
  }

  function deviceParams() {
    const params = new URLSearchParams();
    Object.entries(state.deviceFilters).forEach(([key, value]) => { if (value) params.set(key, value); });
    params.set("page", String(state.devicePage));
    return params;
  }

  function closeManagementDialog(node) { if (node?.close) node.close(); else node?.removeAttribute("open"); }

  function openDeviceEditor(row) {
    const node = document.getElementById("device-dialog");
    const ips = [row.ipv4, ...(row.additional_ips || [])];
    node.innerHTML = `<div class="dialog-header"><div><span class="eyebrow">Device access</span><h2>Edit ${e(row.name)}</h2><p>${e(row.office)} / sys_${e(row.system)} · ${e(row.device_id || "No device ID")}</p></div><button type="button" class="dialog-close" data-management-close>Close</button></div><form class="management-form" id="device-edit-form"><div class="management-ip-list">${ips.map((ip, index) => `<div class="management-ip-row"><input name="ipv4" value="${e(ip)}" inputmode="numeric" required><span>${index ? "Additional" : "Primary"}</span>${index ? '<button type="button" class="link-button remove-management-ip">Remove</button>' : ""}</div>`).join("")}</div><button type="button" class="button button-secondary" id="add-management-ip">+ Add another IP</button><div class="dialog-actions"><button type="button" class="button button-secondary" data-management-close>Cancel</button><button class="button button-primary" type="submit">Save IP access</button></div></form>`;
    node.showModal ? node.showModal() : node.setAttribute("open", "");
    node.querySelectorAll("[data-management-close]").forEach((button) => button.addEventListener("click", () => closeManagementDialog(node)));
    node.querySelectorAll(".remove-management-ip").forEach((button) => button.addEventListener("click", () => button.closest(".management-ip-row").remove()));
    node.querySelector("#add-management-ip").addEventListener("click", () => {
      const rowNode = document.createElement("div"); rowNode.className = "management-ip-row";
      rowNode.innerHTML = '<input name="ipv4" inputmode="numeric" placeholder="203.0.113.11"><span>Additional</span><button type="button" class="link-button remove-management-ip">Remove</button>';
      rowNode.querySelector(".remove-management-ip").addEventListener("click", () => rowNode.remove());
      node.querySelector(".management-ip-list").appendChild(rowNode);
    });
    node.querySelector("#device-edit-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      try { await writeApi(endpoints.devices, { action: "update_ips", client_id: row.id, ipv4: [...event.currentTarget.querySelectorAll('input[name="ipv4"]')].map((input) => input.value) }); closeManagementDialog(node); await loadDevices(); }
      catch (error) { node.querySelector(".management-form").insertAdjacentHTML("afterbegin", `<div class="form-error">${e(error.message)}</div>`); }
    });
  }

  function openBulkDeviceEditor(data) {
    const node = document.getElementById("device-dialog");
    node.innerHTML = `<div class="dialog-header"><div><span class="eyebrow">Office-wide update</span><h2>Change IP access for an office</h2><p>Every device in the office will receive the same primary and optional additional IPs.</p></div><button type="button" class="dialog-close" data-management-close>Close</button></div><form class="management-form" id="bulk-device-form"><label>Office<select name="office" required><option value="">Choose office</option>${data.offices.map((office) => `<option value="${e(office)}">${e(office)}</option>`).join("")}</select></label><div class="management-ip-list"><div class="management-ip-row"><input name="ipv4" placeholder="203.0.113.10" required><span>Primary</span></div><div class="management-ip-row"><input name="ipv4" placeholder="203.0.113.11"><span>Additional</span></div></div><button type="button" class="button button-secondary" id="add-bulk-ip">+ Add another IP</button><div class="dialog-actions"><button type="button" class="button button-secondary" data-management-close>Cancel</button><button class="button button-primary" type="submit">Save office IPs</button></div></form>`;
    node.showModal ? node.showModal() : node.setAttribute("open", "");
    node.querySelectorAll("[data-management-close]").forEach((button) => button.addEventListener("click", () => closeManagementDialog(node)));
    node.querySelector("#add-bulk-ip").addEventListener("click", () => {
      const rowNode = document.createElement("div"); rowNode.className = "management-ip-row";
      rowNode.innerHTML = '<input name="ipv4" inputmode="numeric" placeholder="203.0.113.12"><span>Additional</span><button type="button" class="link-button remove-management-ip">Remove</button>';
      rowNode.querySelector(".remove-management-ip").addEventListener("click", () => rowNode.remove());
      node.querySelector(".management-ip-list").appendChild(rowNode);
    });
    node.querySelector("#bulk-device-form").addEventListener("submit", async (event) => {
      event.preventDefault(); const form = event.currentTarget;
      try { await writeApi(endpoints.devices, { action: "bulk_office", office: form.office.value, ipv4: [...form.querySelectorAll('input[name="ipv4"]')].map((input) => input.value) }); closeManagementDialog(node); await loadDevices(); }
      catch (error) { form.insertAdjacentHTML("afterbegin", `<div class="form-error">${e(error.message)}</div>`); }
    });
  }

  async function loadDevices() {
    const data = await api(`${endpoints.devices}?${deviceParams()}`);
    content.innerHTML = `<div class="page-intro"><div><span class="eyebrow">Access management</span><h2>Devices and IP access</h2><p>Manage every authorized device, its office, profile identity, group assignment and allowed public IPs.</p></div><button class="button button-primary" id="bulk-office-button">Bulk office IPs</button></div><form class="toolbar" id="device-filters"><div class="field field-wide"><label>Search</label><input name="q" value="${e(state.deviceFilters.q || "")}" placeholder="Device, system, IP or device ID"></div><div class="field"><label>Office</label><select name="office"><option value="">All offices</option>${data.offices.map((office) => `<option value="${e(office)}" ${state.deviceFilters.office === office ? "selected" : ""}>${e(office)}</option>`).join("")}</select></div><div class="field"><label>Access</label><select name="active"><option value="">All</option><option value="1" ${state.deviceFilters.active === "1" ? "selected" : ""}>Enabled</option><option value="0" ${state.deviceFilters.active === "0" ? "selected" : ""}>Disabled</option></select></div>${dateFilterOptions(state.deviceFilters)}<button class="button button-primary" type="submit">Apply filters</button><button class="button button-secondary" type="button" id="clear-device-filters">Clear</button></form><div class="metric-grid">${metricCard("Matching devices", data.metrics.total, "Current filters")}${metricCard("Enabled", data.metrics.active, "Access allowed")}${metricCard("Seen before", data.metrics.seen, "Have a last-seen timestamp")}</div><article class="panel-card"><div class="panel-header"><div><h3>Device registry</h3><p>${number(data.pagination.total)} matching devices</p></div></div><div class="panel-body-flush"><div class="table-wrap"><table class="data-table management-table"><thead><tr><th>Office / system</th><th>Device</th><th>Profile / group</th><th>Allowed IPs</th><th>Access</th><th>Last seen</th><th></th></tr></thead><tbody>${data.rows.length ? data.rows.map((row) => `<tr><td><span class="cell-primary">${e(row.office)}</span><div class="cell-muted">sys_${e(row.system)}</div></td><td><span class="cell-primary">${e(row.name)}</span><div class="cell-muted mono">${e(row.device_id || "No device ID")}</div></td><td><span class="cell-primary">${e(row.profile_name)}</span><div class="cell-muted">${e(row.group_name)} · ${e(row.group_id || "No group ID")}</div></td><td><span class="mono">${[row.ipv4, ...(row.additional_ips || [])].map(e).join("<br>")}</span></td><td><button class="status-pill ${row.active ? "is-success" : "is-danger"}" data-device-toggle="${row.id}" data-active="${row.active ? "0" : "1"}">${row.active ? "Enabled" : "Disabled"}</button></td><td>${row.last_seen ? formatDate(row.last_seen) : "Never"}</td><td><button class="link-button" data-device-edit="${row.id}">Edit IPs</button></td></tr>`).join("") : '<tr><td colspan="7" class="empty-state">No devices found.</td></tr>'}</tbody></table></div></div>${pagination(data.pagination, "devices")}</article>`;
    document.getElementById("bulk-office-button").addEventListener("click", () => openBulkDeviceEditor(data));
    document.querySelectorAll("[data-device-edit]").forEach((button) => button.addEventListener("click", () => openDeviceEditor(data.rows.find((row) => String(row.id) === button.dataset.deviceEdit))));
    document.querySelectorAll("[data-device-toggle]").forEach((button) => button.addEventListener("click", async () => { try { await writeApi(endpoints.devices, { action: "toggle", client_id: button.dataset.deviceToggle, active: button.dataset.active === "1" }); await loadDevices(); } catch (error) { showError(error); } }));
    document.getElementById("device-filters").addEventListener("submit", (event) => { event.preventDefault(); const values = new FormData(event.currentTarget); ["q", "office", "active", "from", "to"].forEach((key) => { const value = String(values.get(key) || "").trim(); if (value) state.deviceFilters[key] = value; else delete state.deviceFilters[key]; }); state.devicePage = 1; loadCurrent(); });
    document.getElementById("clear-device-filters").addEventListener("click", () => { state.deviceFilters = { page_size: "25" }; state.devicePage = 1; loadCurrent(); });
    bindPagination("devices");
  }

  async function loadSubadmins() {
    const data = await api(endpoints.subadmins);
    content.innerHTML = `<div class="page-intro"><div><span class="eyebrow">Visibility management</span><h2>Sub-admin access</h2><p>Choose exactly which offices, browser groups and monitored domains each sub-admin can see.</p></div></div>${data.accounts.length ? `<div class="subadmin-management-grid"><article class="panel-card"><div class="panel-header"><div><h3>Accounts</h3><p>Select an account to manage</p></div></div><div class="panel-body subadmin-account-list">${data.accounts.map((account, index) => `<button class="subadmin-account ${index === 0 ? "is-active" : ""}" data-subadmin-account="${account.id}"><strong>${e(account.display_name)}</strong><span>${e(account.username)} · ${account.active ? "Active" : "Disabled"}</span></button>`).join("")}</div></article><article class="panel-card"><div class="panel-header"><div><h3 id="subadmin-editor-title">Visibility rules</h3><p>Excluded scopes are hidden from this account.</p></div></div><div class="panel-body" id="subadmin-editor"></div></article></div>` : '<div class="empty-state"><h2>No sub-admin accounts</h2><p>Create a Sub-admin account first.</p></div>'}`;
    if (!data.accounts.length) return;
    const editor = document.getElementById("subadmin-editor");
    const render = (account) => { editor.innerHTML = `<form id="subadmin-form" class="subadmin-visibility-form"><label class="check-line"><input type="checkbox" name="active" ${account.active ? "checked" : ""}> Account active</label><div class="visibility-section"><h4>Exclude offices</h4><div class="check-grid">${data.office_options.map((office) => `<label class="check-line"><input type="checkbox" name="excluded_offices" value="${e(office)}" ${account.excluded_offices.includes(office.toLowerCase()) ? "checked" : ""}> ${e(office)}</label>`).join("")}</div></div><div class="visibility-section"><h4>Exclude browser groups</h4><div class="check-grid">${data.group_options.map((group) => `<label class="check-line"><input type="checkbox" name="excluded_groups" value="${e(group.browser_group_id)}" ${account.excluded_groups.includes(String(group.browser_group_id).toLowerCase()) ? "checked" : ""}> ${e(group.browser_group_name)} · ${e(group.browser_group_id)}</label>`).join("")}</div></div><div class="visibility-section"><h4>Exclude domains</h4><textarea name="excluded_domains" rows="5" placeholder="one-domain.com per line">${e(account.excluded_domains.join("\n"))}</textarea></div><button class="button button-primary" type="submit">Save visibility</button></form>`; editor.querySelector("#subadmin-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; try { await writeApi(endpoints.subadmins, { account_id: account.id, active: form.active.checked, excluded_offices: [...form.querySelectorAll('[name="excluded_offices"]:checked')].map((input) => input.value), excluded_groups: [...form.querySelectorAll('[name="excluded_groups"]:checked')].map((input) => input.value), excluded_domains: form.excluded_domains.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) }); await loadSubadmins(); } catch (error) { editor.insertAdjacentHTML("afterbegin", `<div class="form-error">${e(error.message)}</div>`); } }); };
    data.accounts.forEach((account) => document.querySelector(`[data-subadmin-account="${account.id}"]`).addEventListener("click", () => { document.querySelectorAll(".subadmin-account").forEach((item) => item.classList.remove("is-active")); document.querySelector(`[data-subadmin-account="${account.id}"]`).classList.add("is-active"); render(account); }));
    render(data.accounts[0]);
  }

  function proxyPoolParams() {
    const params = new URLSearchParams({
      page: String(state.resourcePage),
      page_size: "25",
      q: state.resourceQuery,
    });
    Object.entries(state.proxyFilters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    return params;
  }

  async function loadProxyPools() {
    const url = endpoints.resource.replace("__resource__", "proxy-pools");
    const data = await api(`${url}?${proxyPoolParams()}`);
    const bundles = data.options?.bundles || [];
    const providers = data.options?.providers || [];
    const countries = data.options?.countries || [];
    const selected = state.proxyFilters;
    const generationOffices = data.options?.generation_offices || [];
    const generationCountries = data.options?.generation_countries || [];
    const generationProviders = data.options?.generation_providers || ["P1", "P2", "P3"];
    const generationCard = `<article class="panel-card"><div class="panel-header"><div><h3>Generate inventory for an office</h3><p>Creates or refills the selected provider/country target for every active bundle assigned to the office. P1 is the default.</p></div></div><div class="panel-body"><form class="toolbar proxy-pool-toolbar" id="office-proxy-generator"><div class="field field-wide"><label>Office</label><select name="office" required><option value="">Choose office</option>${generationOffices.map((office) => `<option value="${e(office)}">${e(office)}</option>`).join("")}</select></div><div class="field"><label>Provider</label><select name="provider" required>${generationProviders.map((value) => `<option value="${e(value)}" ${value === "P1" ? "selected" : ""}>${e(value)}</option>`).join("")}</select></div><div class="field field-wide"><label>Country</label><select name="country" required><option value="">Choose country</option>${generationCountries.map((item) => `<option value="${e(item.code)}">${e(item.name)} (${e(item.code)})</option>`).join("")}</select></div><div class="field"><label>Target per bundle</label><input type="number" name="target_count" value="1000" min="1" max="5000" required></div><button class="button button-primary" type="submit">Generate for all bundles</button></form><div id="office-proxy-result" class="cell-muted"></div></div></article>`;
    const poolRows = data.rows.map((row) => {
      const availabilityClass = Number(row.available) === 0 ? "is-danger" : Number(row.available) <= Number(row.threshold || 200) ? "is-warning" : "is-success";
      const controls = row.active
        ? `<button class="link-button" data-proxy-action="refill" data-target-id="${e(row.target_id)}">Refill</button><button class="link-button" data-proxy-action="pause" data-target-id="${e(row.target_id)}">Pause</button><button class="link-button danger-link" data-proxy-action="clear" data-target-id="${e(row.target_id)}">Clear & pause</button>`
        : `<button class="link-button" data-proxy-action="resume" data-target-id="${e(row.target_id)}">Resume</button>`;
      return `<tr><td><span class="cell-primary">${e(row.config)}</span><div class="cell-muted">${e(row.group_name || "Group") } · ${e(row.group_id || "-")}</div></td><td>${e(row.provider)}</td><td><span class="cell-primary">${e(row.country)}</span><div class="cell-muted">${e(row.location)}</div></td><td><span class="status-pill ${availabilityClass}">${number(row.available)}</span><div class="cell-muted">target ${number(row.target)} · refill below ${number(row.threshold)}</div></td><td>${number(row.reserved)}</td><td>${row.refill_pending ? '<span class="status-pill is-warning">Queued</span>' : row.active ? '<span class="status-pill is-success">Active</span>' : '<span class="status-pill is-danger">Paused</span>'}</td><td class="proxy-actions">${controls}<a class="link-button" href="${e(row.admin_url)}">Admin</a></td></tr>`;
    }).join("");
    const metricScope = e(data.metrics.scope || "matching targets");
    content.innerHTML = `<div class="page-intro"><div><span class="eyebrow">Infrastructure</span><h2>Proxy pool manager</h2><p>Track every bundle/group, provider and country. Refill, pause or clear a specific pool without terminal commands.</p></div><a class="button button-secondary" href="${e(data.admin_url)}">Django Admin</a></div><form class="toolbar proxy-pool-toolbar" id="proxy-pool-filters"><div class="field field-wide"><label>Search</label><input name="q" value="${e(state.resourceQuery)}" placeholder="Bundle, group, provider or country"></div><div class="field"><label>Bundle / group</label><select name="bundle"><option value="">All bundles</option>${bundles.map((bundle) => `<option value="${e(bundle.id)}" ${String(selected.bundle) === String(bundle.id) ? "selected" : ""}>${e(bundle.name)} · ${e(bundle.browser_group_id || "-")}</option>`).join("")}</select></div><div class="field"><label>Provider</label><select name="provider"><option value="">All providers</option>${providers.map((value) => `<option value="${e(value)}" ${selected.provider === value ? "selected" : ""}>${e(value)}</option>`).join("")}</select></div><div class="field"><label>Country</label><select name="country"><option value="">All countries</option>${countries.map((value) => `<option value="${e(value)}" ${selected.country === value ? "selected" : ""}>${e(value)}</option>`).join("")}</select></div><div class="field"><label>Stock</label><select name="status"><option value="">All</option><option value="empty" ${selected.status === "empty" ? "selected" : ""}>Empty (0)</option><option value="low" ${selected.status === "low" ? "selected" : ""}>Low (≤200)</option><option value="ready" ${selected.status === "ready" ? "selected" : ""}>Ready (&gt;200)</option></select></div><button class="button button-primary" type="submit">Apply filters</button><button class="button button-secondary" type="button" id="clear-proxy-filters">Clear</button></form><div class="metric-grid">${metricCard("Pool targets", data.metrics.total, metricScope)}${metricCard("Low stock", data.metrics.low, "Visible rows at or below threshold")}${metricCard("Empty pools", data.metrics.empty, "Visible rows with no available proxy")}${metricCard("Available proxies", data.metrics.available, "Visible rows")}</div><article class="panel-card"><div class="panel-header"><div><h3>Pool inventory</h3><p>${data.pagination.total === null || data.pagination.total === undefined ? "Showing the current page · use filters to narrow results" : `${number(data.pagination.total)} matching targets`} · clear only affects unreserved entries</p></div></div><div class="panel-body-flush"><div class="table-wrap"><table class="data-table management-table proxy-pool-table"><thead><tr><th>Bundle / group</th><th>Provider</th><th>Country / location</th><th>Available</th><th>Reserved</th><th>Status</th><th>Actions</th></tr></thead><tbody>${poolRows || '<tr><td colspan="7" class="empty-state">No proxy pools match these filters.</td></tr>'}</tbody></table></div></div>${pagination(data.pagination, "resource")}</article>`;
    content.querySelector(".page-intro").insertAdjacentHTML("afterend", generationCard);
    document.getElementById("office-proxy-generator").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const button = form.querySelector('button[type="submit"]');
      const result = document.getElementById("office-proxy-result");
      const values = new FormData(form);
      button.disabled = true;
      result.textContent = "Creating targets and queueing manual generation...";
      try {
        const response = await writeApi(url, {
          action: "generate_office",
          office: String(values.get("office") || ""),
          provider: String(values.get("provider") || "P1"),
          country: String(values.get("country") || ""),
          target_count: Number(values.get("target_count") || 1000),
        });
        result.innerHTML = `<span class="status-pill is-success">Queued</span> ${e(response.message)}`;
      } catch (error) {
        result.innerHTML = `<span class="status-pill is-danger">Failed</span> ${e(error.message)}`;
      } finally {
        button.disabled = false;
      }
    });
    document.getElementById("proxy-pool-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      const values = new FormData(event.currentTarget);
      state.resourceQuery = String(values.get("q") || "").trim();
      state.proxyFilters = {
        bundle: String(values.get("bundle") || ""),
        provider: String(values.get("provider") || ""),
        country: String(values.get("country") || ""),
        status: String(values.get("status") || ""),
      };
      state.resourcePage = 1;
      loadProxyPools();
    });
    document.getElementById("clear-proxy-filters").addEventListener("click", () => {
      state.resourceQuery = "";
      state.proxyFilters = { bundle: "", provider: "", country: "", status: "" };
      state.resourcePage = 1;
      loadProxyPools();
    });
    document.querySelectorAll("[data-proxy-action]").forEach((button) => button.addEventListener("click", async () => {
      const action = button.dataset.proxyAction;
      if (action === "clear" && !window.confirm("Clear all available proxies for this target and pause it? Reserved proxies will be kept.")) return;
      try {
        await writeApi(url, { action, target_id: button.dataset.targetId });
        await loadProxyPools();
      } catch (error) { showError(error); }
    }));
    bindPagination("resource");
  }

  function auditParams() {
    const params = new URLSearchParams();
    Object.entries(state.auditFilters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    if (state.auditCursor) params.set("cursor", state.auditCursor);
    return params;
  }

  function openAuditGrant(row, data) {
    const node = document.getElementById("device-dialog");
    const ips = [...new Set([row.reported_ip, row.observed_ip].filter(Boolean))];
    const existing = Boolean(row.client_id);
    node.innerHTML = `<div class="dialog-header"><div><span class="eyebrow">Bootstrap authorization</span><h2>Grant device access</h2><p class="mono">${e(row.device_id)}</p></div><button type="button" class="dialog-close" data-management-close>Close</button></div><form class="management-form" id="audit-grant-form"><label>Authorized IPv4<select name="ipv4" required>${ips.map((ip) => `<option value="${e(ip)}">${e(ip)}</option>`).join("")}</select></label>${existing ? `<div class="detail-field"><span>Existing client</span><strong>${e(row.client)}</strong><small>The selected IP will be enabled as an additional address when it differs from the primary IP.</small></div>` : `<label>Device name<input name="name" value="Device ${e(String(row.device_id).slice(0, 12))}" required></label><label>Office<input name="office" required></label><label>System number<input name="system_number" required></label><label>Profile name<input name="profile_name" placeholder="Defaults to device name"></label><label>Configuration bundle<select name="config_bundle_id" required><option value="">Choose bundle</option>${data.configurations.map((item) => `<option value="${item.id}">${e(item.name)} · ${e(item.browser_group_name)} · ${e(item.browser_group_id || "-")}</option>`).join("")}</select></label>`}<div class="dialog-actions"><button type="button" class="button button-secondary" data-management-close>Cancel</button><button type="submit" class="button button-primary">Grant access</button></div></form>`;
    node.showModal ? node.showModal() : node.setAttribute("open", "");
    node.querySelectorAll("[data-management-close]").forEach((button) => button.addEventListener("click", () => closeManagementDialog(node)));
    node.querySelector("#audit-grant-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const values = new FormData(form);
      try {
        await writeApi(endpoints.resource.replace("__resource__", "access-audit"), {
          action: "grant_access", audit_id: row.id,
          ipv4: values.get("ipv4"), name: values.get("name"),
          office: values.get("office"), system_number: values.get("system_number"),
          profile_name: values.get("profile_name"),
          config_bundle_id: values.get("config_bundle_id"),
        });
        closeManagementDialog(node);
        await loadAccessAudit();
      } catch (error) {
        form.querySelector(".form-error")?.remove();
        form.insertAdjacentHTML("afterbegin", `<div class="form-error">${e(error.message)}</div>`);
      }
    });
  }

  async function loadAccessAudit() {
    const url = endpoints.resource.replace("__resource__", "access-audit");
    const data = await api(`${url}?${auditParams()}`);
    const filters = state.auditFilters;
    const rows = data.rows.map((row) => `<tr><td>${formatDate(row.created_at)}</td><td><span class="cell-primary">${e(row.client)}</span><div class="cell-muted mono">${e(row.device_id || "No device ID")}</div></td><td><span class="mono">${e(row.observed_ip || "-")}</span><div class="cell-muted mono">reported ${e(row.reported_ip || "-")}</div></td><td>${statusPill(row.allowed)}</td><td><span class="cell-primary">${e(row.reason)}</span><div class="cell-muted">v${e(row.version || "-")}</div></td><td class="proxy-actions">${row.can_grant ? `<button class="link-button" data-audit-grant="${row.id}">${row.client_id ? "Update access" : "Grant access"}</button>` : ""}<a class="link-button" href="${e(row.admin_url)}">Admin</a></td></tr>`).join("");
    content.innerHTML = `<div class="page-intro"><div><span class="eyebrow">Authorization evidence</span><h2>Bootstrap access audit</h2><p>Fast cursor-based audit history. Grant or update device access directly from a recorded bootstrap hit.</p></div><a class="button button-secondary" href="${e(data.admin_url)}">Django Admin</a></div><form class="toolbar" id="audit-filters"><div class="field field-wide"><label>Exact IP/device or text</label><input name="q" value="${e(filters.q || "")}" placeholder="IPv4, full device ID, client or reason"></div><div class="field"><label>Decision</label><select name="allowed"><option value="">All</option><option value="1" ${filters.allowed === "1" ? "selected" : ""}>Allowed</option><option value="0" ${filters.allowed === "0" ? "selected" : ""}>Denied</option></select></div>${dateFilterOptions(filters)}<button class="button button-primary" type="submit">Apply filters</button><button class="button button-secondary" type="button" id="clear-audit-filters">Clear</button></form><article class="panel-card"><div class="panel-header"><div><h3>Access decisions</h3><p>Newest matching records · no million-row count query</p></div></div><div class="panel-body-flush"><div class="table-wrap"><table class="data-table management-table"><thead><tr><th>Time</th><th>Client / device</th><th>Observed / reported IP</th><th>Allowed</th><th>Reason / version</th><th>Action</th></tr></thead><tbody>${rows || '<tr><td colspan="6" class="empty-state">No audit records match these filters.</td></tr>'}</tbody></table></div></div><div class="pagination"><button class="button button-secondary" id="audit-previous" ${data.pagination.has_previous ? "" : "disabled"}>Previous</button><span>Cursor page ${state.auditCursorStack.length + 1}</span><button class="button button-secondary" id="audit-next" ${data.pagination.has_next ? "" : "disabled"}>Next</button></div></article>`;
    document.querySelectorAll("[data-audit-grant]").forEach((button) => button.addEventListener("click", () => openAuditGrant(data.rows.find((row) => String(row.id) === button.dataset.auditGrant), data)));
    document.getElementById("audit-filters").addEventListener("submit", (event) => {
      event.preventDefault(); const values = new FormData(event.currentTarget);
      ["q", "allowed", "from", "to"].forEach((key) => { const value = String(values.get(key) || "").trim(); if (value) state.auditFilters[key] = value; else delete state.auditFilters[key]; });
      state.auditCursor = ""; state.auditCursorStack = []; loadAccessAudit();
    });
    document.getElementById("clear-audit-filters").addEventListener("click", () => { state.auditFilters = { page_size: "25" }; state.auditCursor = ""; state.auditCursorStack = []; loadAccessAudit(); });
    document.getElementById("audit-next").addEventListener("click", () => { if (!data.pagination.next_cursor) return; state.auditCursorStack.push(state.auditCursor); state.auditCursor = String(data.pagination.next_cursor); loadAccessAudit(); window.scrollTo({ top: 0, behavior: "smooth" }); });
    document.getElementById("audit-previous").addEventListener("click", () => { if (!state.auditCursorStack.length) return; state.auditCursor = state.auditCursorStack.pop() || ""; loadAccessAudit(); window.scrollTo({ top: 0, behavior: "smooth" }); });
  }

  async function loadResource() {
    if (state.route === "proxy-pools") {
      await loadProxyPools();
      return;
    }
    if (state.route === "access-audit") {
      await loadAccessAudit();
      return;
    }
    const url = endpoints.resource.replace("__resource__", encodeURIComponent(state.route));
    const params = new URLSearchParams({
      page: String(state.resourcePage),
      page_size: "25",
      q: state.resourceQuery,
    });
    const data = await api(`${url}?${params}`);
    content.innerHTML = `
      <div class="resource-header">
        <div>
          <span class="eyebrow">Management</span>
          <h2>${e(data.title)}</h2>
          <p>${e(data.description)}</p>
        </div>
        <div class="resource-actions">
          <input class="search-input" id="resource-search" value="${e(state.resourceQuery)}" placeholder="Search this section">
          <button class="button button-secondary" id="resource-search-button">Search</button>
          <a class="button button-primary" href="${e(data.admin_url)}">Manage in Admin</a>
        </div>
      </div>
      <article class="panel-card">
        <div class="panel-header"><div><h3>Records</h3><p>${number(data.pagination.total)} total</p></div></div>
        <div class="panel-body-flush">
          ${data.rows.length ? `
            <div class="table-wrap"><table class="data-table">
              <thead><tr>${data.columns.map((column) => `<th>${e(column.label)}</th>`).join("")}</tr></thead>
              <tbody>${data.rows.map((row) => `<tr>${data.columns.map((column) => `<td>${renderResourceCell(row, column)}</td>`).join("")}</tr>`).join("")}</tbody>
            </table></div>` : `<div class="empty-state"><h2>No records found</h2><p>Try another search or create the first record in Django Admin.</p></div>`}
        </div>
        ${pagination(data.pagination, "resource")}
      </article>`;
    const search = () => {
      state.resourceQuery = document.getElementById("resource-search").value.trim();
      state.resourcePage = 1;
      loadCurrent();
    };
    document.getElementById("resource-search-button").addEventListener("click", search);
    document.getElementById("resource-search").addEventListener("keydown", (event) => {
      if (event.key === "Enter") search();
    });
    bindPagination("resource");
  }

  async function showDomainDetail(id) {
    detailTitle.textContent = "Loading activity?";
    detailContent.innerHTML = "<div class='loading-table'></div>";
    dialog.showModal();
    try {
      const data = await api(`${endpoints.domains}${encodeURIComponent(id)}/`);
      const row = data.activity;
      detailTitle.textContent = row.domain;
      const fields = [
        ["Device", row.client_name], ["Office / system", `${row.office_name} / sys_${row.system_number}`],
        ["Public IP", row.ipv4], ["Device ID", row.device_id],
        ["Group ID", row.group_id || "?"], ["Profile name", row.profile_name || "?"],
        ["Profile ID", row.profile_id], ["Browser ID", row.browser_id || "?"],
        ["Session ID", row.session_id], ["Visits", number(row.visit_count)],
        ["First visited", formatDate(row.first_visited_at)], ["Last visited", formatDate(row.last_visited_at)],
        ["Session started", formatDate(row.session_started_at)], ["Session ended", formatDate(row.session_ended_at)],
        ["Session duration", duration(row.session_duration_seconds)],
        ["Job / reservation", `${row.job_id || "?"} / ${row.reservation_id || "?"}`],
      ];
      detailContent.innerHTML = `
        <div class="detail-grid">
          ${fields.map(([label, value]) => `<div class="detail-field"><span>${e(label)}</span><strong>${e(value)}</strong></div>`).join("")}
        </div>
        <div class="detail-section">
          <div class="panel-header"><div><h3>Domains in the same profile session</h3><p>${number(data.session_domains.length)} unique domains</p></div><a class="link-button" href="${e(row.admin_url)}">Open record in Admin</a></div>
          <div class="table-wrap"><table class="data-table">
            <thead><tr><th>Domain</th><th>Visits</th><th>First visited</th><th>Last visited</th></tr></thead>
            <tbody>${data.session_domains.map((item) => `<tr><td class="cell-primary">${e(item.domain)}</td><td>${number(item.visit_count)}</td><td>${formatDate(item.first_visited_at)}</td><td>${formatDate(item.last_visited_at)}</td></tr>`).join("")}</tbody>
          </table></div>
        </div>`;
    } catch (error) {
      detailTitle.textContent = "Activity unavailable";
      detailContent.innerHTML = `<div class="empty-state"><p>${e(error.message)}</p></div>`;
    }
  }

  async function loadSuspicious() {
    const params = domainParams();
    const data = await api(`${endpoints.suspicious}?${params}`);
    content.innerHTML = `
      <div class="page-intro">
        <div>
          <span class="eyebrow">Monitored-domain alerts</span>
          <h2>Suspicious activity</h2>
          <p>Every monitored-domain match, with the device, office, profile, group, IP and exact timestamps.</p>
        </div>
        <a class="button button-secondary" href="${e(data.monitor_admin_url)}">Manage monitored domains</a>
      </div>
      <div class="subnav" role="group" aria-label="Date range">
        ${[["24h","24 hours"],["7d","7 days"],["30d","30 days"],["90d","90 days"]].map(([value,label]) => `<button data-range="${value}" class="${state.domainFilters.range === value ? "is-active" : ""}">${label}</button>`).join("")}
      </div>
      <form class="toolbar" id="suspicious-filters">${dateFilterOptions(state.domainFilters)}
        <button class="button button-primary" type="submit">Apply filters</button>
        <button class="button button-secondary" type="button" data-clear-suspicious-filters>Clear</button>
      </form>
      <div class="metric-grid">
        ${metricCard("Alerts", data.metrics.records, `${number(data.metrics.domains)} monitored domains`)}
        ${metricCard("Visits", data.metrics.visits, `${number(data.metrics.clients)} devices`)}
        ${metricCard("Profiles", data.metrics.profiles, `${number(data.metrics.sessions)} sessions`)}
      </div>
      <article class="panel-card">
        <div class="panel-header"><div><h3>Monitored-domain matches</h3><p>${number(data.pagination.total)} records</p></div></div>
        <div class="panel-body-flush">${domainTable(data.rows)}</div>
        ${pagination(data.pagination, "suspicious")}
      </article>`;
    bindDomainDetails();
    document.querySelectorAll("[data-range]").forEach((button) => {
      button.addEventListener("click", () => {
        state.domainFilters.range = button.dataset.range;
        delete state.domainFilters.from;
        delete state.domainFilters.to;
        state.domainPage = 1;
        loadCurrent();
      });
    });
    document.getElementById("suspicious-filters").addEventListener("submit", (event) => {
      event.preventDefault();
      const values = new FormData(event.currentTarget);
      ["from", "to"].forEach((key) => {
        const value = String(values.get(key) || "").trim();
        if (value) state.domainFilters[key] = value;
        else delete state.domainFilters[key];
      });
      state.domainFilters.range = "custom";
      state.domainPage = 1;
      loadCurrent();
    });
    document.querySelectorAll("#suspicious-filters input[name=\"from\"], #suspicious-filters input[name=\"to\"]").forEach((field) => {
      field.addEventListener("change", () => document.getElementById("suspicious-filters").requestSubmit());
    });
    content.querySelector("[data-clear-suspicious-filters]").addEventListener("click", () => {
      state.domainFilters = { range: "7d", sort: "last_seen", page_size: "25" };
      state.domainPage = 1;
      loadCurrent();
    });
    bindPagination("suspicious");
  }

  async function loadCurrent() {
    loading();
    refreshButton.disabled = true;
    try {
      if (state.route === "overview") await loadOverview();
      else if (state.route === "domains") await loadDomains();
      else if (state.route === "suspicious") await loadSuspicious();
      else if (state.route === "devices") await loadDevices();
      else if (state.route === "subadmins") await loadSubadmins();
      else await loadResource();
    } catch (error) {
      showError(error);
    } finally {
      refreshButton.disabled = false;
    }
  }

  function navigate(route, updateHash = true) {
    if (!labels[route]) route = "overview";
    state.route = route;
    state.resourcePage = 1;
    document.querySelectorAll(".nav-item").forEach((item) => {
      item.classList.toggle("is-active", item.dataset.route === route);
    });
    breadcrumb.textContent = labels[route][0];
    pageTitle.textContent = labels[route][1];
    if (updateHash) history.replaceState(null, "", `#${route}`);
    document.body.classList.remove("sidebar-open");
    loadCurrent();
  }

  document.querySelectorAll(".nav-item[data-route]").forEach((item) => {
    item.addEventListener("click", () => navigate(item.dataset.route));
  });
  refreshButton.addEventListener("click", loadCurrent);
  document.querySelector("[data-sidebar-open]").addEventListener("click", () => document.body.classList.add("sidebar-open"));
  document.querySelector("[data-sidebar-close]").addEventListener("click", () => document.body.classList.remove("sidebar-open"));
  document.querySelector("[data-dialog-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  window.addEventListener("hashchange", () => navigate(location.hash.slice(1), false));

  navigate(location.hash.slice(1) || "overview", false);
})();
