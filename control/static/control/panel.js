(() => {
  "use strict";

  const app = document.querySelector("#panel-app");
  const content = document.querySelector("#panel-content");
  const drawer = document.querySelector("#detail-dialog");
  const title = document.querySelector("#page-title");
  const breadcrumb = document.querySelector("#page-breadcrumb");
  const refresh = document.querySelector("#refresh-button");
  const sync = document.querySelector("#sync-label");
  const bell = document.querySelector("#notification-button");
  const bellCount = document.querySelector("#notification-count");
  const endpoints = {access: app.dataset.accessUrl, proxy: app.dataset.proxyUrl, optix: app.dataset.optixUrl};
  const state = {
    route: ["access", "proxy", "optix"].includes(location.hash.slice(1)) ? location.hash.slice(1) : "access",
    office: {access: "", proxy: "", optix: ""},
    data: {access: null, proxy: null, optix: null},
  };

  const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[char]));
  const formatDate = value => value ? new Intl.DateTimeFormat("en-IN", {dateStyle:"medium", timeStyle:"short"}).format(new Date(value)) : "Never";
  const csrf = () => document.querySelector("#panel-csrf-token input")?.value || "";
  const params = values => {
    const query = new URLSearchParams();
    Object.entries(values).forEach(([key, value]) => { if (value !== "" && value != null) query.set(key, value); });
    return query.toString();
  };
  const getJson = async (url, values = {}) => {
    const response = await fetch(`${url}?${params(values)}`, {headers:{Accept:"application/json"}, cache:"no-store"});
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) throw new Error(data.message || `Request failed (${response.status})`);
    return data;
  };
  const postJson = async (url, body) => {
    const response = await fetch(url, {method:"POST", headers:{Accept:"application/json","Content-Type":"application/json","X-CSRFToken":csrf()}, body:JSON.stringify(body)});
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) throw new Error(data.message || `Request failed (${response.status})`);
    return data;
  };
  const toast = (message, error = false) => {
    const node = document.createElement("div");
    node.className = `panel-toast${error ? " is-error" : ""}`;
    node.textContent = message;
    document.body.append(node);
    requestAnimationFrame(() => node.classList.add("is-visible"));
    setTimeout(() => { node.classList.remove("is-visible"); setTimeout(() => node.remove(), 220); }, 3800);
  };
  const busy = active => {
    refresh.disabled = active;
    refresh.classList.toggle("is-loading", active);
    sync.textContent = active ? "Syncing" : "Live";
  };
  const loading = () => { content.innerHTML = '<div class="loading-state"><div class="loading-line loading-line-wide"></div><div class="loading-grid"><div class="loading-card"></div><div class="loading-card"></div><div class="loading-card"></div></div><div class="loading-table"></div></div>'; };
  const errorView = error => { content.innerHTML = `<div class="empty-state"><div class="empty-symbol">!</div><h2>Could not load this workspace</h2><p>${escapeHtml(error.message)}</p><button class="button button-primary" data-retry>Try again</button></div>`; };
  const closeDrawer = () => { if (drawer.open) drawer.close(); drawer.innerHTML = ""; };
  const openDrawer = html => {
    drawer.innerHTML = html;
    if (!drawer.open) drawer.showModal();
    drawer.querySelector("[data-drawer-close]")?.addEventListener("click", closeDrawer);
  };
  const officeTabs = (offices, selected, route) => `<div class="office-tabs" role="tablist">${offices.map(office => `<button class="office-tab${office === selected ? " is-active" : ""}" data-office-route="${route}" data-office="${escapeHtml(office)}">${escapeHtml(office)}</button>`).join("")}</div>`;
  const emptyRows = text => `<tr><td colspan="8"><div class="table-empty">${escapeHtml(text)}</div></td></tr>`;
  const statusPill = (active, yes = "Active", no = "Disabled") => `<span class="status-pill ${active ? "is-good" : "is-muted"}">${active ? yes : no}</span>`;
  const checkGroup = (name, values, selected) => `<div class="choice-grid">${values.map(value => `<label class="choice"><input type="checkbox" name="${name}" value="${escapeHtml(value)}" ${selected.includes(value) ? "checked" : ""}><span>${escapeHtml(value)}</span></label>`).join("")}</div>`;
  const selectedChecks = (form, name) => [...form.querySelectorAll(`[name="${name}"]:checked`)].map(node => node.value);

  function updateHeader() {
    const labels = {access:"Access", proxy:"Proxy", optix:"Dollar Control"};
    title.textContent = labels[state.route];
    breadcrumb.textContent = labels[state.route];
    document.querySelectorAll(".nav-item[data-route]").forEach(node => node.classList.toggle("is-active", node.dataset.route === state.route));
    bell.hidden = state.route !== "access";
  }

  function updateBell(data) {
    const count = Number(data?.unread_count || 0);
    bellCount.textContent = String(count);
    bellCount.hidden = count < 1;
  }

  async function loadAccess() {
    const data = await getJson(endpoints.access, {office:state.office.access});
    state.data.access = data;
    state.office.access = data.office;
    updateBell(data);
    content.innerHTML = `
      <section class="workspace-head">
        <div><span class="eyebrow">IP &amp; device identity</span><h2>Office access</h2><p>Review PCs, maintain changing public IPs and approve denied requests.</p></div>
        <button class="button button-primary" id="add-office-ip">Add IP to office</button>
      </section>
      ${officeTabs(data.offices, data.office, "access")}
      <article class="card data-card">
        <div class="table-toolbar"><div><strong>${escapeHtml(data.office || "No office")}</strong><span>${data.rows.length} registered system(s)</span></div><button class="button button-secondary" id="open-notifications">Access requests${data.unread_count ? ` <b>${data.unread_count}</b>` : ""}</button></div>
        <div class="table-scroll"><table><thead><tr><th>Office name</th><th>System number</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody>
          ${data.rows.length ? data.rows.map(row => `<tr><td><strong>${escapeHtml(row.office)}</strong></td><td><strong>${escapeHtml(row.system_number)}</strong><small>${escapeHtml(row.bundle)}</small></td><td>${formatDate(row.last_seen)}</td><td>${statusPill(row.active)}</td><td class="align-right"><button class="link-button" data-access-view="${row.id}">View</button></td></tr>`).join("") : emptyRows("No systems in this office.")}
        </tbody></table></div>
      </article>`;
    document.querySelector("#add-office-ip")?.addEventListener("click", () => openOfficeIp(data.office));
    document.querySelector("#open-notifications")?.addEventListener("click", openNotifications);
    content.querySelectorAll("[data-access-view]").forEach(button => button.addEventListener("click", () => openAccessDevice(data.rows.find(row => String(row.id) === button.dataset.accessView))));
  }

  function openOfficeIp(office) {
    openDrawer(`<div class="drawer-head"><div><span class="eyebrow">Office-wide IP</span><h2>Add an allowed IP</h2><p>This adds a new address without replacing existing IPs.</p></div><button class="dialog-close" data-drawer-close>Close</button></div><form class="drawer-body stack" id="office-ip-form"><div class="context-box"><span>Office</span><strong>${escapeHtml(office)}</strong></div><label>New public IPv4<input name="ipv4" required placeholder="203.0.113.10" inputmode="decimal"></label><button class="button button-primary" type="submit">Add to every active PC</button></form>`);
    drawer.querySelector("#office-ip-form").addEventListener("submit", async event => {
      event.preventDefault();
      try { const result = await postJson(endpoints.access, {action:"add_office_ip", office, ipv4:event.currentTarget.ipv4.value}); toast(result.message); closeDrawer(); await loadAccess(); }
      catch (error) { toast(error.message, true); }
    });
  }

  function openAccessDevice(row) {
    if (!row) return;
    const allIps = [row.primary_ip, ...row.additional_ips];
    openDrawer(`<div class="drawer-head"><div><span class="eyebrow">${escapeHtml(row.office)} / System ${escapeHtml(row.system_number)}</span><h2>${escapeHtml(row.name)}</h2><p>${escapeHtml(row.bundle)}</p></div><button class="dialog-close" data-drawer-close>Close</button></div><div class="drawer-body stack"><div class="detail-list"><div><span>System number</span><strong>${escapeHtml(row.system_number)}</strong></div><div><span>Device ID</span><strong class="mono wrap">${escapeHtml(row.device_id || "Not reported")}</strong></div><div><span>Bundle</span><strong>${escapeHtml(row.bundle)}</strong></div><div><span>Last seen</span><strong>${formatDate(row.last_seen)}</strong></div></div><div><span class="field-title">Allowed IP addresses</span><div class="ip-chips">${allIps.map((ip,index) => `<span>${escapeHtml(ip)}${index === 0 ? " · primary" : ""}</span>`).join("")}</div></div><form class="inline-form" id="device-ip-form"><input name="ipv4" required placeholder="Add another IPv4"><button class="button button-primary" type="submit">Add IP</button></form><label class="toggle-control"><input id="device-access-toggle" type="checkbox" ${row.active ? "checked" : ""}><span>Allow this PC to access Dollar</span></label></div>`);
    drawer.querySelector("#device-ip-form").addEventListener("submit", async event => {
      event.preventDefault();
      try { const result = await postJson(endpoints.access, {action:"add_device_ip", client_id:row.id, ipv4:event.currentTarget.ipv4.value}); toast(result.message); closeDrawer(); await loadAccess(); }
      catch (error) { toast(error.message, true); }
    });
    drawer.querySelector("#device-access-toggle").addEventListener("change", async event => {
      try { const result = await postJson(endpoints.access, {action:"set_access", client_id:row.id, active:event.target.checked}); toast(result.message); await loadAccess(); }
      catch (error) { event.target.checked = !event.target.checked; toast(error.message, true); }
    });
  }

  function openNotifications() {
    const rows = state.data.access?.notifications || [];
    openDrawer(`<div class="drawer-head"><div><span class="eyebrow">Access requests</span><h2>Notifications</h2><p>Opened requests are marked read and always stay in history.</p></div><button class="dialog-close" data-drawer-close>Close</button></div><div class="drawer-body notification-list">${rows.length ? rows.map(row => `<button class="notification-row${row.read ? "" : " is-unread"}" data-notification="${row.id}"><span class="notification-dot"></span><span><strong>${escapeHtml(row.office)} · System ${escapeHtml(row.system_number)}</strong><small>${escapeHtml(row.reported_ip || row.observed_ip || "No IP")} · ${formatDate(row.created_at)}</small></span><em>${escapeHtml(row.review_status)}</em></button>`).join("") : '<div class="table-empty">No denied access requests.</div>'}</div>`);
    drawer.querySelectorAll("[data-notification]").forEach(button => button.addEventListener("click", async () => {
      const row = rows.find(item => String(item.id) === button.dataset.notification);
      if (!row) return;
      try { if (!row.read) await postJson(endpoints.access, {action:"mark_read", audit_id:row.id}); } catch {}
      openAccessRequest(row);
      loadAccess().catch(() => {});
    }));
  }

  function openAccessRequest(row) {
    const evidence = [...new Set([row.reported_ip, row.observed_ip].filter(Boolean))];
    openDrawer(`<div class="drawer-head"><div><span class="eyebrow">Denied access request</span><h2>${escapeHtml(row.office)} · System ${escapeHtml(row.system_number)}</h2><p>${formatDate(row.created_at)}</p></div><button class="dialog-close" data-drawer-close>Close</button></div><div class="drawer-body stack"><div class="detail-list"><div><span>Device ID</span><strong class="mono wrap">${escapeHtml(row.device_id)}</strong></div><div><span>Request IP</span><strong>${escapeHtml(evidence.join(" / ") || "Unavailable")}</strong></div><div><span>Reason</span><strong>${escapeHtml(row.reason)}</strong></div><div><span>Review</span><strong>${escapeHtml(row.review_status)}</strong></div></div>${row.review_status === "pending" ? `<form class="stack" id="request-review-form"><label>IP to approve<select name="ipv4">${evidence.map(ip => `<option>${escapeHtml(ip)}</option>`).join("")}</select></label><div class="scope-cards"><label><input type="radio" name="scope" value="device" checked><span><strong>Only this PC</strong><small>Add IP to the existing Device ID record.</small></span></label><label><input type="radio" name="scope" value="office"><span><strong>Every PC in this office</strong><small>Add IP as an additional address office-wide.</small></span></label></div><div class="drawer-actions"><button class="button button-danger" type="button" id="reject-request">Reject</button><button class="button button-primary" type="submit" ${row.can_approve ? "" : "disabled"}>Approve access</button></div>${row.can_approve ? "" : '<p class="form-note is-danger">No existing PC matches this Device ID. This quick action will not create a duplicate record.</p>'}</form>` : '<div class="context-box"><span>Completed</span><strong>This request remains in history.</strong></div>'}</div>`);
    drawer.querySelector("#request-review-form")?.addEventListener("submit", async event => {
      event.preventDefault();
      try { const form = event.currentTarget; const result = await postJson(endpoints.access, {action:"approve_request", audit_id:row.id, ipv4:form.ipv4.value, scope:form.scope.value}); toast(result.message); closeDrawer(); await loadAccess(); }
      catch (error) { toast(error.message, true); }
    });
    drawer.querySelector("#reject-request")?.addEventListener("click", async () => {
      try { const result = await postJson(endpoints.access, {action:"reject_request", audit_id:row.id}); toast(result.message); closeDrawer(); await loadAccess(); }
      catch (error) { toast(error.message, true); }
    });
  }

  const providerPills = providers => {
    const rows = Object.entries(providers || {});
    return rows.length ? `<div class="provider-pills">${rows.map(([code,value]) => `<span><b>${escapeHtml(code)}</b>${value.available} ready</span>`).join("")}</div>` : '<span class="muted">No active stock</span>';
  };

  async function loadProxy() {
    const data = await getJson(endpoints.proxy, {office:state.office.proxy});
    state.data.proxy = data;
    state.office.proxy = data.office;
    content.innerHTML = `<section class="workspace-head"><div><span class="eyebrow">Bundle inventory</span><h2>Proxy control</h2><p>Inspect stock per system and generate or remove exact provider locations.</p></div><div class="head-actions"><button class="button button-secondary" id="proxy-remove-office">Remove office stock</button><button class="button button-primary" id="proxy-operation">Add proxy stock</button></div></section>${officeTabs(data.offices, data.office, "proxy")}<article class="card data-card"><div class="table-toolbar"><div><strong>${escapeHtml(data.office || "No office")}</strong><span>Availability follows each PC's assigned bundle.</span></div></div><div class="table-scroll"><table><thead><tr><th>System</th><th>Bundle</th><th>Active provider stock</th><th>Status</th><th></th></tr></thead><tbody>${data.rows.length ? data.rows.map(row => `<tr><td><strong>${escapeHtml(row.system_number)}</strong><small>${escapeHtml(row.name)}</small></td><td>${escapeHtml(row.bundle)}</td><td>${providerPills(row.providers)}</td><td>${statusPill(row.active)}</td><td class="align-right"><button class="link-button" data-proxy-view="${row.id}">View</button></td></tr>`).join("") : emptyRows("No systems in this office.")}</tbody></table></div></article>`;
    document.querySelector("#proxy-operation")?.addEventListener("click", () => openProxyOperation());
    document.querySelector("#proxy-remove-office")?.addEventListener("click", () => openProxyOperation("", "remove"));
    content.querySelectorAll("[data-proxy-view]").forEach(button => button.addEventListener("click", () => openProxyDevice(button.dataset.proxyView)));
  }

  async function openProxyDevice(clientId) {
    try {
      const data = await getJson(endpoints.proxy, {office:state.office.proxy, client_id:clientId});
      state.data.proxy = data;
      const client = data.selected_client;
      openDrawer(`<div class="drawer-head"><div><span class="eyebrow">${escapeHtml(client.office)} / System ${escapeHtml(client.system_number)}</span><h2>Proxy inventory</h2><p>${escapeHtml(client.bundle)}</p></div><button class="dialog-close" data-drawer-close>Close</button></div><div class="drawer-body stack"><button class="button button-primary" id="add-device-proxy">Add proxy location to this PC</button><div class="inventory-list">${data.detail_rows.length ? data.detail_rows.map(row => `<div class="inventory-row"><div><strong>${escapeHtml(row.provider)} · ${escapeHtml(row.country)}</strong><span>${escapeHtml(row.region)} / ${escapeHtml(row.city)}</span></div><div><b>${row.available}</b><small>ready</small></div><button class="link-button danger-text" data-remove-target="${row.id}" data-provider="${escapeHtml(row.provider)}" data-country="${escapeHtml(row.country)}" data-region="${escapeHtml(row.region === "Any" ? "" : row.region)}" data-city="${escapeHtml(row.city === "Any" ? "" : row.city)}">Remove</button></div>`).join("") : '<div class="table-empty">No proxy targets for this bundle.</div>'}</div></div>`);
      drawer.querySelector("#add-device-proxy")?.addEventListener("click", () => openProxyOperation(clientId));
      drawer.querySelectorAll("[data-remove-target]").forEach(button => button.addEventListener("click", () => openRemoveProxy({clientId, provider:button.dataset.provider, country:button.dataset.country, region:button.dataset.region, city:button.dataset.city})));
    } catch (error) { toast(error.message, true); }
  }

  function proxyOperationForm(data, clientId = "", mode = "generate") {
    const providers = data.options.providers;
    const countries = data.options.countries;
    const removing = mode === "remove";
    return `<div class="drawer-head"><div><span class="eyebrow">${removing ? "Destructive operation" : "Proxy generation"}</span><h2>${removing ? "Remove available office stock" : "Add proxy stock"}</h2><p>${clientId ? "Only the selected PC bundle" : `Every bundle in ${escapeHtml(data.office)}`}</p></div><button class="dialog-close" data-drawer-close>Close</button></div><form class="drawer-body stack" id="proxy-operation-form"><input type="hidden" name="client_id" value="${escapeHtml(clientId)}"><label>Provider<select name="provider" required><option value="">Choose provider</option>${providers.map(row => `<option value="${escapeHtml(row.code)}">${escapeHtml(row.code)} · ${escapeHtml(row.display_name)}</option>`).join("")}</select></label><label>Country<select name="country" required><option value="">Choose country</option>${countries.map(row => `<option value="${escapeHtml(row.code)}">${escapeHtml(row.name)} [${escapeHtml(row.code)}]</option>`).join("")}</select></label><label>Region / state<select name="region"><option value="">Any</option></select></label><label>City<select name="city"><option value="">Any</option></select></label>${removing ? '<div class="danger-panel"><strong>Available stock only</strong><span>Matching pools will be paused. Reserved proxy history stays intact.</span></div><label>Type REMOVE AVAILABLE to confirm<input name="confirmation" autocomplete="off" required></label>' : '<div class="two-fields"><label>Target stock<input type="number" name="target_count" min="1" max="5000" value="1000"></label><label>Refill below<input type="number" name="threshold" min="1" max="5000" value="200"></label></div>'}<button class="button ${removing ? "button-danger" : "button-primary"}" type="submit">${removing ? "Remove office stock" : "Queue generation"}</button></form>`;
  }

  function openProxyOperation(clientId = "", mode = "generate") {
    const data = state.data.proxy;
    openDrawer(proxyOperationForm(data, clientId, mode));
    const form = drawer.querySelector("#proxy-operation-form");
    const loadGeo = async () => {
      const provider = form.provider.value, country = form.country.value, region = form.region.value;
      if (!provider || !country) return;
      try {
        const geo = await getJson(endpoints.proxy, {office:data.office, provider, country, region});
        if (!region) form.region.innerHTML = '<option value="">Any</option>' + geo.options.regions.map(row => `<option value="${escapeHtml(row.region_code)}">${escapeHtml(row.region_name)}</option>`).join("");
        form.city.innerHTML = '<option value="">Any</option>' + geo.options.cities.map(city => `<option>${escapeHtml(city)}</option>`).join("");
      } catch (error) { toast(error.message, true); }
    };
    form.provider.addEventListener("change", () => { form.region.innerHTML='<option value="">Any</option>'; form.city.innerHTML='<option value="">Any</option>'; loadGeo(); });
    form.country.addEventListener("change", () => { form.region.innerHTML='<option value="">Any</option>'; form.city.innerHTML='<option value="">Any</option>'; loadGeo(); });
    form.region.addEventListener("change", loadGeo);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      try { const row = event.currentTarget; const removing = mode === "remove"; const result = await postJson(endpoints.proxy, {action:removing ? "remove_available" : "generate", scope:clientId ? "device" : "office", office:data.office, client_id:clientId || undefined, provider:row.provider.value, country:row.country.value, region:row.region.value, city:row.city.value, target_count:row.target_count?.value, threshold:row.threshold?.value, confirmation:row.confirmation?.value}); toast(result.message); closeDrawer(); await loadProxy(); }
      catch (error) { toast(error.message, true); }
    });
  }

  function openRemoveProxy(values) {
    const scopeText = values.clientId ? "this PC's bundle" : `every bundle in ${state.office.proxy}`;
    openDrawer(`<div class="drawer-head"><div><span class="eyebrow">Destructive operation</span><h2>Remove available proxy stock</h2><p>Reserved proxy history is always retained.</p></div><button class="dialog-close" data-drawer-close>Close</button></div><form class="drawer-body stack" id="remove-proxy-form"><div class="danger-panel"><strong>${escapeHtml(values.provider)} ${escapeHtml(values.country)}</strong><span>${escapeHtml(values.region || "Any state")} / ${escapeHtml(values.city || "Any city")} · ${escapeHtml(scopeText)}</span></div><label>Type REMOVE AVAILABLE to confirm<input name="confirmation" autocomplete="off" required></label><button class="button button-danger" type="submit">Remove stock and pause pools</button></form>`);
    drawer.querySelector("#remove-proxy-form").addEventListener("submit", async event => {
      event.preventDefault();
      try { const result = await postJson(endpoints.proxy, {action:"remove_available", scope:values.clientId ? "device" : "office", office:state.office.proxy, client_id:values.clientId || undefined, provider:values.provider, country:values.country, region:values.region, city:values.city, confirmation:event.currentTarget.confirmation.value}); toast(result.message); closeDrawer(); await loadProxy(); }
      catch (error) { toast(error.message, true); }
    });
  }

  async function loadOptix() {
    const data = await getJson(endpoints.optix, {office:state.office.optix});
    state.data.optix = data;
    state.office.optix = data.office;
    content.innerHTML = `<section class="workspace-head"><div><span class="eyebrow">Desktop policy</span><h2>Dollar Control</h2><p>Set office defaults, override one PC and manage trusted desktop access.</p></div><button class="button button-primary" id="office-policy">Configure office</button></section>${officeTabs(data.offices, data.office, "optix")}<div class="policy-summary"><div><span>Providers</span><strong>${escapeHtml(data.policy.providers.join(", ") || "None")}</strong></div><div><span>Browsers</span><strong>${escapeHtml(data.policy.browsers.join(", ") || "None")}</strong></div><div><span>Devices</span><strong>${escapeHtml(data.policy.devices.join(", ") || "None")}</strong></div><div><span>Logs</span><strong>${data.policy.show_logs ? "Visible" : "Hidden"}</strong></div></div><article class="card data-card"><div class="table-scroll"><table><thead><tr><th>System</th><th>Bundle</th><th>Permission source</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody>${data.rows.length ? data.rows.map(row => `<tr><td><strong>${escapeHtml(row.system_number)}</strong><small>${escapeHtml(row.name)}</small></td><td>${escapeHtml(row.bundle)}</td><td><span class="status-pill is-info">${escapeHtml(row.permission_source)}</span>${row.remote_action ? `<small class="danger-text">Removal ${row.remote_acknowledged ? "acknowledged" : "pending"}</small>` : ""}</td><td>${formatDate(row.last_seen)}</td><td>${statusPill(row.active, "Allowed", "Blocked")}</td><td class="align-right"><button class="link-button" data-optix-view="${row.id}">Control</button></td></tr>`).join("") : emptyRows("No systems in this office.")}</tbody></table></div></article>`;
    document.querySelector("#office-policy")?.addEventListener("click", openOfficePolicy);
    content.querySelectorAll("[data-optix-view]").forEach(button => button.addEventListener("click", () => openOptixDevice(button.dataset.optixView)));
  }

  function openOfficePolicy() {
    const data = state.data.optix, policy = data.policy;
    openDrawer(`<div class="drawer-head"><div><span class="eyebrow">Office policy</span><h2>${escapeHtml(data.office)}</h2><p>Inherited by every PC without an individual override.</p></div><button class="dialog-close" data-drawer-close>Close</button></div><form class="drawer-body stack" id="office-policy-form"><label class="toggle-control"><input type="checkbox" name="active" ${policy.active ? "checked" : ""}><span>Enable this office policy</span></label><div><span class="field-title">Providers</span>${checkGroup("providers",data.options.providers,policy.providers)}</div><div><span class="field-title">Browsers</span>${checkGroup("browsers",data.options.browsers,policy.browsers)}</div><div><span class="field-title">Profile devices</span>${checkGroup("devices",data.options.devices,policy.devices)}</div><label class="toggle-control"><input type="checkbox" name="show_logs" ${policy.show_logs ? "checked" : ""}><span>Show Logs tab</span></label><button class="button button-primary" type="submit">Save office policy</button></form>`);
    drawer.querySelector("#office-policy-form").addEventListener("submit", async event => {
      event.preventDefault(); const form=event.currentTarget;
      try { const result=await postJson(endpoints.optix,{action:"save_office",office:data.office,active:form.active.checked,providers:selectedChecks(form,"providers"),browsers:selectedChecks(form,"browsers"),devices:selectedChecks(form,"devices"),show_logs:form.show_logs.checked}); toast(result.message); closeDrawer(); await loadOptix(); }
      catch(error){toast(error.message,true);}
    });
  }

  async function openOptixDevice(clientId) {
    try {
      const data = await getJson(endpoints.optix,{office:state.office.optix,client_id:clientId});
      state.data.optix=data; const row=data.selected_client;
      const chosen = row.override ? row : row.resolved;
      openDrawer(`<div class="drawer-head"><div><span class="eyebrow">${escapeHtml(row.office)} / System ${escapeHtml(row.system_number)}</span><h2>${escapeHtml(row.name)}</h2><p>${escapeHtml(row.bundle)}</p></div><button class="dialog-close" data-drawer-close>Close</button></div><form class="drawer-body stack" id="device-policy-form"><label class="toggle-control"><input type="checkbox" name="active" ${row.active ? "checked" : ""}><span>Allow Dollar on this PC</span></label><label class="toggle-control"><input type="checkbox" name="override" ${row.override ? "checked" : ""}><span>Use individual permissions instead of office policy</span></label><div><span class="field-title">Providers</span>${checkGroup("providers",data.options.providers,chosen.providers)}</div><div><span class="field-title">Browsers</span>${checkGroup("browsers",data.options.browsers,chosen.browsers)}</div><div><span class="field-title">Profile devices</span>${checkGroup("devices",data.options.devices,chosen.devices)}</div><label class="toggle-control"><input type="checkbox" name="show_logs" ${chosen.show_logs ? "checked" : ""}><span>Show Logs tab</span></label><button class="button button-primary" type="submit">Save PC control</button><div class="destructive-zone"><span class="field-title">Remote removal</span>${row.remote_action && !row.remote_action_acknowledged_at ? `<p>Removal command r${row.remote_action_revision} is waiting for this PC.</p><button class="button button-secondary" type="button" id="cancel-uninstall">Cancel pending removal</button>` : row.remote_action_acknowledged_at ? `<p>PC acknowledged the removal command at ${formatDate(row.remote_action_acknowledged_at)}.</p>` : `<p>Schedule a verified command that the supported Dollar client acknowledges before uninstalling.</p><button class="button button-danger" type="button" id="schedule-uninstall">Schedule complete Dollar removal</button>`}</div></form>`);
      const form=drawer.querySelector("#device-policy-form");
      form.addEventListener("submit",async event=>{event.preventDefault();try{const result=await postJson(endpoints.optix,{action:"save_device",client_id:row.id,active:form.active.checked,override:form.override.checked,providers:selectedChecks(form,"providers"),browsers:selectedChecks(form,"browsers"),devices:selectedChecks(form,"devices"),show_logs:form.show_logs.checked});toast(result.message);closeDrawer();await loadOptix();}catch(error){toast(error.message,true);}});
      drawer.querySelector("#schedule-uninstall")?.addEventListener("click",()=>openUninstallConfirm(row));
      drawer.querySelector("#cancel-uninstall")?.addEventListener("click",async()=>{try{const result=await postJson(endpoints.optix,{action:"cancel_uninstall",client_id:row.id});toast(result.message);closeDrawer();await loadOptix();}catch(error){toast(error.message,true);}});
    } catch(error){toast(error.message,true);}
  }

  function openUninstallConfirm(row){
    openDrawer(`<div class="drawer-head"><div><span class="eyebrow">High-risk action</span><h2>Remove Dollar from this PC</h2><p>${escapeHtml(row.office)} / System ${escapeHtml(row.system_number)}</p></div><button class="dialog-close" data-drawer-close>Close</button></div><form class="drawer-body stack" id="uninstall-form"><div class="danger-panel"><strong>Remote uninstall</strong><span>The command is device-bound, revisioned and acknowledged before execution. Access remains a separate control.</span></div><label>Enter system number ${escapeHtml(row.system_number)} to confirm<input name="confirmation" autocomplete="off" required></label><button class="button button-danger" type="submit">Schedule removal</button></form>`);
    drawer.querySelector("#uninstall-form").addEventListener("submit",async event=>{event.preventDefault();try{const result=await postJson(endpoints.optix,{action:"schedule_uninstall",client_id:row.id,confirmation:event.currentTarget.confirmation.value});toast(result.message);closeDrawer();await loadOptix();}catch(error){toast(error.message,true);}});
  }

  async function loadRoute() {
    updateHeader(); loading(); busy(true);
    try { await ({access:loadAccess,proxy:loadProxy,optix:loadOptix}[state.route])(); }
    catch (error) { errorView(error); }
    finally { busy(false); }
  }

  document.querySelectorAll(".nav-item[data-route]").forEach(button => button.addEventListener("click", () => {
    state.route=button.dataset.route; location.hash=state.route; closeDrawer(); loadRoute(); document.body.classList.remove("sidebar-open");
  }));
  content.addEventListener("click", event => {
    const officeButton=event.target.closest("[data-office-route]");
    if(officeButton){state.office[officeButton.dataset.officeRoute]=officeButton.dataset.office;loadRoute();}
    if(event.target.closest("[data-retry]"))loadRoute();
  });
  refresh.addEventListener("click",loadRoute);
  bell.addEventListener("click",()=>{if(state.data.access)openNotifications();else{state.route="access";location.hash="access";loadRoute().then(openNotifications);}});
  drawer.addEventListener("cancel",event=>{event.preventDefault();closeDrawer();});
  drawer.addEventListener("click",event=>{if(event.target===drawer)closeDrawer();});
  document.querySelector("[data-sidebar-open]")?.addEventListener("click",()=>document.body.classList.add("sidebar-open"));
  document.querySelector("[data-sidebar-close]")?.addEventListener("click",()=>document.body.classList.remove("sidebar-open"));
  updateHeader();
  getJson(endpoints.access).then(data=>{state.data.access=data;state.office.access=data.office;updateBell(data);}).catch(()=>{}).finally(loadRoute);
})();
