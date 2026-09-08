/* Shared report UI: each panel supplies its own URLs, theme and authenticated session. */
window.createPanelReports = ({app, content, escapeHtml:e, formatDate:date, getJson, openDrawer, busy, errorView}) => {
  const settings = {
    audit: {office:"", range:"24h", page:1, view:"systems"},
    domains: {office:"", range:"24h", page:1, q:""},
  };
  const endpoints = {audit:app.dataset.auditUrl, domains:app.dataset.domainsUrl};
  let sequence = 0;
  const number = n => Number(n || 0).toLocaleString("en-IN");
  const pager = p => `<div class="report-pagination"><span>${number(p.total)} records · Page ${p.page} of ${p.pages}</span><div><button class="button button-secondary" data-report-page="${p.page - 1}" ${p.has_previous ? "" : "disabled"}>Previous</button><button class="button button-secondary" data-report-page="${p.page + 1}" ${p.has_next ? "" : "disabled"}>Next</button></div></div>`;
  const metric = (value, label) => `<div class="fleet-metric"><div><strong>${number(value)}</strong><small>${e(label)}</small></div></div>`;
  async function load(route) {
    const ticket = ++sequence;
    const config = settings[route];
    let data;
    try { data = await getJson(endpoints[route], config); }
    catch(error) { if(ticket !== sequence || location.hash.slice(1) !== route) return; throw error; }
    if (ticket !== sequence || location.hash.slice(1) !== route) return;
    config.office = data.office;
    const isAudit = route === "audit";
    const filters = `<form class="report-filters"><label>Period<select name="range">${[["24h","Last 24 hours"],["7d","Last 7 days"],["30d","Last 30 days"],["90d","Last 90 days"]].map(([value,label]) => `<option value="${value}" ${config.range === value ? "selected" : ""}>${label}</option>`).join("")}</select></label>${isAudit ? `<label>Show<select name="view"><option value="systems" ${config.view==="systems"?"selected":""}>System totals</option><option value="events" ${config.view==="events"?"selected":""}>Profile events</option></select></label>` : `<label class="report-search">Search<input name="q" value="${e(config.q)}" placeholder="Domain, system or profile"></label>`}<button class="button button-secondary" type="submit">Apply</button></form>`;
    const metrics = isAudit
      ? metric(data.metrics.systems,"Office systems") + metric(data.metrics.attempts,"Profile attempts reported") + metric(data.metrics.opened,"Unique profiles opened") + metric(data.metrics.open_events,"Open events reported")
      : metric(data.metrics.domains,"Recorded domains") + metric(data.metrics.visits,"Reported visits") + metric(data.metrics.profiles,"Profiles with domain reports") + metric(data.metrics.systems,"Reporting systems");
    let headers, rows;
    if (isAudit && config.view === "systems") {
      headers = "<th>System / bundle</th><th>Profile attempts</th><th>Profiles opened</th><th>Proxy jobs / submitted</th><th>Last report</th>";
      rows = data.rows.map(row => `<tr><td><strong>${e(row.system || row.name)}</strong><small>${e(row.bundle)}</small></td><td>${number(row.attempts)}</td><td>${number(row.opened)}</td><td>${data.proxy_relay ? "Remote proxy service" : `${number(row.proxy_requests)} / ${number(row.submitted)}`}</td><td>${date(row.last_activity)}</td></tr>`).join("");
    } else if (isAudit) {
      headers = "<th>Time</th><th>System</th><th>Profile</th><th>Event</th>";
      rows = data.rows.map(row => `<tr><td>${date(row.time)}</td><td>${e(row.system || row.name)}</td><td><strong>${e(row.profile_name || row.profile_id || "Not assigned yet")}</strong><small>${e(row.profile_id)}</small></td><td><span class="status-pill ${["profile_opened","opened"].includes(row.status) ? "is-good" : "is-muted"}">${e(row.status)}</span></td></tr>`).join("");
    } else {
      headers = "<th>Domain</th><th>System / profile</th><th>Reported visits</th><th>First visit</th><th>Last visit</th><th></th>";
      rows = data.rows.map(row => `<tr><td class="report-domain"><strong>${e(row.domain)}</strong></td><td><strong>${e(row.system_number || row.client_name)}</strong><small>${e(row.profile_name || row.profile_id)}</small></td><td>${number(row.visit_count)}</td><td>${date(row.first_visited_at)}</td><td>${date(row.last_visited_at)}</td><td><button class="link-button" data-domain-detail="${row.id}">View</button></td></tr>`).join("");
    }
    content.innerHTML = `<section class="workspace-head"><div><span class="eyebrow">Office reporting</span><h2>${isAudit ? "Office Audit" : "Domain Activity"}</h2><p>${isAudit ? "Profile attempts and confirmed openings reported by each PC." : "Domains reported from browser profiles launched by the tools."}</p></div></section><div class="office-tabs" role="tablist" aria-label="Office">${data.offices.map(office => `<button class="office-tab${office === data.office ? " is-active" : ""}" role="tab" aria-selected="${office === data.office}" data-report-office="${e(office)}">${e(office)}</button>`).join("")}</div>${filters}<div class="fleet-metrics">${metrics}</div><p class="report-note">${e(data.note)}</p><article class="card data-card fleet-table"><div class="table-toolbar"><div><strong>${e(data.office)}</strong><span>${date(data.range.from)} — ${date(data.range.to)}</span></div></div><div class="table-scroll"><table><thead><tr>${headers}</tr></thead><tbody>${rows || '<tr><td colspan="6"><div class="table-empty">No reports received for this office and period. Check office assignments and reporting PCs; this does not prove there were no launches.</div></td></tr>'}</tbody></table></div>${pager(data.pagination)}</article>`;
    content.querySelectorAll("[data-report-office]").forEach(button => button.addEventListener("click", () => {config.office=button.dataset.reportOffice; config.page=1; reload(route);}));
    content.querySelectorAll("[data-report-page]").forEach(button => button.addEventListener("click", () => {config.page=Number(button.dataset.reportPage); reload(route);}));
    content.querySelector(".report-filters").addEventListener("submit", event => {
      event.preventDefault(); const values = new FormData(event.currentTarget);
      config.range=values.get("range"); config.page=1;
      if (isAudit) config.view=values.get("view"); else config.q=values.get("q");
      reload(route);
    });
    content.querySelectorAll("[data-domain-detail]").forEach(button => button.addEventListener("click", () => {
      const row = data.rows.find(item => String(item.id) === button.dataset.domainDetail);
      openDrawer(`<div class="drawer-head"><div><span class="eyebrow">Recorded domain</span><h2 class="wrap">${e(row.domain)}</h2><p>${e(row.office_name)} / ${e(row.system_number)}</p></div><button class="dialog-close" data-drawer-close>Close</button></div><div class="drawer-body stack"><div class="detail-list">${[["Profile", row.profile_name],["Profile ID",row.profile_id],["Browser ID",row.browser_id],["Session",row.session_id],["First visit",date(row.first_visited_at)],["Last visit",date(row.last_visited_at)],["Visits",row.visit_count],["Session start",date(row.session_started_at)],["Session end",date(row.session_ended_at)]].map(([label,value])=>`<div><span>${e(label)}</span><strong class="wrap">${e(value)}</strong></div>`).join("")}</div><p class="report-note">This is a reported hostname, not a saved full URL or a live browser status.</p></div>`);
    }));
  }
  async function reload(route) {const ticket=sequence+1; busy(true); try {await load(route);} catch(error) {if(ticket===sequence && location.hash.slice(1)===route)errorView(error);} finally {if(ticket===sequence && location.hash.slice(1)===route)busy(false);}}
  return {load, cancel:()=>{sequence++;}};
};

window.createPanelNotifications = ({app, getJson, postJson, openDrawer, openRequest, updateBell, escapeHtml:e, formatDate:date, toast}) => {
  let mode="unread", page=1, inFlight=null, sequence=0;
  async function refresh() {
    if (inFlight) return inFlight;
    inFlight=getJson(app.dataset.notificationsUrl,{notification_filter:"unread",page_size:10}).then(data=>{updateBell(data);return data;}).finally(()=>{inFlight=null;});
    return inFlight;
  }
  async function show() {
    const ticket=++sequence;
    try {
      const data=await getJson(app.dataset.notificationsUrl,{notification_filter:mode,page});
      if(ticket!==sequence)return;
      updateBell(data);
      const p=data.pagination;
      openDrawer(`<div class="drawer-head"><div><span class="eyebrow">Access alerts · all offices</span><h2>Notifications</h2><p>${e(data.scope_note)} Opening a request marks it read; history is retained.</p></div><button class="dialog-close" data-drawer-close>Close</button></div><div class="drawer-body stack"><div class="report-notification-filters"><button class="button button-secondary" data-alert-mode="unread" aria-pressed="${mode==="unread"}">Unread (${data.unread_count})</button><button class="button button-secondary" data-alert-mode="all" aria-pressed="${mode==="all"}">All history</button></div><div class="notification-list">${data.notifications.map(row=>`<button class="notification-row${row.read?"":" is-unread"}" data-alert-id="${row.id}"><span class="notification-dot"></span><span><strong>${e(row.office)} · ${e(row.system_number)}</strong><small>${e(row.reason)} · ${e(row.reported_ip || row.observed_ip)}<br>${date(row.created_at)}</small></span><em>${e(row.review_status)}</em></button>`).join("") || '<div class="table-empty">No requests in this view.</div>'}</div><div class="report-pagination"><span>Page ${p.page} of ${p.pages}</span><div><button class="button button-secondary" data-alert-page="${p.page-1}" ${p.has_previous?"":"disabled"}>Previous</button><button class="button button-secondary" data-alert-page="${p.page+1}" ${p.has_next?"":"disabled"}>Next</button></div></div></div>`);
      const drawer=document.querySelector("#detail-dialog");
      drawer.querySelectorAll("[data-alert-mode]").forEach(button=>button.addEventListener("click",()=>{mode=button.dataset.alertMode;page=1;show();}));
      drawer.querySelectorAll("[data-alert-page]").forEach(button=>button.addEventListener("click",()=>{page=Number(button.dataset.alertPage);show();}));
      drawer.querySelectorAll("[data-alert-id]").forEach(button=>button.addEventListener("click",async()=>{
        const clickTicket=sequence;
        const row=data.notifications.find(item=>String(item.id)===button.dataset.alertId);
        try {
          if(!row.read) await postJson(app.dataset.accessUrl,{action:"mark_read",audit_id:row.id});
          if(clickTicket!==sequence)return;
          row.read=true; openRequest(row);
          const previous=inFlight;
          if(previous)await previous.catch(()=>{});
          refresh().catch(()=>{});
        } catch(error) {toast(error.message,true);}
      }));
    } catch(error) {if(ticket===sequence)toast(error.message,true);}
  }
  // Update only the badge, never replace open forms or trigger an approval.
  setInterval(()=>{if(!document.hidden)refresh().catch(()=>{});},15000);
  window.addEventListener("focus",()=>refresh().catch(()=>{}));
  document.addEventListener("visibilitychange",()=>{if(!document.hidden)refresh().catch(()=>{});});
  return {show,refresh,cancel:()=>{sequence++;}};
};
