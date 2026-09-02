(() => {
  const app = document.getElementById("mobile-ops");
  if (!app) return;
  const apiUrl = app.dataset.apiUrl;
  const csrf = document.querySelector("#csrf-token input")?.value || "";
  const notice = document.getElementById("notice");
  const agentStrip = document.getElementById("agent-strip");
  const commandList = document.getElementById("command-list");
  let timer = null;

  const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));
  const show = (message, isError = false) => {
    notice.hidden = false;
    notice.className = `notice${isError ? " error" : ""}`;
    notice.textContent = message;
    window.clearTimeout(show.timeout);
    show.timeout = window.setTimeout(() => { notice.hidden = true; }, 9000);
  };
  const request = async (body) => {
    const response = await fetch(apiUrl, {
      method: body ? "POST" : "GET",
      credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json", "X-CSRFToken": csrf } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      const error = new Error(payload.message || `Request failed (${response.status}).`);
      error.payload = payload;
      throw error;
    }
    return payload;
  };
  const formatDate = (value) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: "short", timeStyle: "medium" }).format(new Date(value)) : "Never";

  function renderAgent(agent) {
    agentStrip.className = `agent-strip ${agent?.online ? "online" : "offline"}`;
    if (!agent) {
      agentStrip.innerHTML = '<span class="agent-dot"></span><div><strong>YS bridge not configured</strong><small>Run the one-time bridge provisioning on the server and office PC.</small></div>';
      return;
    }
    agentStrip.innerHTML = `<span class="agent-dot"></span><div><strong>${esc(agent.name)} · ${agent.online ? "Online" : "Offline"}</strong><small>${agent.online ? "Office PC is ready for YS actions" : `Last seen ${esc(formatDate(agent.last_seen))}`} ${agent.version ? `· v${esc(agent.version)}` : ""}</small></div>`;
  }

  function resultText(command) {
    if (command.error) return command.error;
    const values = Object.entries(command.result || {}).map(([key, value]) => `${key.replaceAll("_", " ")}: ${typeof value === "object" ? JSON.stringify(value) : value}`);
    return values.slice(0, 5).join(" · ");
  }

  function renderCommands(commands) {
    if (!commands.length) {
      commandList.innerHTML = '<p class="empty">No YS commands yet.</p>';
      return;
    }
    commandList.innerHTML = commands.map((command) => `<article class="command-row"><div class="command-main"><strong>${esc(command.action_label)} · ${esc(command.office)}</strong><div class="command-meta">${esc(formatDate(command.requested_at))} · ${esc(command.id.slice(0, 8))}</div>${resultText(command) ? `<div class="command-result">${esc(resultText(command))}</div>` : ""}${["failed", "cancelled"].includes(command.status) ? `<button class="retry" data-retry="${esc(command.id)}">Retry</button>` : ""}</div><span class="status ${esc(command.status)}">${esc(command.status)}</span></article>`).join("");
    commandList.querySelectorAll("[data-retry]").forEach((button) => button.addEventListener("click", async () => {
      button.disabled = true;
      try { const data = await request({ action: "retry_command", command_id: button.dataset.retry }); show(data.message); await load(false); }
      catch (error) { show(error.message, true); }
      finally { button.disabled = false; }
    }));
  }

  function fillOptions(data) {
    const officeOptions = data.offices.map((office) => `<option value="${esc(office)}">${esc(office)}</option>`).join("");
    document.querySelectorAll("[data-office-select]").forEach((select) => {
      const selected = select.value;
      select.innerHTML = `<option value="">Choose office</option>${officeOptions}`;
      select.value = selected;
    });
    const deleteSelect = document.getElementById("delete-office");
    const deleteSelected = deleteSelect.value;
    deleteSelect.innerHTML = `<option value="">Choose office</option>${officeOptions}<option value="__all__">All offices</option>`;
    deleteSelect.value = deleteSelected;
    const provider = document.querySelector('#proxy-form [name="provider"]');
    const providerSelected = provider.value || "P3";
    provider.innerHTML = data.providers.map((value) => `<option value="${esc(value)}">${esc(value)}</option>`).join("");
    provider.value = data.providers.includes(providerSelected) ? providerSelected : data.providers[0];
  }

  async function load(updateOptions = true) {
    try {
      const data = await request();
      if (updateOptions) fillOptions(data);
      renderAgent(data.agent);
      renderCommands(data.commands || []);
    } catch (error) {
      show(error.message, true);
    }
  }

  function bindForm(id, buildBody, pendingText) {
    const form = document.getElementById(id);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      const oldText = button.textContent;
      button.disabled = true;
      button.textContent = pendingText;
      try {
        const data = await request(buildBody(new FormData(form)));
        show(data.message);
        if (id === "ys-delete-form") form.confirmation.value = "";
        await load(false);
      } catch (error) {
        show(error.message, true);
      } finally {
        button.disabled = false;
        button.textContent = oldText;
      }
    });
  }

  bindForm("proxy-form", (values) => ({ action: "generate_proxies", office: values.get("office"), provider: values.get("provider"), country: String(values.get("country") || "").toUpperCase(), target_count: Number(values.get("target_count")) }), "Generating…");
  bindForm("office-ip-form", (values) => ({ action: "add_office_ipv4", office: values.get("office"), ipv4: values.get("ipv4") }), "Adding…");
  bindForm("ys-whitelist-form", (values) => ({ action: "queue_ys_whitelist", mode: values.get("mode"), ipv4: values.get("ipv4") }), "Queueing…");
  bindForm("ys-delete-form", (values) => ({ action: "queue_ys_delete", office: values.get("office"), confirmation: values.get("confirmation") }), "Queueing…");
  document.getElementById("refresh").addEventListener("click", () => load(false));
  load(true);
  timer = window.setInterval(() => load(false), 8000);
  window.addEventListener("beforeunload", () => window.clearInterval(timer));
})();
