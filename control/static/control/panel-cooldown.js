(() => {
  "use strict";
  let dispose = () => {};

  window.ProxyCooldown = {
    mount(content, {getJson, postJson, toast}) {
      dispose();
      const url = document.querySelector("#panel-app").dataset.cooldownUrl;
      const card = document.createElement("section");
      card.className = "cooldown-card";
      card.innerHTML = `<div class="cooldown-copy"><span class="eyebrow">Global · OPTIX + Dollar · All offices</span><h3 id="cooldown-title">25-hour IP check</h3><p>One shared switch for every provider, browser and PC using this proxy service.</p><small>OFF allows IP reuse; history is kept and new usage is still recorded. Tubelight and duplicates within one RUN stay unchanged.</small><span class="cooldown-feedback" role="status" aria-live="polite">Reading current setting…</span></div><button type="button" class="cooldown-switch" role="switch" aria-checked="false" aria-labelledby="cooldown-title" disabled><span class="cooldown-track" aria-hidden="true"><i></i></span><strong>Loading…</strong></button>`;
      content.querySelector(".workspace-head").insertAdjacentElement("afterend", card);
      const button = card.querySelector("button");
      const label = button.querySelector("strong");
      const feedback = card.querySelector(".cooldown-feedback");
      let policy = null, canChange = false, saving = false, sequence = 0, stopped = false;
      const live = () => !stopped && card.isConnected;
      const render = () => {
        button.disabled = saving || !policy || !canChange;
        button.setAttribute("aria-checked", String(policy?.enabled === true));
        button.setAttribute("aria-busy", String(saving));
        label.textContent = saving ? "Saving…" : policy ? (policy.enabled ? "ON" : "OFF") : "Unavailable";
      };
      const accept = data => {
        if (data?.ok !== true || typeof data?.policy?.enabled !== "boolean" || !Number.isInteger(data.policy.revision)) throw new Error("Could not verify the global IP setting.");
        policy = data.policy;
        canChange = data.can_change === true;
        feedback.textContent = canChange ? (policy.enabled ? "ON — used IPs are blocked for 25 hours." : "OFF — historical IP reuse is allowed across all offices.") : "Read only — a full administrator can change this setting.";
        feedback.classList.remove("is-error");
        render();
      };
      const refresh = async () => {
        if (!live() || saving) return;
        const ticket = ++sequence;
        try {
          const data = await getJson(url);
          if (live() && ticket === sequence && !saving) accept(data);
        } catch (error) {
          if (!live() || ticket !== sequence) return;
          policy = null;
          feedback.textContent = `Setting unavailable: ${error.message} No change was confirmed.`;
          feedback.classList.add("is-error");
          render();
        }
      };
      button.addEventListener("click", async () => {
        if (!live() || saving || !policy || !canChange) return;
        saving = true;
        ++sequence;
        render();
        try {
          const data = await postJson(url, {enabled:!policy.enabled, expected_revision:policy.revision});
          if (live()) {
            accept(data);
            toast(`25-hour IP check ${policy.enabled ? "ON" : "OFF"} for OPTIX and Dollar — all offices.`);
          }
        } catch (error) {
          if (live()) toast(error.message, true);
        } finally {
          saving = false;
          if (live()) { render(); await refresh(); }
        }
      });
      const onFocus = () => { if (!document.hidden) refresh(); };
      const timer = setInterval(() => { if (!live()) dispose(); else onFocus(); }, 15000);
      window.addEventListener("focus", onFocus);
      document.addEventListener("visibilitychange", onFocus);
      dispose = () => {
        stopped = true;
        ++sequence;
        clearInterval(timer);
        window.removeEventListener("focus", onFocus);
        document.removeEventListener("visibilitychange", onFocus);
      };
      refresh();
    },
  };
})();
