"use strict";
const token = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);
const PRESENT = new Set(["available", "needs_params"]);
const WRITE_VERBS = new Set(["set", "add", "update", "create", "del", "delete", "remove", "clear"]);
let profile = null;
let submitUrl = "";

const SW_LABELS = {
  adguard: "AdGuard Home", tor: "Tor", vpn: "VPN", obfuscation: "VPN obfuscation",
  nas: "NAS / SMB file sharing", sms_forward: "SMS forwarding",
  bark: "Bark parental controls", ipv6: "IPv6", mlo: "MLO (Wi-Fi 7)", vlan: "VLAN",
  ids_ips: "IDS / IPS", secondwan: "Dual WAN / failover", repeater_eap: "Repeater (WPA-Ent)",
  passthrough: "Modem passthrough",
};
const cap = (p) => p.capabilities || {};
const hw = (p) => cap(p).hardware_feature || {};
const sw = (p) => cap(p).software_feature || {};
const truthy = (v) => v === true || (typeof v === "string" && v !== "" && v !== "0" && v !== "false");
const HW = [
  { label: "Cellular modem", fn: (p) => truthy(hw(p).simo) || truthy(hw(p).build_in_modem) },
  { label: "Bluetooth", fn: (p) => truthy(hw(p).bluetooth) },
  { label: "GPS", fn: (p) => truthy(hw(p).gps) },
  { label: "USB 3.0", fn: (p) => truthy(hw(p).usb3) },
  { label: "Screen", fn: (p) => truthy(hw(p).screen) },
  { label: "microSD", fn: (p) => truthy(hw(p).microsd) },
  { label: "NAND flash", fn: (p) => truthy(hw(p).nand) },
];

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}
function badge(t, c) { return `<span class="badge ${escapeHtml(c)}">${escapeHtml(t)}</span>`; }
function block(label, body, req) {
  return `<div class="detail-block"><div class="detail-label${req ? " req" : ""}">${escapeHtml(label)}</div>` +
    `<pre>${escapeHtml(body)}</pre></div>`;
}

function pairedRead(p, service, method) {
  const us = method.indexOf("_");
  if (us < 0) return null;
  const verb = method.slice(0, us), noun = method.slice(us + 1);
  if (!WRITE_VERBS.has(verb) || !noun) return null;
  const methods = p.services[service] || {};
  for (const cand of [`get_${noun}`, `get_${noun}_list`, `get_${noun}_config`, `get_${noun}_info`]) {
    const r = methods[cand];
    if (r && r.signature && typeof r.signature === "object" && !Array.isArray(r.signature)) {
      return { from: `${service}.${cand}`, shape: r.signature };
    }
  }
  return null;
}

function renderCaps(p) {
  const c = cap(p);
  if (!c.country_code && !c.software_feature && !c.hardware_feature) return "";
  const onSw = Object.entries(SW_LABELS).filter(([k]) => sw(p)[k] === true).map(([, l]) => l);
  const onHw = HW.filter((h) => h.fn(p)).map((h) => h.label);
  const region = c.country_code
    ? `<div class="caps-region">Regulatory region <b>${escapeHtml(c.country_code)}</b></div>` : "";
  const chips = [...onSw, ...onHw].map((f) => `<span class="flag">${escapeHtml(f)}</span>`).join("");
  if (!region && !chips) return "";
  return `<div class="caps">${region}<div class="caps-flags">${chips}</div></div>`;
}

function methodRow(service, method, rec) {
  const present = PRESENT.has(rec.status);
  let cov = "";
  if (rec.covered_by) cov = badge(`gli4py: ${rec.covered_by}`, "cov-yes");
  else if (present) cov = badge("not in gli4py", "cov-no");
  const parts = [];
  if (rec.signature != null) parts.push(block("Response signature", JSON.stringify(rec.signature, null, 2)));
  const inferred = rec.risk === "write" && !(rec.params && rec.params.length)
    ? pairedRead(profile, service, method) : null;
  if (inferred) parts.push(block(`Request shape · inferred from ${inferred.from}`, JSON.stringify(inferred.shape, null, 2), true));
  else if (rec.params && rec.params.length) parts.push(block("Params", JSON.stringify(rec.params, null, 2), true));
  const detail = parts.length ? `<div class="detail">${parts.join("")}</div>` : "";
  return `<div class="method">
    <div class="mhead">
      <span class="mname">${escapeHtml(method)}</span>
      ${badge(rec.status, "st-" + rec.status)}
      ${badge(rec.risk, "rk-" + rec.risk)}
      <span class="spacer"></span>${cov}
    </div>${detail}</div>`;
}

function renderProfile(p) {
  const services = [];
  for (const service of Object.keys(p.services).sort()) {
    const methods = p.services[service];
    const rows = Object.keys(methods).sort().map((m) => methodRow(service, m, methods[m]));
    services.push(`<section class="service"><h3>${escapeHtml(service)}` +
      `<span class="svc-count">${rows.length}</span></h3>${rows.join("")}</section>`);
  }
  return renderCaps(p) + `<div class="results">${services.join("")}</div>`;
}

function setProgress(message, done) {
  $("progress-msg").textContent = message || "";
  $("progress-count").textContent = (typeof done === "number" && done > 0) ? `${done} checked` : "";
}
function showProgress(on) { $("progress").hidden = !on; }

async function onCapture(e) {
  e.preventDefault();
  const dangerous = $("dangerous").checked;
  const destructive = $("destructive").checked && dangerous;
  if (dangerous && !confirm(
    destructive
      ? "RECKLESS: this will CALL write endpoints AND destructive methods (reboot / factory-reset / firmware) on your router. Only do this on a sacrificial device. Continue?"
      : "DANGEROUS: this will CALL write endpoints on your router, changing its configuration. Only do this on a spare device. Continue?"
  )) return;
  $("status").textContent = "";
  $("result").innerHTML = ""; $("banner").innerHTML = ""; $("actions").hidden = true;
  setProgress("Starting…", null); showProgress(true);
  try {
    const res = await fetch("api/enumerate", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Profiler-Token": token },
      body: JSON.stringify({
        host: $("host").value.trim(),
        username: $("username").value.trim() || "root",
        password: $("password").value,
        ssh: $("ssh").checked,
        dangerous: dangerous,
        include_destructive: destructive,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "", result = null, errorMsg = null;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.event === "progress") setProgress(ev.message, ev.done);
        else if (ev.event === "result") result = ev;
        else if (ev.event === "error") errorMsg = ev.message;
      }
    }
    const tail = (buf + decoder.decode()).trim();  // flush a final line lacking a trailing newline
    if (tail) {
      const ev = JSON.parse(tail);
      if (ev.event === "result") result = ev;
      else if (ev.event === "error") errorMsg = ev.message;
    }
    showProgress(false);
    if (errorMsg) { $("result").innerHTML = `<p class="error">${escapeHtml(errorMsg)}</p>`; return; }
    if (!result) { $("result").innerHTML = '<p class="error">No result received.</p>'; return; }
    profile = result.profile; submitUrl = result.submit_url || "";
    if (result.registry_reachable === false) {
      $("banner").innerHTML = '<div class="new">⚠️ Couldn\'t reach the registry — submit anyway; the bot will dedup.</div>';
    } else {
      $("banner").innerHTML = result.lookup
        ? `<div class="known">✅ <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is already in the registry.</div>`
        : `<div class="new">🆕 <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is new — please contribute it!</div>`;
    }
    $("result").innerHTML = renderProfile(profile);
    $("actions").hidden = false;
    $("submit").classList.toggle("primary", !result.lookup);
  } catch (err) {
    showProgress(false);
    $("result").innerHTML = `<p class="error">${escapeHtml(err.message || err)}</p>`;
  }
}

function onDownload() {
  const blob = new Blob([JSON.stringify(profile, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = `${profile.id}.json`; a.click();
  URL.revokeObjectURL(a.href);
}
function onSubmit() { if (submitUrl) window.open(submitUrl, "_blank", "noopener"); }

$("form").addEventListener("submit", onCapture);
$("download").addEventListener("click", onDownload);
$("submit").addEventListener("click", onSubmit);
$("result").addEventListener("click", (e) => {
  const m = e.target.closest(".method");
  if (m) m.classList.toggle("open");
});
// destructive probing only unlocks once write-probing is enabled
$("dangerous").addEventListener("change", () => {
  $("destructive").disabled = !$("dangerous").checked;
  if (!$("dangerous").checked) $("destructive").checked = false;
});
