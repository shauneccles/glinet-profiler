"use strict";
const token = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);
const PRESENT = new Set(["available", "needs_params"]);
let profile = null;
let submitUrl = "";

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function badge(t, c) { return `<span class="badge ${escapeHtml(c)}">${escapeHtml(t)}</span>`; }

function renderProfile(p) {
  const parts = [];
  for (const service of Object.keys(p.services).sort()) {
    const methods = p.services[service];
    const rows = [];
    for (const m of Object.keys(methods).sort()) {
      const rec = methods[m];
      let cov = "";
      if (rec.covered_by) cov = badge(`gli4py: ${rec.covered_by}`, "cov-yes");
      else if (PRESENT.has(rec.status)) cov = badge("not yet in gli4py", "cov-no");
      rows.push(`<div class="method"><code>${escapeHtml(m)}</code>${badge(rec.status, "st-" + rec.status)}${badge(rec.risk, "rk-" + rec.risk)}${cov}</div>`);
    }
    parts.push(`<section class="service"><h3>${escapeHtml(service)}</h3>${rows.join("")}</section>`);
  }
  return parts.join("");
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
    if (!result) { $("result").innerHTML = "<p class='error'>No result received.</p>"; return; }
    profile = result.profile; submitUrl = result.submit_url || "";
    if (result.registry_reachable === false) {
      $("banner").innerHTML = `<div class="new">⚠️ Couldn't reach the registry — submit anyway; the bot will dedup.</div>`;
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
// destructive probing only unlocks once write-probing is enabled
$("dangerous").addEventListener("change", () => {
  $("destructive").disabled = !$("dangerous").checked;
  if (!$("dangerous").checked) $("destructive").checked = false;
});
