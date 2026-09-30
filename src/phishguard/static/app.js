// PhishGuard web UI. No dependencies, no third-party requests.
// Every value that comes from an analyzed URL or e-mail is untrusted: it is only ever
// inserted with textContent (via el()), never as HTML.
"use strict";

const VERDICTS = {
  low_risk: { label: "Riesgo bajo", note: "Sin señales fuertes. No garantiza que sea seguro." },
  suspicious: { label: "Sospechoso", note: "Hay señales de alerta. No introduzcas datos en ese sitio." },
  phishing: { label: "Phishing", note: "Varios indicadores de phishing. No abras el enlace." },
};
const MAX_BATCH = 100;
const MAX_EMAIL_BYTES = 5 * 1024 * 1024;
const TRACE_URL = "http://paypa1-login.xyz/verify/account";

const SAMPLE_EMAIL = [
  "Return-Path: <bounce@mailer-notify.top>",
  "Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=mailer-notify.top; dkim=none; dmarc=fail header.from=bbva-mx-seguridad.com",
  'From: "BBVA Mexico Seguridad" <alertas@bbva-mx-seguridad.com>',
  "Reply-To: soporte.clientes@gmail.com",
  "To: cliente@example.com",
  "Subject: Urgente: su cuenta ha sido suspendida",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="MIXED"',
  "",
  "--MIXED",
  'Content-Type: text/html; charset="utf-8"',
  "",
  "<p>Detectamos <b>actividad inusual</b>. Su cuenta ha sido suspendida.</p>",
  '<p>Verifique su cuenta en las próximas 24 horas: <a href="http://bbva-mx-seguridad.com/acceso/verificar">https://www.bbva.mx/acceso</a></p>',
  "",
  "--MIXED",
  "Content-Type: application/octet-stream",
  'Content-Disposition: attachment; filename="estado_de_cuenta.pdf.exe"',
  "Content-Transfer-Encoding: base64",
  "",
  "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAA",
  "--MIXED--",
  "",
].join("\n");

// ---------- helpers ----------

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "className") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(2)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

class ApiError extends Error {}

async function api(path, { json, form } = {}) {
  const options = form ? { method: "POST", body: form }
    : json !== undefined ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(json) }
    : undefined;
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new ApiError("No se pudo contactar con el servidor local. Comprueba que uvicorn sigue en marcha.");
  }
  let data = null;
  try { data = await response.json(); } catch { /* non-JSON error body */ }
  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : "la entrada no es válida";
    throw new ApiError(detail.charAt(0).toUpperCase() + detail.slice(1) + ".");
  }
  return data;
}

const percent = (value, digits = 0) => `${(value * 100).toFixed(digits)} %`;

// ---------- output ----------

const output = $("#output");

function showError(message, hint) {
  output.replaceChildren(el("div", { className: "alert", role: "alert" },
    el("p", { text: message }), hint ? el("p", { text: hint }) : null));
}

async function withLoading(button, task) {
  const label = button.textContent;
  button.disabled = true;
  if (!button.classList.contains("go")) button.textContent = "Analizando…";
  output.setAttribute("aria-busy", "true");
  try {
    output.replaceChildren(await task());
  } catch (error) {
    showError(error instanceof ApiError ? error.message : "No se pudo mostrar el resultado.",
      error instanceof ApiError ? null : String(error));
  } finally {
    button.disabled = false;
    button.textContent = label;
    output.setAttribute("aria-busy", "false");
  }
}

// ---------- report pieces ----------

const mark = (verdict) => el("span", { className: `mark mark-${verdict}`, "aria-hidden": "true" });

function verdictLine(score, verdict) {
  const info = VERDICTS[verdict];
  return el("div", { className: "verdict-line" },
    el("p", { className: "score", "aria-label": `Score ${score} de 100` }, String(score), el("small", { text: "/100" })),
    el("div", {},
      el("p", { className: `verdict t-${verdict}` }, mark(verdict), info.label),
      el("p", { className: "verdict-note", text: info.note })));
}

function scale(score, verdict) {
  const fill = el("div", { className: `scale-fill f-${verdict}`, style: `width: ${Math.max(score, 1)}%` });
  return [
    el("div", { className: "scale", "aria-hidden": "true" }, fill,
      el("span", { className: "scale-tick", style: "left: 30%" }),
      el("span", { className: "scale-tick", style: "left: 60%" })),
    el("div", { className: "scale-legend", "aria-hidden": "true" },
      el("span", { style: "left: 0", text: "0" }),
      el("span", { style: "left: 30%", text: "30 sospechoso" }),
      el("span", { style: "left: 60%", text: "60 phishing" })),
  ];
}

function facts(pairs) {
  return el("dl", { className: "facts" },
    pairs.map(([k, v]) => el("div", {}, el("dt", { text: k }), el("dd", { text: v }))));
}

function findingsList(findings) {
  if (!findings.length) return el("p", { className: "none", text: "No se activó ninguna regla." });
  return el("ol", { className: "findings" }, findings.map((f) => {
    const level = f.weight >= 25 ? "w-high" : f.weight === 0 ? "w-zero" : "";
    return el("li", { className: "finding" },
      el("span", { className: `w ${level}`, text: f.weight ? `+${f.weight}` : "info" }),
      el("code", { className: "r", text: f.rule }),
      el("p", { className: "m" }, f.message, f.evidence ? el("code", { className: "e", text: f.evidence }) : null));
  }));
}

function jsonActions(data) {
  const text = JSON.stringify(data, null, 2);
  const pre = el("pre", { className: "json", hidden: true, tabindex: "0" }, text);
  const toggle = el("button", {
    type: "button", className: "btn btn-line", "aria-expanded": "false", text: "Ver JSON",
    onclick: () => {
      pre.hidden = !pre.hidden;
      toggle.setAttribute("aria-expanded", String(!pre.hidden));
      toggle.textContent = pre.hidden ? "Ver JSON" : "Ocultar JSON";
    },
  });
  const copy = el("button", { type: "button", className: "btn btn-line", text: "Copiar JSON",
    onclick: () => copyText(text, copy, "Copiar JSON") });
  return [el("div", { className: "actions" }, toggle, copy), pre];
}

function resultRows(items) {
  // items: [{ score, verdict, url, detail }]
  return el("div", { className: "rows" }, items.map((item) => {
    if (item.error) {
      return el("div", { className: "row" },
        el("span", { className: "s", text: "—" }),
        el("span", { className: "v", text: "No válida" }),
        el("span", { className: "u" }, `${item.url} · ${item.error}`));
    }
    const detail = el("div", { className: "row-detail", hidden: true }, item.detail);
    const button = el("button", {
      type: "button", "aria-expanded": "false", text: item.url,
      onclick: () => {
        detail.hidden = !detail.hidden;
        button.setAttribute("aria-expanded", String(!detail.hidden));
      },
    });
    return [
      el("div", { className: "row" },
        el("span", { className: "s", text: item.score }),
        el("span", { className: `v t-${item.verdict}` }, mark(item.verdict), VERDICTS[item.verdict].label),
        el("span", { className: "u" }, button)),
      detail,
    ];
  }));
}

// ---------- reports ----------

function urlReport(report) {
  return el("article", { className: "report", "aria-label": "Informe de la URL" },
    verdictLine(report.score, report.verdict),
    scale(report.score, report.verdict),
    facts([
      ["URL", report.normalized_url],
      ["Host", report.host || "—"],
      ["Dominio real", report.registered_domain || "—"],
      ["Modelo", report.ml_probability == null ? "No aplica" : `${percent(report.ml_probability, 1)} de probabilidad`],
    ]),
    el("h3", { className: "sub-title", text: `Indicadores · ${report.findings.length}` }),
    findingsList(report.findings),
    jsonActions(report));
}

function batchReport(items) {
  const counts = { phishing: 0, suspicious: 0, low_risk: 0 };
  const ok = items.filter((item) => item.report).sort((a, b) => b.report.score - a.report.score);
  ok.forEach((item) => { counts[item.report.verdict] += 1; });
  const invalid = items.length - ok.length;
  const tally = [["Analizadas", items.length], ["Phishing", counts.phishing],
                 ["Sospechosas", counts.suspicious], ["Riesgo bajo", counts.low_risk]];
  if (invalid) tally.push(["No válidas", invalid]);

  return el("article", { className: "report", "aria-label": "Resultado del lote" },
    el("div", { className: "tally" }, tally.map(([k, v]) => el("div", {}, el("b", { text: v }), el("span", { text: k })))),
    resultRows([
      ...ok.map((item) => ({ score: item.report.score, verdict: item.report.verdict, url: item.url,
                             detail: findingsList(item.report.findings) })),
      ...items.filter((item) => !item.report),
    ]),
    jsonActions(items));
}

function emailReport(report) {
  return el("article", { className: "report", "aria-label": "Informe del correo" },
    verdictLine(report.score, report.verdict),
    scale(report.score, report.verdict),
    facts([
      ["Asunto", report.subject || "(sin asunto)"],
      ["Remitente", report.sender || "—"],
      ["Enlaces", String(report.links.length)],
      ["Adjuntos", String(report.attachments.length)],
    ]),
    el("h3", { className: "sub-title", text: `Indicadores · ${report.findings.length}` }),
    findingsList(report.findings),
    report.links.length ? [
      el("h3", { className: "sub-title", text: `Enlaces · ${report.links.length}` }),
      resultRows(report.links.map((link) => ({
        score: link.report.score, verdict: link.report.verdict, url: link.url,
        detail: [link.text ? el("p", { className: "e", text: `Texto visible: ${link.text}` }) : null,
                 findingsList(link.report.findings)],
      }))),
    ] : null,
    report.attachments.length ? [
      el("h3", { className: "sub-title", text: "Adjuntos" }),
      el("ul", { className: "attachments" }, report.attachments.map((name) => el("li", { text: name }))),
    ] : null,
    jsonActions(report));
}

// ---------- tabs + copy ----------

function setupTabs(tablist) {
  const tabs = $$('[role="tab"]', tablist);
  const select = (tab, focus) => {
    for (const t of tabs) {
      const selected = t === tab;
      t.setAttribute("aria-selected", String(selected));
      t.tabIndex = selected ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !selected;
    }
    if (focus) tab.focus();
  };
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => select(tab, false));
    tab.addEventListener("keydown", (event) => {
      const moves = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 };
      if (!(event.key in moves)) return;
      event.preventDefault();
      select(tabs[(moves[event.key] + tabs.length) % tabs.length], true);
    });
  });
}

async function copyText(text, button, label) {
  try {
    await navigator.clipboard.writeText(text);
    button.dataset.state = "success";
    button.textContent = "Copiado";
  } catch {
    button.textContent = "No se pudo copiar";
  }
  setTimeout(() => { delete button.dataset.state; button.textContent = label; }, 1600);
}

// ---------- forms ----------

function setupUrlForm() {
  const form = $("#panel-url");
  const input = $("#url-input");
  const field = $(".bigfield", form);
  const button = $(".go", form);
  input.addEventListener("input", () => field.removeAttribute("aria-invalid"));

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const url = input.value.trim();
    if (!url) {
      field.setAttribute("aria-invalid", "true");
      showError("Pega una URL para analizarla.");
      input.focus();
      return;
    }
    withLoading(button, async () => urlReport(await api("/analyze", { json: { url } })));
  });

  $$("[data-example]", form).forEach((example) => example.addEventListener("click", () => {
    input.value = example.dataset.example;
    form.requestSubmit();
  }));

  // Shareable links: /?url=<encoded url> opens with the analysis already run.
  const shared = new URLSearchParams(window.location.search).get("url");
  if (shared) {
    input.value = shared;
    form.requestSubmit();
  }
}

function setupBatchForm() {
  const form = $("#panel-batch");
  const textarea = $("#batch-input");
  const count = $("#batch-count");
  const button = $('button[type="submit"]', form);
  const lines = () => textarea.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  textarea.addEventListener("input", () => {
    const n = lines().length;
    count.textContent = `${n} ${n === 1 ? "URL" : "URLs"}${n > MAX_BATCH ? ` · el máximo es ${MAX_BATCH}` : ""}`;
    textarea.toggleAttribute("aria-invalid", n > MAX_BATCH);
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const urls = lines();
    if (!urls.length) { showError("Escribe al menos una URL, una por línea."); textarea.focus(); return; }
    if (urls.length > MAX_BATCH) { showError(`El lote tiene ${urls.length} URLs; el máximo es ${MAX_BATCH}.`); return; }
    withLoading(button, async () => batchReport(await api("/analyze/batch", { json: { urls } })));
  });
}

function setupEmailForm() {
  const form = $("#panel-email");
  const fileInput = $("#email-file");
  const drop = $("#email-drop");
  const fileName = $("#email-file-name");
  const raw = $("#email-raw");
  const button = $('button[type="submit"]', form);
  const defaultText = fileName.textContent;
  let file = null;

  const setFile = (f) => {
    file = f || null;
    drop.classList.toggle("has-file", Boolean(file));
    fileName.textContent = file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KB` : defaultText;
  };
  fileInput.addEventListener("change", () => setFile(fileInput.files[0]));
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("is-over")));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });

  $("#email-sample").addEventListener("click", () => {
    setFile(null);
    fileInput.value = "";
    raw.value = SAMPLE_EMAIL;
    raw.closest("details").open = true;
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (file) {
      if (file.size > MAX_EMAIL_BYTES) { showError("El archivo supera los 5 MB."); return; }
      const body = new FormData();
      body.append("file", file);
      withLoading(button, async () => emailReport(await api("/analyze/email/upload", { form: body })));
    } else if (raw.value.trim()) {
      withLoading(button, async () => emailReport(await api("/analyze/email", { json: { raw: raw.value } })));
    } else {
      showError("Elige un archivo .eml o pega el código fuente del correo.",
        "El código fuente incluye las cabeceras (From, Authentication-Results…), no solo el texto visible.");
    }
  });
}

// ---------- live sections ----------

const line = (key, value, hot) =>
  [el("span", { className: "k", text: key.padEnd(11, " ") }), el("span", { className: hot ? "hot" : null, text: value }), "\n"];

async function loadTrace() {
  const slot = (name) => $(`[data-trace="${name}"]`);
  try {
    const report = await api("/analyze", { json: { url: TRACE_URL } });
    slot("parse").replaceChildren(
      ...line("host", report.host), ...line("dominio", report.registered_domain),
      ...line("esquema", report.normalized_url.split(":")[0]));
    slot("rules").replaceChildren(...report.findings.filter((f) => f.rule !== "ml_model")
      .flatMap((f) => [el("span", { className: f.weight >= 25 ? "hot" : null, text: `+${f.weight}`.padEnd(5, " ") }), f.rule, "\n"]));
    const ml = report.findings.find((f) => f.rule === "ml_model");
    slot("ml").replaceChildren(...(report.ml_probability == null ? line("modelo", "no aplica") : [
      ...line("prob.", percent(report.ml_probability, 1)),
      ...line("suma", ml ? `+${ml.weight}` : "0 (menos de 80 %)", Boolean(ml))]));
    slot("verdict").replaceChildren(
      ...line("score", `${report.score}/100`, report.verdict !== "low_risk"),
      ...line("dictamen", VERDICTS[report.verdict].label.toUpperCase(), report.verdict !== "low_risk"));
  } catch {
    $$("[data-trace]").forEach((node) => { node.textContent = "No disponible: el servidor no respondió."; });
  }
}

async function loadModel() {
  const rows = $("#model-rows");
  try {
    const info = await api("/model");
    const metrics = info.test_metrics;
    $('[data-model="auc"]').textContent = metrics.roc_auc.toFixed(2);
    $('[data-model="samples"]').textContent = (info.samples.legitimate + info.samples.phishing).toLocaleString("es-MX");
    $('[data-model="date"]').textContent = info.trained_on;
    rows.replaceChildren(...Object.entries(metrics.by_threshold).map(([threshold, m]) =>
      el("tr", { className: Number(threshold) >= 0.8 ? "in-use" : null },
        el("td", { text: `p ≥ ${threshold}` }),
        el("td", { className: "num", text: m.precision.toFixed(2) }),
        el("td", { className: "num", text: m.recall.toFixed(2) }),
        el("td", { className: "num", text: percent(m.false_positive_rate, 1) }))));
  } catch {
    rows.replaceChildren(el("tr", {}, el("td", { colspan: "4", className: "muted", text: "No hay un modelo entrenado en este servidor." })));
  }
}

async function loadVersion() {
  try { $("#version").textContent = `v${(await api("/health")).version}`; } catch { /* keep empty */ }
}

document.addEventListener("DOMContentLoaded", () => {
  setupTabs($(".modes"));
  setupTabs($(".code-tabs"));
  const copy = $("[data-copy-active]");
  copy.addEventListener("click", () => {
    const panel = $$('.code [role="tabpanel"]').find((p) => !p.hidden);
    copyText(panel.textContent, copy, "Copiar");
  });
  setupUrlForm();
  setupBatchForm();
  setupEmailForm();
  loadTrace();
  loadModel();
  loadVersion();
});
