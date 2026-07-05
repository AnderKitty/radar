/* Radar.uy — carga stats.json (solo agregados) y renderiza el reporte.
   Vanilla, sin dependencias. Adaptado del diseño de Claude Design a datos reales. */
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fmt = (n) => (n || 0).toLocaleString("es-UY");
  const MONO = 'font-family:"IBM Plex Mono",monospace';

  /* ── Mapeos de presentación ─────────────────────────────────── */
  const DEV_RED = new Set(["EXPOSED_CAMERA", "EXPOSED_DATABASE", "EXPOSED_SERVICE", "ICS/SCADA", "NETWORK_DEVICE"]);
  const DEV_ORANGE = new Set(["CAMERA", "ADMIN_PANEL", "REMOTE_ACCESS", "HONEYPOT"]);
  const DEV_YELLOW = new Set(["ROUTER", "IOT_DEVICE", "PRINTER"]);
  const devColor = (k) =>
    DEV_RED.has(k) ? "#f85149" : DEV_ORANGE.has(k) ? "#f0883e" : DEV_YELLOW.has(k) ? "#d4a72c" : "#4493f8";

  const DEVLABEL = {
    CAMERA: "Cámaras", EXPOSED_CAMERA: "Cámaras expuestas", WEB_SERVER: "Servidores web",
    SERVER: "Servidores", HOST: "Hosts", ROUTER: "Routers", REMOTE_ACCESS: "Accesos remotos",
    ADMIN_PANEL: "Paneles de administración", EXPOSED_DATABASE: "Bases de datos expuestas",
    EXPOSED_SERVICE: "Servicios expuestos", "ICS/SCADA": "Control industrial", IOT_DEVICE: "Dispositivos IoT",
    NETWORK_DEVICE: "Equipos de red", PRINTER: "Impresoras", HONEYPOT: "Honeypots", CDN_EDGE: "Nodos CDN",
  };
  const devLabel = (k) => DEVLABEL[k] || k;

  const PORTNAME = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 554: "RTSP", 81: "HTTP-alt", 8080: "HTTP-alt",
    8000: "HTTP-alt", 8001: "HTTP-alt", 8002: "HTTP-alt", 8081: "HTTP-alt",
    3389: "RDP", 21: "FTP", 23: "Telnet", 25: "SMTP", 37777: "Dahua", 34567: "DVR", 8443: "HTTPS-alt",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 502: "Modbus", 102: "S7",
    1883: "MQTT", 8883: "MQTT-TLS", 2375: "Docker", 5900: "VNC", 9000: "Cámara", 161: "SNMP", 3000: "HTTP-alt",
  };
  const portLabel = (p) => (PORTNAME[p] ? `:${p} · ${PORTNAME[p]}` : `:${p}`);

  function prettyISP(name) {
    const s = (name || "").toLowerCase();
    if (s.includes("telecomunicaciones") || s.includes("antel")) return "ANTEL";
    if (s.includes("claro") || s.includes("america movil") || s.includes("amx") || s.includes("am wireless")) return "Claro";
    if (s.includes("telefonica") || s.includes("movistar")) return "Movistar";
    if (s.includes("dedicado")) return "Dedicado";
    if (s.includes("tv cable") || s.includes("cable")) return "TV Cable";
    return name.length > 24 ? name.slice(0, 24) + "…" : name;
  }

  const CVE_INFO = {
    "CVE-2017-7921": { product: "Hikvision · backdoor", severity: "CRITICAL" },
    "CVE-2021-36260": { product: "Hikvision · RCE", severity: "CRITICAL" },
    "CVE-2024-6387": { product: "OpenSSH · regreSSHion", severity: "HIGH" },
    "CVE-2021-41773": { product: "Apache 2.4.49 · RCE", severity: "CRITICAL" },
    "CVE-2021-42013": { product: "Apache 2.4.50 · RCE", severity: "CRITICAL" },
    "CVE-2019-10149": { product: "Exim · RCE", severity: "CRITICAL" },
    "CVE-2015-3306": { product: "ProFTPD · RCE", severity: "CRITICAL" },
    "CVE-2018-14847": { product: "MikroTik · lectura de credenciales", severity: "HIGH" },
    "CVE-2021-40438": { product: "Apache · SSRF", severity: "HIGH" },
  };
  const cveInfo = (id) => CVE_INFO[id] || { product: "Falla pública conocida", severity: "HIGH" };
  function sevColors(sev) {
    if (sev === "CRITICAL") return { bg: "rgba(248,81,73,0.14)", fg: "#ff8a84" };
    if (sev === "HIGH") return { bg: "rgba(240,136,62,0.14)", fg: "#f0883e" };
    if (sev === "MEDIUM") return { bg: "rgba(212,167,44,0.14)", fg: "#d4a72c" };
    return { bg: "rgba(68,147,248,0.14)", fg: "#4493f8" };
  }

  /* ── Helper de DOM ──────────────────────────────────────────── */
  function el(tag, style, text) {
    const n = document.createElement(tag);
    if (style) n.style.cssText = style;
    if (text != null) n.textContent = text;
    return n;
  }

  /* ── Carga ──────────────────────────────────────────────────── */
  fetch("stats.json", { cache: "no-store" })
    .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(render)
    .catch(() => document.body.classList.add("load-failed"));

  function render(d) {
    $("#last-run").textContent = d.last_run || "02:00 · America/Montevideo";
    document.querySelectorAll(".updated").forEach((n) => (n.textContent = fmtDate(d.scan_date || d.updated)));

    const c = d.by_criticality || {};
    const auth = d.by_auth_state || {};
    const targets = {
      crit: c.CRITICAL || 0, high: c.HIGH || 0, med: c.MEDIUM || 0, low: c.LOW || 0,
      hosts: d.total_devices || 0, open: auth.open || 0,
    };
    if (d.ips_scanned != null) targets.ips = d.ips_scanned;
    else $("#card-ips").style.display = "none";

    barChart("#device-bars", (d.by_device_type || []).slice(0, 9)
      .map((x) => ({ label: devLabel(x.key), value: x.count, color: devColor(x.key) })), "120px,150px");
    barChart("#brand-bars", (d.by_brand || []).slice(0, 8)
      .map((x) => ({ label: x.key, value: x.count, color: "#4493f8" })), "110px,130px");
    barChart("#isp-bars", ispRows(d.by_isp || []).map((x) => ({ ...x, color: "#7c8dff" })), "110px,130px");
    barChart("#port-bars", (d.by_port || []).slice(0, 8)
      .map((x) => ({ label: portLabel(x.key), value: x.count, color: "#3fb3a8" })), "120px,150px");
    barChart("#dept-bars", (d.by_department || []).slice(0, 10)
      .map((x) => ({ label: x.key, value: x.count, color: "#bc8cff" })), "120px,150px");

    authChart(auth);
    cveList(d.by_cve || []);
    trend(d.history || []);
    startCounters(targets);
  }

  /* ── ISPs: fusionar por nombre lindo, top 6 ─────────────────── */
  function ispRows(list) {
    const m = new Map();
    list.forEach((x) => { const k = prettyISP(x.key); m.set(k, (m.get(k) || 0) + x.count); });
    return [...m.entries()].map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value).slice(0, 6);
  }

  /* ── Barras horizontales ────────────────────────────────────── */
  function barChart(sel, rows, labelCol) {
    const host = $(sel); host.textContent = "";
    const max = Math.max(1, ...rows.map((r) => r.value));
    rows.forEach((r) => {
      const row = el("div", `display:grid;grid-template-columns:minmax(${labelCol}) 1fr auto;gap:14px;align-items:center`);
      const lbl = el("div", `${MONO};font-size:12px;color:#9aa7b6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis`, r.label);
      lbl.title = r.label;
      const track = el("div", "height:9px;border-radius:6px;background:rgba(255,255,255,0.05);overflow:hidden");
      track.appendChild(el("div", `height:100%;border-radius:6px;width:${Math.max(2, (r.value / max) * 100)}%;background:${r.color}`));
      const val = el("div", `${MONO};font-size:12px;color:#e6edf3;min-width:52px;text-align:right`, fmt(r.value));
      row.append(lbl, track, val);
      host.appendChild(row);
    });
  }

  /* ── Estado de autenticación ────────────────────────────────── */
  function authChart(auth) {
    const host = $("#auth-bars"); host.textContent = "";
    const rows = [
      { label: "Requiere credenciales", value: auth["auth-required"] || 0, color: "#3fb950" },
      { label: "Sin autenticación (open)", value: auth.open || 0, color: "#f85149" },
      { label: "Desconocido", value: auth.unknown || 0, color: "#5f6b7a" },
    ];
    const max = Math.max(1, ...rows.map((r) => r.value));
    rows.forEach((r) => {
      const wrap = el("div");
      const top = el("div", `display:flex;justify-content:space-between;${MONO};font-size:12.5px;margin-bottom:7px`);
      top.append(el("span", "color:#9aa7b6", r.label), el("span", "color:#e6edf3", fmt(r.value)));
      const track = el("div", "height:9px;border-radius:6px;background:rgba(255,255,255,0.05);overflow:hidden");
      track.appendChild(el("div", `height:100%;border-radius:6px;width:${Math.max(2, (r.value / max) * 100)}%;background:${r.color}`));
      wrap.append(top, track);
      host.appendChild(wrap);
    });
  }

  /* ── CVEs ───────────────────────────────────────────────────── */
  function cveList(list) {
    const host = $("#cve-rows"); host.textContent = "";
    if (!list.length) {
      host.appendChild(el("div", "font-size:13px;color:#5f6b7a;padding:8px 0", "Sin CVEs inferidos en este barrido."));
      return;
    }
    list.slice(0, 6).forEach((x) => {
      const info = cveInfo(x.key), sv = sevColors(info.severity);
      const row = el("div", "display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid rgba(255,255,255,0.05)");
      const left = el("div", "min-width:0");
      left.append(el("div", `${MONO};font-size:13px;color:#e6edf3`, x.key),
        el("div", "font-size:12px;color:#9aa7b6;margin-top:2px", info.product));
      const right = el("div", "display:flex;align-items:center;gap:12px;flex-shrink:0");
      right.append(
        el("span", `${MONO};font-size:10.5px;letter-spacing:0.06em;padding:3px 8px;border-radius:5px;background:${sv.bg};color:${sv.fg}`, info.severity),
        el("span", `${MONO};font-size:13px;color:#9aa7b6;min-width:44px;text-align:right`, fmt(x.count)));
      row.append(left, right);
      host.appendChild(row);
    });
  }

  /* ── Tendencia (críticos por día) ───────────────────────────── */
  function trend(hist) {
    const host = $("#hist-bars"); host.textContent = "";
    const rows = hist.slice(-30);
    if (!rows.length) {
      host.appendChild(el("div", `${MONO};font-size:12px;color:#5f6b7a;align-self:center`, "La serie diaria se va llenando con cada barrido."));
      return;
    }
    const max = Math.max(1, ...rows.map((h) => h.critical || 0));
    rows.forEach((h) => {
      const v = h.critical || 0;
      const bar = el("div", `flex:1;height:${Math.max(6, (v / max) * 100)}%;background:linear-gradient(180deg,#f85149,rgba(248,81,73,0.25));border-radius:3px 3px 0 0;min-height:5px`);
      bar.title = `${h.date}: ${fmt(v)} críticos`;
      host.appendChild(bar);
    });
  }

  /* ── Contadores animados ────────────────────────────────────── */
  function startCounters(targets) {
    const run = () => animateCounters(targets);
    if (reduce || !("IntersectionObserver" in window)) { run(); return; }
    const io = new IntersectionObserver((ents, obs) => {
      if (ents.some((e) => e.isIntersecting)) { run(); obs.disconnect(); }
    }, { threshold: 0.15 });
    io.observe($("#numeros"));
  }

  function animateCounters(targets) {
    const nodes = [...document.querySelectorAll(".kpi-num[data-kpi]")];
    const set = (k, v) => nodes.forEach((n) => { if (n.dataset.kpi === k) n.textContent = fmt(v); });
    if (reduce) { for (const k in targets) set(k, targets[k]); return; }
    const start = performance.now(), dur = 1500, ease = (t) => 1 - Math.pow(1 - t, 3);
    (function tick(now) {
      const e = ease(Math.min(1, (now - start) / dur));
      for (const k in targets) set(k, Math.round(targets[k] * e));
      if ((now - start) / dur < 1) requestAnimationFrame(tick);
    })(start);
  }

  /* ── Fecha ──────────────────────────────────────────────────── */
  function fmtDate(iso) {
    if (!iso) return "—";
    const [y, m, dd] = String(iso).split("-").map(Number);
    const mes = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];
    return `${dd} ${mes[(m || 1) - 1]} ${y}`;
  }
})();

// ---- Mapa del registro público (realce progresivo) ----------------------
(function () {
  var _regMap = null, _regLayer = null;
  window.renderRegistryMap = function (entries) {
    var el = document.getElementById('reg-map');
    if (!el || typeof L === 'undefined') return; // sin Leaflet: la lista alcanza
    if (!_regMap) {
      _regMap = L.map(el, { scrollWheelZoom: false }).setView([-32.8, -55.9], 6);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap', maxZoom: 18
      }).addTo(_regMap);
      _regLayer = L.layerGroup().addTo(_regMap);
    }
    _regLayer.clearLayers();
    entries.forEach(function (e) {
      if (!e.location) return;
      var meta = Registry.categoryMeta(e.category);
      var m = L.circleMarker([e.location.lat, e.location.lng], {
        radius: 7, color: meta.color, fillColor: meta.color, fillOpacity: 0.8, weight: 2
      });
      // popup construido con nodos DOM (textContent) — nunca innerHTML con datos
      var div = document.createElement('div');
      var strong = document.createElement('strong');
      strong.textContent = e.name;
      div.appendChild(strong);
      div.appendChild(document.createElement('br'));
      div.appendChild(document.createTextNode(meta.label));
      div.appendChild(document.createElement('br'));
      var a = document.createElement('a');
      a.href = /^https?:\/\//i.test(e.url) ? e.url : '#';
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'Abrir →';
      div.appendChild(a);
      m.bindPopup(div);
      m.addTo(_regLayer);
    });
  };
})();

// ---- Información pública accesible (registro curado) ---------------------
function renderPublicRegistry(entries) {
  var listEl = document.getElementById('reg-list');
  var filterEl = document.getElementById('reg-filters');
  if (!listEl) return;
  var current = 'all';

  function draw() {
    var rows = Registry.filterByCategory(entries, current);
    listEl.innerHTML = '';
    if (rows.length === 0) {
      var empty = document.createElement('p');
      empty.className = 'reg-empty';
      empty.textContent = 'Aún no hay recursos verificados en esta categoría.';
      listEl.appendChild(empty);
    } else {
      rows.forEach(function (e) {
        var meta = Registry.categoryMeta(e.category);
        var card = document.createElement('a');
        card.className = 'reg-card';
        card.href = /^https?:\/\//i.test(e.url) ? e.url : '#'; card.target = '_blank'; card.rel = 'noopener noreferrer';
        var dot = document.createElement('span');
        dot.className = 'reg-dot'; dot.style.background = meta.color;
        var body = document.createElement('div');
        var name = document.createElement('div');
        name.className = 'reg-name'; name.textContent = e.name;
        var sub = document.createElement('div');
        sub.className = 'reg-sub';
        sub.textContent = meta.label + ' · ' + e.operator + ' · ' + e.department;
        body.appendChild(name); body.appendChild(sub);
        card.appendChild(dot); card.appendChild(body);
        listEl.appendChild(card);
      });
    }
    if (window.renderRegistryMap) {
      window.renderRegistryMap(rows);
    }
  }

  if (filterEl) {
    var counts = Registry.countByCategory(entries);
    var cats = ['all'].concat(Object.keys(Registry.CATEGORIES).filter(function (c) { return counts[c]; }));
    filterEl.innerHTML = '';
    cats.forEach(function (c) {
      var b = document.createElement('button');
      b.className = 'reg-filter';
      b.textContent = c === 'all'
        ? 'Todos (' + entries.length + ')'
        : Registry.categoryMeta(c).label + ' (' + counts[c] + ')';
      b.onclick = function () {
        current = c;
        draw();
        Array.prototype.forEach.call(filterEl.children, function (x) {
          x.classList.toggle('active', x === b);
        });
      };
      filterEl.appendChild(b);
    });
    if (filterEl.firstChild) filterEl.firstChild.classList.add('active');
  }
  draw();
}
window.renderPublicRegistry = renderPublicRegistry;

function loadPublicRegistry() {
  fetch('public-registry.json?cb=' + Date.now())
    .then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); })
    .then(function (data) { renderPublicRegistry(data); })
    .catch(function () {
      var errEl = document.getElementById('reg-error');
      if (errEl) errEl.style.display = 'block';
    });
}
loadPublicRegistry();
