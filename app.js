/* Zarpa · Radar de exposición — carga stats.json (solo agregados) y
   renderiza el reporte. Estética "Pizarra crepuscular": las barras de
   dispositivo van todas en azul; el riesgo se marca con una etiqueta al
   lado del nombre, no con el color de la barra. Vanilla, sin build. */
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fmt = (n) => (n || 0).toLocaleString("es-UY");

  /* ── qué tipos de dispositivo llevan etiqueta de riesgo ──────── */
  const DEV_CRIT = new Set(["EXPOSED_CAMERA", "EXPOSED_DATABASE", "EXPOSED_SERVICE", "ICS/SCADA"]);
  const DEV_RISK = new Set(["ADMIN_PANEL", "REMOTE_ACCESS", "NETWORK_DEVICE"]);
  const devFlag = (k) =>
    DEV_CRIT.has(k) ? { cls: "crit", txt: "concentra críticos" } :
    DEV_RISK.has(k) ? { cls: "risk", txt: "riesgo alto" } : null;

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
  const SEV = {
    CRITICAL: { bg: "var(--crit-wash)", fg: "var(--crit)" },
    HIGH: { bg: "var(--high-wash)", fg: "var(--high)" },
    MEDIUM: { bg: "var(--med-wash)", fg: "var(--med)" },
    LOW: { bg: "var(--low-wash)", fg: "var(--low)" },
  };
  const sevColors = (s) => SEV[s] || SEV.HIGH;

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /* ── Carga ──────────────────────────────────────────────────── */
  fetch("stats.json", { cache: "no-store" })
    .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(render)
    .catch(() => document.body.classList.add("load-failed"));

  function render(d) {
    $("#last-run").textContent = d.last_run || "~18:00 · America/Montevideo";
    document.querySelectorAll(".updated").forEach((n) => (n.textContent = fmtDate(d.scan_date || d.updated)));

    const c = d.by_criticality || {};
    const auth = d.by_auth_state || {};
    const targets = {
      crit: c.CRITICAL || 0, high: c.HIGH || 0, med: c.MEDIUM || 0, low: c.LOW || 0,
      hosts: d.total_devices || 0, open: auth.open || 0,
      alive: d.total_devices || 0, nocreds: auth.open || 0,
    };
    // IP barridas por ciclo: usa el campo si existe; si no, el tamaño real del barrido (~2,5 M)
    targets.ips = d.ips_scanned || 2500000;

    $("#crit-foot-meta").textContent =
      `2,5 M IP analizadas · ${fmt(d.total_devices || 0)} equipos vivos · ${fmt(auth.open || 0)} servicios sin credenciales`;

    barChart("#device-bars", (d.by_device_type || []).slice(0, 8)
      .map((x) => ({ label: devLabel(x.key), value: x.count, flag: devFlag(x.key) })));
    barChart("#brand-bars", (d.by_brand || []).slice(0, 7).map((x) => ({ label: x.key, value: x.count })));
    barChart("#isp-bars", ispRows(d.by_isp || []));
    barChart("#port-bars", (d.by_port || []).slice(0, 7).map((x) => ({ label: portLabel(x.key), value: x.count })));
    barChart("#dept-bars", (d.by_department || []).slice(0, 8).map((x) => ({ label: x.key, value: x.count })));

    authChart(auth);
    uyMap(d.by_department || []);
    cveList(d.by_cve || []);
    trend(d.history || []);
    criticalityDeltas(d);
    persistentNote(d);
    ispRank(d.by_isp_detail || []);
    webExposCard(d.by_web_exposure || []);
    externalCard(d.external);
    startCounters(targets);
  }

  /* ── Barras horizontales (todas azul; riesgo = etiqueta) ─────── */
  function barChart(sel, rows) {
    const host = $(sel);
    if (!host) return;
    host.textContent = "";
    const max = Math.max(1, ...rows.map((r) => r.value));
    rows.forEach((r) => {
      const row = el("div", "bar-row");
      const name = el("div", "bar-name");
      name.appendChild(el("span", "txt", r.label)).title = r.label;
      if (r.flag) name.appendChild(el("span", "bar-flag " + r.flag.cls, r.flag.txt));
      const track = el("div", "bar-track");
      const fill = el("div", "bar-fill");
      fill.dataset.w = Math.max(2, (r.value / max) * 100);
      track.appendChild(fill);
      row.append(name, track, el("div", "bar-val", fmt(r.value)));
      host.appendChild(row);
    });
    animateFills(host);
  }

  /* ── ISPs: fusionar por nombre lindo, top 6 ─────────────────── */
  function ispRows(list) {
    const m = new Map();
    list.forEach((x) => { const k = prettyISP(x.key); m.set(k, (m.get(k) || 0) + x.count); });
    return [...m.entries()].map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value).slice(0, 6);
  }

  /* ── Estado de autenticación ────────────────────────────────── */
  function authChart(auth) {
    const host = $("#auth-bars");
    if (!host) return;
    host.textContent = "";
    const rows = [
      { label: "Requiere credenciales", value: auth["auth-required"] || 0, color: "var(--ok)" },
      { label: "Sin autenticación (open)", value: auth.open || 0, color: "var(--crit)" },
      { label: "Desconocido", value: auth.unknown || 0, color: "var(--ink-4)" },
    ];
    const max = Math.max(1, ...rows.map((r) => r.value));
    rows.forEach((r) => {
      const wrap = el("div", "auth-row");
      const top = el("div", "auth-top");
      top.append(el("span", "k", r.label), el("span", "v", fmt(r.value)));
      const track = el("div", "auth-track");
      const fill = el("div", "auth-fill");
      fill.style.background = r.color;
      fill.dataset.w = Math.max(2, (r.value / max) * 100);
      track.appendChild(fill);
      wrap.append(top, track);
      host.appendChild(wrap);
    });
    animateFills(host, "auth-fill");
  }

  /* ── CVEs ───────────────────────────────────────────────────── */
  function cveList(list) {
    const host = $("#cve-rows");
    if (!host) return;
    host.textContent = "";
    if (!list.length) {
      host.appendChild(el("div", "reg-empty", "Sin CVEs inferidos en este barrido.")).style.padding = "8px 0";
      return;
    }
    list.slice(0, 6).forEach((x) => {
      const info = cveInfo(x.key), sv = sevColors(info.severity);
      const row = el("div", "cve-row");
      const left = el("div");
      left.append(el("div", "cve-id", x.key), el("div", "cve-prod", info.product));
      const right = el("div", "cve-right");
      const badge = el("span", "sev", info.severity);
      badge.style.background = sv.bg; badge.style.color = sv.fg;
      right.append(badge, el("span", "cve-count", fmt(x.count)));
      row.append(left, right);
      host.appendChild(row);
    });
  }
  /* ── Deltas por criticidad vs. ayer ────────────────────────── */
  function criticalityDeltas(d) {
    const c = d.by_criticality || {};
    const h = d.history || [];
    const prev = h.length >= 2 ? h[h.length - 2] : null;
    const map = [
      ["#crit-delta", "CRITICAL", "critical"], ["#high-delta", "HIGH", "high"],
      ["#med-delta", "MEDIUM", "medium"], ["#low-delta", "LOW", "low"],
    ];
    for (const [sel, critKey, histKey] of map) {
      const node = $(sel);
      if (!node) continue;
      if (!prev || prev[histKey] == null) { node.textContent = ""; continue; }
      const delta = (c[critKey] || 0) - prev[histKey];
      if (delta > 0) { node.textContent = "▲ +" + fmt(delta) + " vs. ayer"; node.style.color = "var(--crit)"; }
      else if (delta < 0) { node.textContent = "▼ −" + fmt(Math.abs(delta)) + " vs. ayer"; node.style.color = "var(--ok)"; }
      else { node.textContent = "= sin cambios vs. ayer"; node.style.color = "var(--ink-4)"; }
    }
  }

  /* ── Persistencia: cuántos críticos son exposición durable ──── */
  function persistentNote(d) {
    const p = d.persistent_by_criticality || {};
    const c = d.by_criticality || {};
    const map = [
      ["#crit-persist", "CRITICAL", true], ["#high-persist", "HIGH", false],
      ["#med-persist", "MEDIUM", false], ["#low-persist", "LOW", false],
    ];
    for (const [sel, key, hint] of map) {
      const node = $(sel);
      if (!node) continue;
      const total = c[key] || 0;
      if (p[key] == null || !total) { node.textContent = ""; continue; }
      const real = p[key], pct = Math.round((100 * real) / total);
      node.textContent = "▪ " + fmt(real) + " reales (" + pct + "%)" + (hint ? " · exposición durable" : "");
    }
  }

  /* ── Ranking por operador (ISP) ─────────────────────────────── */
  function ispRank(list) {
    const box = $("#isp-rank");
    if (!box || !list.length) return;
    const card = $("#isp-rank-card");
    if (card) card.style.display = "block";
    box.textContent = "";
    list.slice(0, 8).forEach((x) => {
      const pctOpen = x.total ? Math.round((100 * (x.open || 0)) / x.total) : 0;
      const row = el("div", "rank-row");
      const name = el("div", "isp", x.isp);
      name.title = x.isp;
      row.append(name, el("div", "num", fmt(x.total)), pctBar(pctOpen, "var(--high)"));
      box.appendChild(row);
    });
  }
  function pctBar(pct, color) {
    const wrap = el("div", "pctwrap");
    const track = el("div", "pctbar");
    const i = el("i");
    i.style.width = Math.max(2, pct) + "%"; i.style.background = color;
    track.appendChild(i);
    wrap.append(track, el("div", "pct", pct + "%"));
    return wrap;
  }

  /* ── Exposiciones web sensibles ─────────────────────────────── */
  const WEBEXP_LABEL = {
    exposed_git: "Repos git expuestos", exposed_env: "Archivos .env expuestos",
    exposed_server_status: "Apache server-status", open_dir_listing: "Listados de directorio",
  };
  function webExposCard(list) {
    if (!$("#webexp-bars") || !list.length) return;
    const card = $("#webexp-card");
    if (card) card.style.display = "block";
    barChart("#webexp-bars", list.map((x) => ({
      label: WEBEXP_LABEL[x.key] || x.key, value: x.count, flag: { cls: "crit", txt: "sensible" },
    })));
  }

  /* ── Fuera de Uruguay ───────────────────────────────────────── */
  function externalCard(ext) {
    const card = $("#external-card");
    if (!card || !ext || !ext.total_devices) return;
    card.style.display = "block";
    $("#external-total").textContent = fmt(ext.total_devices);
    $("#external-crit").textContent = fmt((ext.by_criticality || {}).CRITICAL || 0);
    barChart("#external-dev", (ext.by_device_type || []).slice(0, 6)
      .map((x) => ({ label: devLabel(x.key), value: x.count, flag: devFlag(x.key) })));
    barChart("#external-port", (ext.by_port || []).slice(0, 6).map((x) => ({ label: portLabel(x.key), value: x.count })));
  }

  /* ── Mapa de Uruguay: capitales coloreadas por nivel relativo ──
     El color sale del RANKING (cuartiles) del conteo por departamento,
     no del número: nunca se muestra la cantidad, solo "más / menos
     expuesto". Así respetamos la invariante de solo-agregados. */
  const DEPT_CAP = {
    "Montevideo":     { cap: "Montevideo",     lat: -34.905, lon: -56.191 },
    "Canelones":      { cap: "Canelones",      lat: -34.538, lon: -56.284 },
    "Maldonado":      { cap: "Maldonado",      lat: -34.909, lon: -54.958 },
    "Rocha":          { cap: "Rocha",          lat: -34.482, lon: -54.334 },
    "Treinta y Tres": { cap: "Treinta y Tres", lat: -33.224, lon: -54.383 },
    "Cerro Largo":    { cap: "Melo",           lat: -32.366, lon: -54.167 },
    "Rivera":         { cap: "Rivera",         lat: -30.905, lon: -55.550 },
    "Artigas":        { cap: "Artigas",        lat: -30.402, lon: -56.470 },
    "Salto":          { cap: "Salto",          lat: -31.383, lon: -57.961 },
    "Paysandú":       { cap: "Paysandú",       lat: -32.321, lon: -58.081 },
    "Río Negro":      { cap: "Fray Bentos",    lat: -33.139, lon: -58.303 },
    "Soriano":        { cap: "Mercedes",       lat: -33.255, lon: -58.030 },
    "Colonia":        { cap: "Colonia",        lat: -34.462, lon: -57.840 },
    "San José":       { cap: "San José",       lat: -34.337, lon: -56.713 },
    "Flores":         { cap: "Trinidad",       lat: -33.523, lon: -56.901 },
    "Florida":        { cap: "Florida",        lat: -34.099, lon: -56.214 },
    "Durazno":        { cap: "Durazno",        lat: -33.381, lon: -56.523 },
    "Lavalleja":      { cap: "Minas",          lat: -34.375, lon: -55.237 },
    "Tacuarembó":     { cap: "Tacuarembó",     lat: -31.712, lon: -55.981 },
  };
  // contorno real de Uruguay (lon/lat), derivado de GeoJSON oficial y simplificado
  const UY_OUTLINE = [[-57.068,-30.086],[-57.209,-30.286],[-57.496,-30.289],[-57.632,-30.171],[-57.641,-30.34],[-57.881,-30.495],[-57.802,-30.701],[-57.814,-30.923],[-57.908,-30.931],[-57.868,-31.018],[-57.916,-31.239],[-57.979,-31.394],[-58.087,-31.451],[-57.984,-31.596],[-58.072,-31.812],[-58.203,-31.855],[-58.137,-32.013],[-58.189,-32.155],[-58.097,-32.253],[-58.201,-32.455],[-58.107,-32.937],[-58.138,-33.043],[-58.383,-33.143],[-58.439,-33.539],[-58.504,-33.583],[-58.317,-34.144],[-57.872,-34.486],[-57.151,-34.459],[-56.831,-34.7],[-56.479,-34.765],[-56.337,-34.91],[-56.163,-34.952],[-55.691,-34.782],[-55.392,-34.812],[-55.285,-34.908],[-55.074,-34.894],[-54.949,-34.99],[-54.137,-34.673],[-54.035,-34.535],[-53.763,-34.418],[-53.73,-34.346],[-53.767,-34.304],[-53.536,-34.077],[-53.483,-33.889],[-53.363,-33.76],[-53.53,-33.689],[-53.505,-33.128],[-53.076,-32.735],[-53.59,-32.444],[-53.726,-32.093],[-53.965,-31.918],[-54.09,-31.932],[-54.454,-31.653],[-54.511,-31.506],[-54.837,-31.439],[-55.002,-31.272],[-55.063,-31.331],[-55.239,-31.257],[-55.35,-31.041],[-55.577,-30.835],[-55.827,-31.044],[-56.004,-31.084],[-55.99,-30.854],[-56.131,-30.734],[-56.168,-30.613],[-56.372,-30.501],[-56.455,-30.385],[-56.619,-30.299],[-56.647,-30.203],[-56.816,-30.102],[-57.068,-30.086]];

  function uyMap(deptList) {
    const host = $("#uy-map");
    if (!host) return;
    host.innerHTML = "";
    const NS = "http://www.w3.org/2000/svg";
    const mk = (t, a) => { const n = document.createElementNS(NS, t); for (const k in a) n.setAttribute(k, a[k]); return n; };

    // proyección equirectangular con ESCALA UNIFORME (conserva la forma):
    // la longitud se corrige por cos(lat media) y se usa el mismo factor
    // de escala en ambos ejes, así los puntos caen en su lugar real.
    const pad = 4;
    let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90;
    UY_OUTLINE.forEach(([lon, lat]) => {
      minLon = Math.min(minLon, lon); maxLon = Math.max(maxLon, lon);
      minLat = Math.min(minLat, lat); maxLat = Math.max(maxLat, lat);
    });
    const latMid = (minLat + maxLat) / 2;
    const kx = Math.cos((latMid * Math.PI) / 180); // achica la longitud según la latitud
    const geoW = (maxLon - minLon) * kx;
    const geoH = maxLat - minLat;
    // viewBox proporcional a la geografía real (evita el estirado)
    const AR = geoW / geoH;
    const H = 100, W = +(H * AR).toFixed(2);
    const sx = (W - 2 * pad) / geoW, sy = (H - 2 * pad) / geoH;
    const s = Math.min(sx, sy); // escala uniforme
    const ox = (W - geoW * s) / 2, oy = (H - geoH * s) / 2;
    const px = (lon) => ox + (lon - minLon) * kx * s;
    const py = (lat) => oy + (maxLat - lat) * s;

    const svg = mk("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Mapa de exposición por departamento" });
    const d = "M" + UY_OUTLINE.map(([lo, la]) => `${px(lo).toFixed(2)},${py(la).toFixed(2)}`).join(" L") + " Z";
    svg.appendChild(mk("path", { d, class: "uy-shape" }));

    // ranking → nivel (cuartiles sobre los deptos con dato)
    const counts = {};
    deptList.forEach((x) => { counts[x.key] = x.count; });
    const present = Object.keys(DEPT_CAP).filter((k) => counts[k] != null);
    const sorted = present.slice().sort((a, b) => counts[b] - counts[a]);
    const rankOf = {};
    sorted.forEach((k, i) => (rankOf[k] = i));
    const n = sorted.length;
    // 4 niveles por posición en el ranking (sin exponer el número)
    const LEVELS = [
      { name: "Muy expuesto", color: "#f47c6c" },
      { name: "Expuesto", color: "#f0a35e" },
      { name: "Moderado", color: "#e5cb5f" },
      { name: "Bajo", color: "#6aa5db" },
    ];
    const levelOf = (k) => {
      if (rankOf[k] == null) return null;
      const q = n <= 1 ? 0 : Math.floor((rankOf[k] / n) * 4);
      return Math.min(3, q);
    };

    const tip = document.createElement("div");
    tip.className = "uy-tip";
    host.appendChild(tip);

    Object.keys(DEPT_CAP).forEach((dept) => {
      const c = DEPT_CAP[dept];
      const lv = levelOf(dept);
      const color = lv == null ? "var(--ink-5)" : LEVELS[lv].color;
      const cx = px(c.lon), cy = py(c.lat);
      if (lv != null) svg.appendChild(mk("circle", { cx, cy, r: 4.4, fill: color, opacity: .22, class: "uy-pt-ring" }));
      const pt = mk("circle", { cx, cy, r: 2.6, fill: color, class: "uy-pt", stroke: "#14171c", "stroke-width": .8 });
      const label = lv == null ? "sin dato" : LEVELS[lv].name;
      const lvColor = lv == null ? "var(--ink-4)" : LEVELS[lv].color;
      pt.addEventListener("mouseenter", () => {
        tip.innerHTML = `<div class="cap">${c.cap}</div><div class="lv" style="color:${lvColor}">${label}</div>`;
        tip.style.left = (cx / W) * 100 + "%";
        tip.style.top = (cy / H) * 100 + "%";
        tip.style.opacity = "1";
      });
      pt.addEventListener("mouseleave", () => { tip.style.opacity = "0"; });
      svg.appendChild(pt);
    });
    host.appendChild(svg);

    // leyenda
    const leg = $("#map-legend");
    if (leg) {
      leg.innerHTML = LEVELS.map((l) =>
        `<span class="item"><span class="dot" style="background:${l.color}"></span>${l.name}</span>`
      ).join("");
    }
  }

  /* ── FIRMA: sismógrafo de 30 días — área SVG con eje X ──────── */
  function trend(hist) {
    const svg = $("#trend-svg");
    if (!svg) return;
    const rows = hist.slice(-30);
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    if (rows.length < 2) {
      $("#trend-peak").textContent = rows[0] ? fmt(rows[0].critical || 0) : "—";
      $("#trend-last").textContent = rows[0] ? fmt(rows[0].critical || 0) : "—";
      const shell = svg.parentElement;
      let empty = shell.querySelector(".trend-empty");
      if (!empty) { empty = el("div", "trend-empty", "La serie diaria se completa con cada barrido."); shell.appendChild(empty); }
      svg.style.display = "none";
      return;
    }
    svg.style.display = "block";

    const W = 900, H = 230, padL = 40, padR = 14, padT = 16, padB = 30;
    const iw = W - padL - padR, ih = H - padT - padB;
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("preserveAspectRatio", "none");
    const NS = "http://www.w3.org/2000/svg";
    const mk = (t, a) => { const n = document.createElementNS(NS, t); for (const k in a) n.setAttribute(k, a[k]); return n; };

    const vals = rows.map((r) => r.critical || 0);
    const peak = Math.max(1, ...vals);
    const X = (i) => padL + (rows.length === 1 ? iw / 2 : (i / (rows.length - 1)) * iw);
    const Y = (v) => padT + ih - (v / peak) * ih;

    $("#trend-peak").textContent = fmt(peak);
    $("#trend-last").textContent = fmt(vals[vals.length - 1]);

    // grilla + ticks del eje Y
    const grad = mk("linearGradient", { id: "trendFill", x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.appendChild(mk("stop", { offset: "0%", "stop-color": "#f47c6c", "stop-opacity": ".30" }));
    grad.appendChild(mk("stop", { offset: "100%", "stop-color": "#f47c6c", "stop-opacity": "0" }));
    const defs = mk("defs", {}); defs.appendChild(grad); svg.appendChild(defs);

    for (let t = 0; t <= 3; t++) {
      const gv = Math.round((peak * t) / 3), gy = Y(gv);
      svg.appendChild(mk("line", { x1: padL, y1: gy, x2: W - padR, y2: gy, stroke: "rgba(255,255,255,.06)", "stroke-width": 1 }));
      const lbl = mk("text", { x: padL - 8, y: gy + 4, "text-anchor": "end", fill: "#586479", "font-size": 11, "font-family": "IBM Plex Mono, monospace" });
      lbl.textContent = fmt(gv);
      svg.appendChild(lbl);
    }

    // ticks del eje X (primero, ~medio, último)
    const xIdx = rows.length <= 2 ? [0, rows.length - 1] : [0, Math.floor((rows.length - 1) / 2), rows.length - 1];
    xIdx.forEach((i) => {
      const t = mk("text", { x: X(i), y: H - 9, "text-anchor": i === 0 ? "start" : i === rows.length - 1 ? "end" : "middle", fill: "#586479", "font-size": 11, "font-family": "IBM Plex Mono, monospace" });
      t.textContent = shortDate(rows[i].date);
      svg.appendChild(t);
    });

    // área + línea (curva suave: spline Catmull-Rom → bézier, sin diente de sierra)
    const baseY = padT + ih;
    const P = rows.map((r, i) => ({ x: +X(i).toFixed(2), y: +Y(r.critical || 0).toFixed(2) }));
    const smooth = (pts) => {
      let d = `${pts[0].x},${pts[0].y}`;
      const t = 1 / 6; // tensión suave (Catmull-Rom uniforme)
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
        const c1x = p1.x + (p2.x - p0.x) * t;
        const c2x = p2.x - (p3.x - p1.x) * t;
        let c1y = p1.y + (p2.y - p0.y) * t;
        let c2y = p2.y - (p3.y - p1.y) * t;
        c1y = Math.min(c1y, baseY); c2y = Math.min(c2y, baseY); // no pasar del baseline
        d += ` C${c1x.toFixed(2)},${c1y.toFixed(2)} ${c2x.toFixed(2)},${c2y.toFixed(2)} ${p2.x},${p2.y}`;
      }
      return d;
    };
    const curve = smooth(P);
    const areaD = `M${P[0].x},${baseY.toFixed(1)} L${curve} L${P[P.length - 1].x},${baseY.toFixed(1)} Z`;
    const area = mk("path", { d: areaD, fill: "url(#trendFill)" });
    const line = mk("path", { d: `M${curve}`, fill: "none", stroke: "#f47c6c", "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" });
    svg.append(area, line);

    if (!reduce) {
      const len = line.getTotalLength ? line.getTotalLength() : 0;
      if (len) {
        line.style.strokeDasharray = len; line.style.strokeDashoffset = len;
        line.style.transition = "stroke-dashoffset 1.1s ease-out";
        requestAnimationFrame(() => requestAnimationFrame(() => { line.style.strokeDashoffset = 0; }));
      }
    }

    // puntos interactivos + tooltip
    const tt = $("#trend-tt");
    rows.forEach((r, i) => {
      const cx = X(i), cy = Y(r.critical || 0);
      svg.appendChild(mk("circle", { cx, cy, r: 2.4, fill: "#e0868a" }));
      const hit = mk("circle", { cx, cy, r: 12, fill: "transparent", style: "cursor:pointer" });
      hit.addEventListener("mouseenter", () => {
        if (!tt) return;
        tt.innerHTML = "";
        const b = el("b", null, fmt(r.critical || 0) + " críticos");
        const dd = el("span", "d", fmtDate(r.date));
        tt.append(b, dd);
        const px = (cx / W) * 100, py = (cy / H) * 100;
        tt.style.left = px + "%"; tt.style.top = py + "%"; tt.style.opacity = "1";
      });
      hit.addEventListener("mouseleave", () => { if (tt) tt.style.opacity = "0"; });
      svg.appendChild(hit);
    });
  }

  /* ── Animación de barras al entrar en viewport ──────────────── */
  function animateFills(host, cls = "bar-fill") {
    const fills = host.querySelectorAll("." + cls);
    if (reduce) { fills.forEach((f) => (f.style.width = f.dataset.w + "%")); return; }
    requestAnimationFrame(() => requestAnimationFrame(() => {
      fills.forEach((f) => (f.style.width = f.dataset.w + "%"));
    }));
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
    const nodes = [...document.querySelectorAll("[data-kpi]")];
    const fmtKpi = (k, v) => (k === "ips" ? fmtMillions(v) : fmt(v));
    const set = (k, v) => nodes.forEach((n) => { if (n.dataset.kpi === k) n.textContent = fmtKpi(k, v); });
    if (reduce) { for (const k in targets) set(k, targets[k]); return; }
    const start = performance.now(), dur = 1400, ease = (t) => 1 - Math.pow(1 - t, 3);
    (function tick(now) {
      const e = ease(Math.min(1, (now - start) / dur));
      for (const k in targets) set(k, Math.round(targets[k] * e));
      if ((now - start) / dur < 1) requestAnimationFrame(tick);
    })(start);
  }
  // formato abreviado para cifras grandes: 2.500.000 → "2,5 M"
  function fmtMillions(v) {
    if (v >= 1e6) return (v / 1e6).toLocaleString("es-UY", { maximumFractionDigits: 1 }) + " M";
    if (v >= 1e3) return Math.round(v / 1e3) + " K";
    return fmt(v);
  }

  /* ── Fechas ─────────────────────────────────────────────────── */
  const MES = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];
  function fmtDate(iso) {
    if (!iso) return "—";
    const [y, m, dd] = String(iso).split("-").map(Number);
    return `${dd} ${MES[(m || 1) - 1]} ${y}`;
  }
  function shortDate(iso) {
    if (!iso) return "";
    const [, m, dd] = String(iso).split("-").map(Number);
    return `${dd} ${MES[(m || 1) - 1]}`;
  }

  /* ── Nav móvil + scroll-spy ─────────────────────────────────── */
  const burger = $("#navBurger"), links = $("#navLinks");
  if (burger && links) {
    burger.addEventListener("click", () => {
      const open = links.classList.toggle("open");
      burger.classList.toggle("open", open);
    });
    links.addEventListener("click", (e) => {
      if (e.target.tagName === "A") { links.classList.remove("open"); burger.classList.remove("open"); }
    });
  }

  /* scroll-spy del nav — solo anclas internas (#seccion); ignora enlaces externos como "Datos abiertos" */
  const spy = [...document.querySelectorAll(".nav-links a")].filter((a) => {
    const h = a.getAttribute("href") || "";
    return h.charAt(0) === "#" && h.length > 1;
  });
  const secs = spy.map((a) => document.querySelector(a.getAttribute("href"))).filter(Boolean);
  if (secs.length && "IntersectionObserver" in window) {
    const so = new IntersectionObserver((ents) => {
      ents.forEach((e) => {
        if (e.isIntersecting) {
          spy.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + e.target.id));
        }
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    secs.forEach((s) => so.observe(s));
  }
})();

/* ── Mapa del registro público (Leaflet, realce progresivo) ───── */
(function () {
  var _regMap = null, _regLayer = null;
  window.renderRegistryMap = function (entries) {
    var el = document.getElementById("reg-map");
    if (!el || typeof L === "undefined") return;
    if (!_regMap) {
      _regMap = L.map(el, { scrollWheelZoom: false }).setView([-32.8, -55.9], 6);
      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: "© OpenStreetMap · © CARTO", maxZoom: 19,
      }).addTo(_regMap);
      _regLayer = L.layerGroup().addTo(_regMap);
    }
    _regLayer.clearLayers();
    entries.forEach(function (e) {
      if (!e.location) return;
      var meta = Registry.categoryMeta(e.category);
      var m = L.circleMarker([e.location.lat, e.location.lng], {
        radius: 7, color: meta.color, fillColor: meta.color, fillOpacity: 0.8, weight: 2,
      });
      var div = document.createElement("div");
      var strong = document.createElement("strong");
      strong.textContent = e.name;
      div.appendChild(strong);
      div.appendChild(document.createElement("br"));
      div.appendChild(document.createTextNode(meta.label));
      div.appendChild(document.createElement("br"));
      var a = document.createElement("a");
      a.href = /^https?:\/\//i.test(e.url) ? e.url : "#";
      a.target = "_blank"; a.rel = "noopener noreferrer";
      a.textContent = "Abrir →";
      div.appendChild(a);
      m.bindPopup(div);
      m.addTo(_regLayer);
    });
  };
})();

/* ── Información pública accesible (registro curado) ──────────── */
function renderPublicRegistry(entries) {
  var listEl = document.getElementById("reg-list");
  var filterEl = document.getElementById("reg-filters");
  if (!listEl) return;
  var current = "all";

  function draw() {
    var rows = Registry.filterByCategory(entries, current);
    listEl.innerHTML = "";
    if (rows.length === 0) {
      var empty = document.createElement("p");
      empty.className = "reg-empty";
      empty.textContent = "Aún no hay recursos verificados en esta categoría.";
      listEl.appendChild(empty);
    } else {
      rows.forEach(function (e) {
        var meta = Registry.categoryMeta(e.category);
        var card = document.createElement("a");
        card.className = "reg-card";
        card.href = /^https?:\/\//i.test(e.url) ? e.url : "#";
        card.target = "_blank"; card.rel = "noopener noreferrer";
        var dot = document.createElement("span");
        dot.className = "reg-dot"; dot.style.background = meta.color;
        var body = document.createElement("div");
        var name = document.createElement("div");
        name.className = "reg-name"; name.textContent = e.name;
        var sub = document.createElement("div");
        sub.className = "reg-sub";
        sub.textContent = meta.label + " · " + e.operator + " · " + e.department;
        body.appendChild(name); body.appendChild(sub);
        card.appendChild(dot); card.appendChild(body);
        listEl.appendChild(card);
      });
    }
    if (window.renderRegistryMap) window.renderRegistryMap(rows);
  }

  if (filterEl) {
    var counts = Registry.countByCategory(entries);
    var cats = ["all"].concat(Object.keys(Registry.CATEGORIES).filter(function (c) { return counts[c]; }));
    filterEl.innerHTML = "";
    cats.forEach(function (c) {
      var b = document.createElement("button");
      b.className = "reg-filter";
      b.textContent = c === "all"
        ? "Todos (" + entries.length + ")"
        : Registry.categoryMeta(c).label + " (" + counts[c] + ")";
      b.onclick = function () {
        current = c;
        draw();
        Array.prototype.forEach.call(filterEl.children, function (x) { x.classList.toggle("active", x === b); });
      };
      filterEl.appendChild(b);
    });
    if (filterEl.firstChild) filterEl.firstChild.classList.add("active");
  }
  draw();
}
window.renderPublicRegistry = renderPublicRegistry;

/* ── Higiene de correo (.uy) — SPF/DMARC declarados vs. aplicados ── */
(function () {
  var fmt = function (n) { return (n || 0).toLocaleString("es-UY"); };
  var pct = function (part, total) { return total ? Math.round((100 * part) / total) : 0; };

  var BUCKET_LABEL = {
    "gub.uy": "gub.uy", "edu.uy": "edu.uy", "org.uy": "org.uy",
    "com.uy": "com.uy", "net.uy": "net.uy", "mil.uy": "mil.uy", "otros": "otros",
  };
  var BUCKET_ORDER = ["gub.uy", "mil.uy", "edu.uy", "org.uy", "net.uy", "com.uy", "otros"];

  function stackedBar(hostSel, declared, enforced, total, labelDecl, labelEnf) {
    var host = document.querySelector(hostSel);
    if (!host) return;
    host.innerHTML = "";
    var pDecl = pct(declared, total), pEnf = pct(enforced, total);
    var wrap = document.createElement("div");
    wrap.className = "hyg-bar";
    wrap.innerHTML =
      '<div class="hyg-bar-top"><span class="k">' + labelDecl + '</span>' +
      '<span class="v"><b>' + fmt(declared) + "</b> de " + fmt(total) + " · " + pDecl + "%</span></div>" +
      '<div class="hyg-track"><div class="hyg-declared" data-w="' + pDecl + '"></div>' +
      '<div class="hyg-enforced" data-w="' + pEnf + '"></div></div>' +
      '<div class="hyg-legend"><span><i style="background:linear-gradient(90deg,#4a7fd6,#6ea8ff)"></i>Declarado · ' + pDecl + "%</span>" +
      '<span><i style="background:linear-gradient(90deg,#2f6f5a,#43d69a)"></i>' + labelEnf + " · " + pEnf + "%</span></div>";
    host.appendChild(wrap);
    var d = wrap.querySelector(".hyg-declared"), e = wrap.querySelector(".hyg-enforced");
    var reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { d.style.width = pDecl + "%"; e.style.width = pEnf + "%"; }
    else requestAnimationFrame(function () { requestAnimationFrame(function () { d.style.width = pDecl + "%"; e.style.width = pEnf + "%"; }); });
  }

  function miniBar(pctVal, color) {
    return '<div class="hyg-mini"><div class="hyg-mini-track"><i style="width:' +
      Math.max(2, pctVal) + "%;background:" + color + '"></i></div><span class="pct">' + pctVal + "%</span></div>";
  }

  function render(d) {
    var o = d.overall || {}, total = o.total || d.total_domains || 0;
    var spfPct = pct(o.with_spf, total), dmarcPct = pct(o.with_dmarc, total);

    var kpis = document.getElementById("hyg-kpis");
    if (kpis) {
      kpis.innerHTML =
        kpi(fmt(total), "dominios .uy medidos", "enumerados vía Certificate Transparency") +
        kpi(spfPct + "%", "declara SPF", "estricto (−all): <b>" + pct(o.spf_enforced, total) + "%</b>") +
        kpi(dmarcPct + "%", "declara DMARC", "aplica (quarantine/reject): <b>" + pct(o.dmarc_enforced, total) + "%</b>") +
        kpi(pct(o.with_spf - o.spf_enforced, total) + "%", "SPF que no bloquea", "declaran pero sin política estricta");
    }

    stackedBar("#hyg-spf", o.with_spf || 0, o.spf_enforced || 0, total, "SPF en dominios .uy", "Estricto −all");
    stackedBar("#hyg-dmarc", o.with_dmarc || 0, o.dmarc_enforced || 0, total, "DMARC en dominios .uy", "Aplica");

    var buckets = d.by_bucket || {};
    var host = document.getElementById("hyg-buckets");
    if (host) {
      host.innerHTML = "";
      var keys = BUCKET_ORDER.filter(function (k) { return buckets[k]; })
        .concat(Object.keys(buckets).filter(function (k) { return BUCKET_ORDER.indexOf(k) < 0; }));
      keys.forEach(function (k) {
        var b = buckets[k]; if (!b || !b.total) return;
        var row = document.createElement("div");
        row.className = "hyg-bucket-row";
        row.innerHTML =
          '<span class="bkt">' + (BUCKET_LABEL[k] || k) + "</span>" +
          '<span class="num">' + fmt(b.total) + "</span>" +
          miniBar(pct(b.with_spf, b.total), "linear-gradient(90deg,#4a7fd6,#6ea8ff)") +
          miniBar(pct(b.with_dmarc, b.total), "linear-gradient(90deg,#2f6f5a,#43d69a)");
        host.appendChild(row);
      });
    }
  }

  function kpi(big, lbl, sub) {
    return '<div class="hyg-kpi"><div class="big">' + big + '</div><div class="lbl">' + lbl + '</div><div class="sub">' + sub + "</div></div>";
  }

  fetch("uy_hygiene.json?cb=" + Date.now())
    .then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); })
    .then(render)
    .catch(function () {
      var sec = document.getElementById("higiene");
      if (sec) sec.style.display = "none"; // sidecar ausente → ocultar sección
    });
})();

function loadPublicRegistry() {
  fetch("public-registry.json?cb=" + Date.now())
    .then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); })
    .then(function (data) { renderPublicRegistry(data); })
    .catch(function () {
      var errEl = document.getElementById("reg-error");
      if (errEl) errEl.style.display = "block";
    });
}
loadPublicRegistry();

/* sugerencia sutil de modo escritorio en móvil — no intrusiva, descartable y recordada */
(function () {
  var hint = document.getElementById("desktop-hint");
  if (!hint) return;
  var isMobile = /Mobi|Android|iPhone|iPod|iPad|Opera Mini|IEMobile|BlackBerry/i.test(navigator.userAgent);
  var dismissed = false;
  try { dismissed = localStorage.getItem("zarpa_dhint") === "1"; } catch (e) {}
  if (!isMobile || dismissed) return;
  hint.classList.add("show");
  var close = document.getElementById("dhint-close");
  if (close) close.addEventListener("click", function () {
    hint.classList.remove("show");
    try { localStorage.setItem("zarpa_dhint", "1"); } catch (e) {}
  });
})();

