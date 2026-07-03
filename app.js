/* Radar · carga stats.json (solo agregados) y dibuja el reporte. Vanilla, sin libs. */
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const SVGNS = "http://www.w3.org/2000/svg";
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const fmt = (n) => (n || 0).toLocaleString("es-UY");

  const DEVTYPE = {
    CAMERA: "Cámaras", EXPOSED_CAMERA: "Cámaras abiertas", WEB_SERVER: "Servidores web",
    ROUTER: "Routers", SERVER: "Servidores", HOST: "Otros equipos", ADMIN_PANEL: "Paneles de admin",
    EXPOSED_DATABASE: "Bases de datos", "ICS/SCADA": "Sistemas industriales", REMOTE_ACCESS: "Acceso remoto",
    IOT_DEVICE: "Dispositivos IoT", NETWORK_DEVICE: "Equipos de red", PRINTER: "Impresoras", HONEYPOT: "Señuelos",
  };
  const CRITLABEL = { CRITICAL: "Crítico", HIGH: "Alto", MEDIUM: "Medio", LOW: "Bajo" };
  const CRITVAR = { CRITICAL: "var(--crit)", HIGH: "var(--high)", MEDIUM: "var(--medium)", LOW: "var(--low)" };
  const AUTHLABEL = { open: "Expuestos", "auth-required": "Protegidos", unknown: "Sin determinar" };
  const AUTHVAR = { open: "var(--alarm)", "auth-required": "var(--low)", unknown: "var(--ink-2)" };
  const CVENOTE = {
    "CVE-2024-6387": "OpenSSH · ejecución remota (“regreSSHion”)",
    "CVE-2017-7921": "Hikvision · acceso sin contraseña",
    "CVE-2021-36260": "Hikvision · ejecución remota",
    "CVE-2018-14847": "MikroTik · lectura de credenciales",
    "CVE-2021-40438": "Apache · petición forzada al servidor",
    "CVE-2015-3306": "ProFTPD · lectura/escritura de archivos",
  };

  const label = (map, k) => map[k] || k;

  fetch("stats.json", { cache: "no-store" })
    .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(render)
    .catch(() => {
      $("#hero-total").textContent = "—";
      $(".hero-lead").textContent = "No pudimos cargar los datos de hoy. Probá recargar en un rato.";
    });

  function render(d) {
    $("#updated").textContent = fmtDate(d.scan_date);
    $("#foot-total").textContent = fmt(d.total_devices) + " equipos";

    countUp($("#hero-total"), d.total_devices);
    $("#crit-num").textContent = fmt((d.by_criticality || {}).CRITICAL || 0);

    drawBlips(d);
    critBar(d.by_criticality || {}, d.total_devices);
    authSeg(d.by_auth_state || {});

    bars("#chart-devicetype", (d.by_device_type || []).slice(0, 8).map((x) => ({ label: label(DEVTYPE, x.key), count: x.count })));
    bars("#chart-brand", (d.by_brand || []).slice(0, 8).map((x) => ({ label: x.key, count: x.count })));
    bars("#chart-depto", (d.by_department || []).slice(0, 10).map((x) => ({ label: x.key, count: x.count })));

    rankList("#rank-isp", (d.by_isp || []).slice(0, 6).map((x) => ({ name: x.key, count: x.count })));
    rankList("#rank-cve", (d.by_cve || []).slice(0, 6).map((x) => ({ name: x.key, note: CVENOTE[x.key], count: x.count })));
  }

  /* ── Contador ─────────────────────────────────────────────── */
  function countUp(node, target) {
    target = target || 0;
    if (reduce) { node.textContent = fmt(target); return; }
    const dur = 1800, t0 = performance.now();
    const ease = (t) => 1 - Math.pow(1 - t, 3);
    function step(now) {
      const p = Math.min(1, (now - t0) / dur);
      node.textContent = fmt(Math.round(target * ease(p)));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* ── Blips del radar (muestra, no las IPs) ────────────────── */
  function drawBlips(d) {
    const g = $("#blips");
    const cx = 200, cy = 200, R = 182;
    const N = 190;
    const critShare = d.total_devices ? (d.by_criticality.CRITICAL || 0) / d.total_devices : 0;
    const reds = Math.max(3, Math.round(N * critShare));
    // PRNG determinista para que el patrón sea estable entre cargas.
    let s = 0x2f6e2b1;
    const rnd = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    for (let i = 0; i < N; i++) {
      const ang = rnd() * Math.PI * 2;
      const rad = Math.sqrt(rnd()) * R;
      const c = document.createElementNS(SVGNS, "circle");
      c.setAttribute("cx", (cx + Math.cos(ang) * rad).toFixed(1));
      c.setAttribute("cy", (cy + Math.sin(ang) * rad).toFixed(1));
      const crit = i < reds;
      c.setAttribute("r", crit ? 3.4 : 1.7 + rnd() * 1.1);
      c.setAttribute("class", crit ? "blip-crit" : "blip");
      g.appendChild(c);
    }
  }

  /* ── Barra de criticidad ──────────────────────────────────── */
  function critBar(by, total) {
    const bar = $("#crit-bar"), leg = $("#crit-legend");
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    order.forEach((k) => {
      const n = by[k] || 0; if (!n) return;
      const seg = document.createElement("span");
      seg.style.flex = n; seg.style.background = CRITVAR[k];
      seg.title = `${CRITLABEL[k]}: ${fmt(n)}`;
      bar.appendChild(seg);
    });
    order.forEach((k) => {
      const n = by[k] || 0; if (!n) return;
      leg.appendChild(legendItem(CRITVAR[k], CRITLABEL[k], n));
    });
  }

  function authSeg(by) {
    const seg = $("#auth-seg"), leg = $("#auth-legend");
    const order = ["open", "auth-required", "unknown"];
    const total = order.reduce((a, k) => a + (by[k] || 0), 0) || 1;
    order.forEach((k) => {
      const n = by[k] || 0; if (!n) return;
      const s = document.createElement("span");
      s.style.flex = n; s.style.background = AUTHVAR[k];
      const p = Math.round((n / total) * 100);
      s.textContent = p >= 9 ? AUTHLABEL[k] : "";
      if (k === "unknown") s.style.color = "var(--ink)";
      seg.appendChild(s);
    });
    order.forEach((k) => {
      const n = by[k] || 0; if (!n) return;
      leg.appendChild(legendItem(AUTHVAR[k], AUTHLABEL[k], n));
    });
  }

  function legendItem(color, name, n) {
    const li = document.createElement("div"); li.className = "li";
    const sw = document.createElement("span"); sw.className = "sw"; sw.style.background = color;
    const nm = document.createElement("span"); nm.textContent = name + " ";
    const num = document.createElement("span"); num.className = "n"; num.textContent = fmt(n);
    li.append(sw, nm, num);
    return li;
  }

  /* ── Barras horizontales ──────────────────────────────────── */
  function bars(sel, rows) {
    const host = $(sel);
    const max = rows.length ? rows[0].count : 1;
    rows.forEach((r) => {
      const row = document.createElement("div"); row.className = "row";
      const lbl = document.createElement("div"); lbl.className = "row-label"; lbl.textContent = r.label; lbl.title = r.label;
      const track = document.createElement("div"); track.className = "row-track";
      const fill = document.createElement("div"); fill.className = "row-fill";
      fill.style.width = Math.max(2, (r.count / max) * 100) + "%";
      track.appendChild(fill);
      const val = document.createElement("div"); val.className = "row-val mono"; val.textContent = fmt(r.count);
      row.append(lbl, track, val);
      host.appendChild(row);
    });
  }

  /* ── Rankings ─────────────────────────────────────────────── */
  function rankList(sel, rows) {
    const host = $(sel);
    rows.forEach((r, i) => {
      const li = document.createElement("li");
      const idx = document.createElement("span"); idx.className = "idx"; idx.textContent = String(i + 1).padStart(2, "0");
      const name = document.createElement("span"); name.className = "name";
      name.textContent = r.name;
      if (r.note) { const s = document.createElement("small"); s.textContent = r.note; name.appendChild(s); }
      const cnt = document.createElement("span"); cnt.className = "cnt mono"; cnt.textContent = fmt(r.count);
      li.append(idx, name, cnt);
      host.appendChild(li);
    });
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    const [y, m, dd] = iso.split("-").map(Number);
    const meses = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"];
    return `${dd} de ${meses[(m || 1) - 1]} de ${y}`;
  }
})();
