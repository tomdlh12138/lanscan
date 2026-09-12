/* =========================================================================
 * LAN Scan — 纯前端局域网设备扫描（iPad Safari / 任意现代浏览器）
 *
 * 实现原理（浏览器能做的最可靠方式）：
 *   - 浏览器不能发 ICMP(ping)、不能做原始 TCP、不能读 MAC。
 *   - 对「网段 × 端口」逐个发起 http(s)://IP:PORT 的 fetch(no-cors) 请求，
 *     用超时 + 错误判定端口是否有 HTTP(S) 服务在响应 → 即视为「发现设备」。
 *   - 本机网段通过 WebRTC ICE 候选尽力获取（Safari 可能返回 mDNS 混淆地址）。
 *
 * 局限（已在 README 与界面提示中说明）：
 *   - 只能可靠发现「开放 HTTP/HTTPS 端口」的设备；
 *   - 使用自签名证书的 HTTPS 设备因证书校验会被误判为关闭；
 *   - SSH/SMB 等纯 TCP 端口无法被浏览器识别（会误判为关闭）。
 * ========================================================================= */

'use strict';

/* ----------------------------- 端口预设 ----------------------------- */
// reliable: 浏览器可尝试探测的 HTTP/HTTPS 端口
const RELIABLE_PORTS = [
  { port: 80,   sv: 'HTTP' },
  { port: 443,  sv: 'HTTPS*' },
  { port: 8080, sv: 'HTTP' },
  { port: 8000, sv: 'HTTP' },
  { port: 8888, sv: 'HTTP' },
  { port: 3000, sv: 'HTTP' },
  { port: 5000, sv: 'HTTP' },
  { port: 9090, sv: 'HTTP' },
  { port: 8443, sv: 'HTTPS*' },
];
// unreliable: 纯 TCP 端口，浏览器无法识别，仅作「尽力尝试」并明确标注
const UNRELIABLE_PORTS = [
  { port: 22,   sv: 'SSH' },
  { port: 21,   sv: 'FTP' },
  { port: 23,   sv: 'Telnet' },
  { port: 25,   sv: 'SMTP' },
  { port: 53,   sv: 'DNS' },
  { port: 139,  sv: 'NetBIOS' },
  { port: 445,  sv: 'SMB' },
  { port: 3306, sv: 'MySQL' },
  { port: 3389, sv: 'RDP' },
  { port: 5900, sv: 'VNC' },
  { port: 81,   sv: 'HTTP' },
  { port: 88,   sv: 'HTTP' },
];

/* ----------------------------- DOM 引用 ----------------------------- */
const $ = (id) => document.getElementById(id);
const els = {
  netPrefix: $('netPrefix'), hostStart: $('hostStart'), hostEnd: $('hostEnd'),
  quickNets: $('quickNets'), ports: $('ports'), togglePorts: $('togglePorts'),
  customPort: $('customPort'), addPort: $('addPort'),
  concurrency: $('concurrency'), timeoutMs: $('timeoutMs'),
  startBtn: $('startBtn'), stopBtn: $('stopBtn'), detectBtn: $('detectBtn'),
  statusPill: $('statusPill'), statusDot: $('statusDot'), statusText: $('statusText'),
  statScanned: $('statScanned'), statFound: $('statFound'), statProgress: $('statProgress'),
  progressBar: $('progressBar'),
  exportBtn: $('exportBtn'), clearBtn: $('clearBtn'),
  resultsEmpty: $('resultsEmpty'), cards: $('cards'),
  detailDialog: $('detailDialog'), detailBody: $('detailBody'),
  footerMsg: $('footerMsg'),
};

/* ----------------------------- 状态 ----------------------------- */
const state = {
  devices: new Map(),   // ip -> { ip, ports: [{port, scheme, title}], title, via }
  stopped: false,
  running: false,
  scanned: 0,
  total: 0,
};

/* ----------------------------- 端口 UI 渲染 ----------------------------- */
function renderPorts() {
  els.ports.innerHTML = '';
  const make = (p, unreliable) => {
    const label = document.createElement('label');
    label.className = 'port-chip' + (unreliable ? ' unreliable' : '');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.value = p.port;
    cb.checked = !unreliable; // 默认只勾选 reliable
    cb.dataset.unreliable = unreliable ? '1' : '0';
    const pn = document.createElement('span');
    pn.className = 'pn'; pn.textContent = p.port;
    const sv = document.createElement('span');
    sv.className = 'sv'; sv.textContent = p.sv;
    label.append(cb, pn, sv);
    els.ports.appendChild(label);
  };
  RELIABLE_PORTS.forEach((p) => make(p, false));
  UNRELIABLE_PORTS.forEach((p) => make(p, true));
}

function getSelectedPorts() {
  return [...els.ports.querySelectorAll('input[type=checkbox]:checked')].map((cb) => ({
    port: parseInt(cb.value, 10),
    unreliable: cb.dataset.unreliable === '1',
  }));
}

/* ----------------------------- 网段辅助 ----------------------------- */
function isPrivateIP(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  if (p[0] === 10) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  return false;
}

function buildHostList() {
  const prefix = els.netPrefix.value.trim().replace(/\.$/, '');
  const start = parseInt(els.hostStart.value, 10);
  const end = parseInt(els.hostEnd.value, 10);
  if (!/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(prefix)) {
    throw new Error('网段前缀格式应为「a.b.c」（三段）');
  }
  if (Number.isNaN(start) || Number.isNaN(end) || start < 0 || end > 255 || start > end) {
    throw new Error('主机范围应在 0–255 且起始 ≤ 结束');
  }
  const hosts = [];
  for (let h = start; h <= end; h++) hosts.push(`${prefix}.${h}`);
  return hosts;
}

/* ----------------------------- 探测核心 ----------------------------- */
async function probe(ip, port, timeoutMs) {
  const schemes = ['http', 'https'];
  for (const scheme of schemes) {
    const url = `${scheme}://${ip}:${port}/`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      await fetch(url, { mode: 'no-cors', cache: 'no-store', signal: ctrl.signal });
      clearTimeout(timer);
      // 走到这里说明 TCP 连上且收到了响应（opaque）——端口有服务
      return { port, scheme, open: true };
    } catch (e) {
      clearTimeout(timer);
      if (ctrl.signal.aborted) {
        // 超时：该 scheme 放弃，试下一个；都超时则整体视为关闭
        continue;
      }
      // 非超时错误：连接被拒或协议不匹配，试下一个 scheme
      continue;
    }
  }
  return { port, scheme: null, open: false };
}

// 尽力获取页面标题（多数设备禁用 CORS，通常拿不到，故 best-effort）
async function tryGetTitle(ip, port, scheme) {
  try {
    const res = await fetch(`${scheme}://${ip}:${port}/`, { mode: 'cors', cache: 'no-store' });
    const html = await res.text();
    const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
    return m ? m[1].trim().slice(0, 80) : null;
  } catch (e) {
    return null;
  }
}

/* ----------------------------- 并发池 ----------------------------- */
async function runPool(tasks, concurrency, worker) {
  let idx = 0;
  const runners = Array.from({ length: Math.min(concurrency, tasks.length) || 1 }, async () => {
    while (idx < tasks.length) {
      const cur = idx++;
      if (state.stopped) return;
      await worker(tasks[cur]);
    }
  });
  await Promise.all(runners);
}

/* ----------------------------- 主扫描流程 ----------------------------- */
async function startScan() {
  if (state.running) return;
  let hosts, ports;
  try {
    hosts = buildHostList();
    ports = getSelectedPorts();
  } catch (e) {
    setStatus('error', e.message);
    return;
  }
  if (ports.length === 0) {
    setStatus('error', '请至少选择一个端口');
    return;
  }

  // 重置
  state.devices.clear();
  state.stopped = false;
  state.running = true;
  state.scanned = 0;
  state.total = hosts.length * ports.length;
  renderCards();
  updateStats();

  els.startBtn.disabled = true;
  els.stopBtn.disabled = false;
  setStatus('running', `扫描中 · 共 ${hosts.length} 个 IP × ${ports.length} 端口`);

  const concurrency = Math.max(1, Math.min(100, parseInt(els.concurrency.value, 10) || 30));
  const timeoutMs = Math.max(300, Math.min(5000, parseInt(els.timeoutMs.value, 10) || 1200));
  const tasks = [];
  hosts.forEach((ip) => ports.forEach((p) => tasks.push({ ip, port: p.port, unreliable: p.unreliable })));

  const seenOpen = new Set(); // 已为某 IP 发起过完整端口扫描的标记

  await runPool(tasks, concurrency, async (task) => {
    if (state.stopped) return;
    const r = await probe(task.ip, task.port, timeoutMs);
    state.scanned++;
    updateProgress();

    if (r.open) {
      const dev = getOrCreateDevice(task.ip);
      const exists = dev.ports.some((x) => x.port === r.port);
      if (!exists) {
        dev.ports.push({ port: r.port, scheme: r.scheme, title: null });
        if (!task.unreliable) {
          // 对可靠端口尝试拿标题
          const t = await tryGetTitle(task.ip, r.port, r.scheme);
          if (t) { dev.title = t; dev.ports[dev.ports.length - 1].title = t; }
        }
        if (!seenOpen.has(task.ip)) {
          seenOpen.add(task.ip);
          bumpFound();
          renderCards();
        } else {
          // 已发现设备的端口更新，重绘其卡片
          renderCards();
        }
      }
    }
  });

  finishScan();
}

function finishScan() {
  state.running = false;
  els.startBtn.disabled = false;
  els.stopBtn.disabled = true;
  const found = state.devices.size;
  if (state.stopped) {
    setStatus('done', `已停止 · 发现 ${found} 台设备`);
  } else {
    setStatus('done', `完成 · 共发现 ${found} 台设备`);
  }
  els.exportBtn.disabled = found === 0;
  els.clearBtn.disabled = found === 0;
}

/* ----------------------------- 设备存取 ----------------------------- */
function getOrCreateDevice(ip) {
  let d = state.devices.get(ip);
  if (!d) {
    d = { ip, ports: [], title: null, via: 'http-probe' };
    state.devices.set(ip, d);
  }
  return d;
}

/* ----------------------------- 渲染 ----------------------------- */
function renderCards() {
  if (state.devices.size === 0) {
    els.resultsEmpty.style.display = '';
    els.cards.innerHTML = '';
    return;
  }
  els.resultsEmpty.style.display = 'none';
  const sorted = [...state.devices.values()].sort((a, b) => ip2num(a.ip) - ip2num(b.ip));
  els.cards.innerHTML = '';
  sorted.forEach((d) => {
    const card = document.createElement('div');
    card.className = 'card';
    card.addEventListener('click', () => openDetail(d.ip));

    const ip = document.createElement('div');
    ip.className = 'ip';
    ip.textContent = d.ip;

    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = d.title || (d.ports.length ? `${d.ports.length} 个开放端口` : '');

    const portsLine = document.createElement('div');
    portsLine.className = 'ports-line';
    d.ports.slice().sort((a, b) => a.port - b.port).forEach((p) => {
      const tag = document.createElement('span');
      tag.className = 'tag' + (p.scheme === 'https' ? ' https' : '');
      tag.textContent = `${p.port}/${p.scheme || '?'}`;
      portsLine.appendChild(tag);
    });

    const src = document.createElement('div');
    src.className = 'src';
    src.innerHTML = '<span class="badge">HTTP 端口探测</span>';

    card.append(ip, meta, portsLine, src);
    els.cards.appendChild(card);
  });
}

function ip2num(ip) {
  return ip.split('.').reduce((n, p) => n * 256 + (+p), 0);
}

function openDetail(ip) {
  const d = state.devices.get(ip);
  if (!d) return;
  const sorted = d.ports.slice().sort((a, b) => a.port - b.port);
  const portTags = sorted.map((p) =>
    `<span class="tag${p.scheme === 'https' ? ' https' : ''}">${p.port}/${p.scheme || '?'}</span>`
  ).join('');
  // 默认用第一个开放端口生成可点击链接
  const firstHttp = sorted.find((p) => p.scheme);
  const link = firstHttp
    ? `<a class="open-link" href="${firstHttp.scheme}://${d.ip}:${firstHttp.port}/" target="_blank" rel="noopener">打开 ${firstHttp.scheme}://${d.ip}:${firstHttp.port}</a>`
    : '';

  els.detailBody.innerHTML = `
    <h2>${d.ip}</h2>
    ${d.title ? `<p style="color:var(--text-dim);margin:2px 0 0">${escapeHtml(d.title)}</p>` : ''}
    <div class="row"><span class="k">探测方式</span><span class="v">HTTP 端口探测</span></div>
    <div class="row"><span class="k">开放端口数</span><span class="v">${d.ports.length}</span></div>
    <div class="pblock">
      <h3>开放端口</h3>
      <div class="plist">${portTags || '<span class="sv">无</span>'}</div>
    </div>
    ${link}
  `;
  if (typeof els.detailDialog.showModal === 'function') {
    els.detailDialog.showModal();
  } else {
    els.detailDialog.setAttribute('open', '');
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ----------------------------- 统计/状态 ----------------------------- */
function setStatus(kind, text) {
  els.statusPill.className = 'status-pill ' + (kind === 'running' ? 'running' : kind === 'done' ? 'done' : kind === 'error' ? 'error' : '');
  els.statusText.textContent = text;
}
function updateProgress() {
  const pct = state.total ? Math.round((state.scanned / state.total) * 100) : 0;
  els.statProgress.textContent = pct + '%';
  els.progressBar.style.width = pct + '%';
  els.statScanned.textContent = state.scanned;
}
function bumpFound() {
  els.statFound.textContent = state.devices.size;
}
function updateStats() {
  els.statScanned.textContent = 0;
  els.statFound.textContent = 0;
  els.statProgress.textContent = '0%';
  els.progressBar.style.width = '0%';
}

/* ----------------------------- 本机网段检测 (WebRTC) ----------------------------- */
async function detectLocalIP() {
  setStatus('running', '正在尝试获取本机网段…');
  const ips = await new Promise((resolve) => {
    const found = new Set();
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('');
      pc.onicecandidate = (e) => {
        if (!e.candidate || !e.candidate.candidate) return;
        const m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(e.candidate.candidate);
        if (m && isPrivateIP(m[1])) found.add(m[1]);
      };
      pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => {});
      setTimeout(() => { try { pc.close(); } catch (_) {} resolve([...found]); }, 1600);
    } catch (_) {
      resolve([]);
    }
  });

  if (ips.length === 0) {
    setStatus('error', '无法自动检测（Safari 可能隐藏了本机 IP）。请手动输入网段。');
    return;
  }
  // 取第一个私有 IP，填入网段前缀
  const ip = ips[0];
  const parts = ip.split('.');
  els.netPrefix.value = `${parts[0]}.${parts[1]}.${parts[2]}`;
  els.hostStart.value = '1';
  els.hostEnd.value = '254';
  setStatus('done', `已填入网段 ${els.netPrefix.value}.x（来源：${ips.join(', ')}）`);
}

/* ----------------------------- 导出 CSV ----------------------------- */
function exportCSV() {
  if (state.devices.size === 0) return;
  const rows = [['IP', '开放端口', '协议', '标题', '探测方式']];
  [...state.devices.values()].sort((a, b) => ip2num(a.ip) - ip2num(b.ip)).forEach((d) => {
    const ports = d.ports.slice().sort((a, b) => a.port - b.port)
      .map((p) => `${p.port}`).join('|');
    const schemes = d.ports.slice().sort((a, b) => a.port - b.port)
      .map((p) => p.scheme || '?').join('|');
    rows.push([d.ip, ports, schemes, d.title || '', 'http-probe']);
  });
  const csv = '\uFEFF' + rows.map((r) =>
    r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `lanscan-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* ----------------------------- 事件绑定 ----------------------------- */
function bindEvents() {
  els.quickNets.querySelectorAll('button').forEach((b) => {
    b.addEventListener('click', () => {
      els.netPrefix.value = b.dataset.net;
      els.hostStart.value = '1';
      els.hostEnd.value = '254';
    });
  });
  els.togglePorts.addEventListener('click', () => {
    els.ports.style.display = els.ports.style.display === 'none' ? '' : 'none';
  });
  els.addPort.addEventListener('click', () => {
    const v = parseInt(els.customPort.value, 10);
    if (Number.isNaN(v) || v < 1 || v > 65535) { alert('端口需在 1–65535'); return; }
    if ([...els.ports.querySelectorAll('input')].some((c) => +c.value === v)) return;
    const label = document.createElement('label');
    label.className = 'port-chip unreliable';
    label.innerHTML = `<input type="checkbox" value="${v}" checked data-unreliable="1"><span class="pn">${v}</span><span class="sv">自定义</span>`;
    els.ports.appendChild(label);
    els.customPort.value = '';
  });
  els.startBtn.addEventListener('click', startScan);
  els.stopBtn.addEventListener('click', () => { state.stopped = true; });
  els.detectBtn.addEventListener('click', detectLocalIP);
  els.exportBtn.addEventListener('click', exportCSV);
  els.clearBtn.addEventListener('click', () => {
    state.devices.clear();
    renderCards();
    els.exportBtn.disabled = true;
    els.clearBtn.disabled = true;
    updateStats();
    setStatus('done', '结果已清空');
  });
}

/* ----------------------------- 启动 ----------------------------- */
renderPorts();
bindEvents();
setStatus('', '待命');
