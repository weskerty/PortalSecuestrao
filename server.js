const express = require('express');
const { execSync, exec, spawn } = require('child_process');
const dgram = require('dgram');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const http = require('http');

function loadEnv() {
  const p = path.join(__dirname, '.env');
  if (!fs.existsSync(p)) return;
  fs.readFileSync(p, 'utf8').split('\n').forEach(l => {
    const m = l.match(/^([^#=]+)=(.*)$/);
    if (m) process.env[m[1].trim()] = m[2].trim();
  });
}
loadEnv();

const PORT       = parseInt(process.env.PORT)     || 8080;
const DNS_PORT   = parseInt(process.env.DNS_PORT) || 5454;
const IFACE_IN   = process.env.IFACE_IN           || 'wlan2';
const OPEN_MS    = parseInt(process.env.OPEN_MS)  || 7000;
const LOG_MAX    = parseInt(process.env.LOG_MAX)  || 500;
const CLEAN_MS   = parseInt(process.env.CLEAN_MS) || 3600000;
const WA_RANGES  = (process.env.WA_RANGES || '31.13.64.0/18,157.240.0.0/16,179.60.192.0/22').split(',').map(s => s.trim());
const CONN_HOSTS = (process.env.CONNECTIVITY_DOMAINS || '').split(',').map(s => s.trim()).filter(Boolean);
const FREE_MACS  = new Set((process.env.FREE_MACS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
const ADMIN_USERS = {};
(process.env.ADMIN_USERS || 'admin:1234').split(',').forEach(e => {
  const [u, ...rest] = e.split(':');
  if (u && rest.length) ADMIN_USERS[u.trim()] = rest.join(':').trim();
});

function T() { return new Date().toTimeString().slice(0, 8); }
const L = {
  info: s => console.log(`\x1b[36m[${T()}]\x1b[0m ${s}`),
  ok:   s => console.log(`\x1b[32m[${T()}]\x1b[0m ${s}`),
  warn: s => console.log(`\x1b[33m[${T()}]\x1b[0m ${s}`),
  err:  s => console.log(`\x1b[31m[${T()}]\x1b[0m ${s}`),
};

const app = express();
app.use(express.json());
const server = http.createServer(app);

const authed   = new Set();
const sessions = new Map();
const devices  = new Map();
const log      = [];

function pushLog(mac, ip, type, data) {
  if (log.length >= LOG_MAX) log.shift();
  log.push({ ts: Date.now(), mac, ip, type, data });
}

function run(cmd) {
  try { return execSync(cmd, { stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000 }).toString().trim(); }
  catch (_) { return ''; }
}

let iptBusy = false;
const iptQ = [];
function ipt(rule) {
  return new Promise(resolve => {
    iptQ.push({ rule, resolve });
    if (!iptBusy) drainIpt();
  });
}
function drainIpt() {
  if (!iptQ.length) { iptBusy = false; return; }
  iptBusy = true;
  const { rule, resolve } = iptQ.shift();
  exec(`su -c "iptables ${rule}"`, { timeout: 8000 }, () => { resolve(); drainIpt(); });
}

const macCache = new Map();
const MAC_TTL = 30000;

function getMac(ip) {
  const hit = macCache.get(ip);
  if (hit && Date.now() - hit.ts < MAC_TTL) return hit.mac;
  let mac = null;
  try {
    const arp = fs.readFileSync('/proc/net/arp', 'utf8');
    for (const line of arp.split('\n').slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols[0] === ip && cols[3] && cols[3] !== '00:00:00:00:00:00') { mac = cols[3].toLowerCase(); break; }
    }
  } catch (_) {}
  if (!mac) {
    const m = run(`su -c "ip neigh show ${ip}"`).match(/([0-9a-f]{2}(:[0-9a-f]{2}){5})/i);
    mac = m ? m[1].toLowerCase() : null;
  }
  if (mac) macCache.set(ip, { mac, ts: Date.now() });
  return mac;
}

function getMacCached(ip) {
  const hit = macCache.get(ip);
  return (hit && Date.now() - hit.ts < MAC_TTL) ? hit.mac : null;
}

function getGatewayIP() {
  if (process.env.GW) return process.env.GW;
  for (const cmd of [
    `su -c "ip addr show ${IFACE_IN}"`,
    `ip addr show ${IFACE_IN}`,
    `ifconfig ${IFACE_IN}`,
  ]) {
    const m = run(cmd).match(/inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)/);
    if (m) return m[1];
  }
  L.err(`GW detect failed, fallback`);
  return '192.168.43.1';
}

const GW = getGatewayIP();
const PORTAL_URL = `http://${GW}:${PORT}/`;

async function initRules() {
  L.info(`initRules GW=${GW} IFACE=${IFACE_IN} PORT=${PORT} DNS=${DNS_PORT}`);
  run(`su -c "iptables -t nat -N PORTAL_PRE 2>/dev/null"`);
  await ipt(`-t nat -F PORTAL_PRE`);
  run(`su -c "iptables -t nat -D PREROUTING -i ${IFACE_IN} -j PORTAL_PRE 2>/dev/null"`);
  await ipt(`-t nat -I PREROUTING -i ${IFACE_IN} -j PORTAL_PRE`);
  await ipt(`-t nat -A PORTAL_PRE -p udp --dport 53 -j DNAT --to-destination ${GW}:${DNS_PORT}`);
  await ipt(`-t nat -A PORTAL_PRE -p tcp --dport 80 -j REDIRECT --to-port ${PORT}`);
  await ipt(`-t nat -A PORTAL_PRE -p tcp --dport 443 -j REDIRECT --to-port ${PORT}`);
  run(`su -c "iptables -N PORTAL_WA 2>/dev/null"`);
  await ipt(`-F PORTAL_WA`);
  for (const r of WA_RANGES) await ipt(`-A PORTAL_WA -d ${r} -j ACCEPT`);
  await ipt(`-A PORTAL_WA -m state --state RELATED,ESTABLISHED -j ACCEPT`);
  await ipt(`-A PORTAL_WA -j DROP`);
  run(`su -c "iptables -D INPUT -i ${IFACE_IN} -p tcp --dport ${PORT} -j ACCEPT 2>/dev/null"`);
  await ipt(`-I INPUT -i ${IFACE_IN} -p tcp --dport ${PORT} -j ACCEPT`);
  for (const mac of FREE_MACS) {
    run(`su -c "iptables -D FORWARD -i ${IFACE_IN} -m mac --mac-source ${mac} -j ACCEPT 2>/dev/null"`);
    await ipt(`-I FORWARD -i ${IFACE_IN} -m mac --mac-source ${mac} -j ACCEPT`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p udp --dport 53 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 443 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 80 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -d ${GW} -p tcp --dport 80 -j REDIRECT --to-port ${PORT}`);
    L.ok(`FREE_MAC pre-auth: ${mac}`);
  }
}

async function restrictMac(mac) {
  await ipt(`-D FORWARD -i ${IFACE_IN} -m mac --mac-source ${mac} -j ACCEPT`);
  if (!FREE_MACS.has(mac)) await ipt(`-I FORWARD -i ${IFACE_IN} -m mac --mac-source ${mac} -j PORTAL_WA`);
  const d = devices.get(mac);
  if (d) { d.restricted = true; d.restrictedAt = Date.now(); }
  L.warn(`RESTRICT ${mac}`);
}

async function authMac(mac, ip) {
  if (authed.has(mac)) return;
  authed.add(mac);
  if (!devices.has(mac))
    devices.set(mac, { mac, ip, authedAt: Date.now(), restricted: false, restrictedAt: null, domains: [], free: FREE_MACS.has(mac) });
  if (!FREE_MACS.has(mac)) {
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p udp --dport 53 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 80 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 443 -j RETURN`);
    await ipt(`-I FORWARD -i ${IFACE_IN} -m mac --mac-source ${mac} -j ACCEPT`);
    setTimeout(() => restrictMac(mac), OPEN_MS);
  }
  pushLog(mac, ip, 'auth', null);
  L.ok(`AUTH ${mac} ${ip}`);
}

async function deauthMac(mac) {
  authed.delete(mac);
  await ipt(`-t nat -D PORTAL_PRE -m mac --mac-source ${mac} -p udp --dport 53 -j RETURN`);
  await ipt(`-t nat -D PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 80 -j RETURN`);
  await ipt(`-t nat -D PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 443 -j RETURN`);
  await ipt(`-D FORWARD -i ${IFACE_IN} -m mac --mac-source ${mac} -j ACCEPT`);
  await ipt(`-D FORWARD -i ${IFACE_IN} -m mac --mac-source ${mac} -j PORTAL_WA`);
  devices.delete(mac);
  pushLog(mac, '', 'deauth', null);
  L.warn(`DEAUTH ${mac}`);
}

function parseDnsName(buf) {
  try {
    let off = 12, name = '';
    while (buf[off]) {
      if (name) name += '.';
      name += buf.slice(off + 1, off + 1 + buf[off]).toString();
      off += buf[off] + 1;
    }
    return name.toLowerCase();
  } catch (_) { return ''; }
}

function isConnHost(name) {
  return CONN_HOSTS.some(h => name === h || name.endsWith('.' + h));
}

function dnsReply(reqBuf, ip) {
  try {
    const id = reqBuf.slice(0, 2);
    let off = 12;
    while (off < reqBuf.length && reqBuf[off] !== 0) off += reqBuf[off] + 1;
    off++;
    const qdSection = reqBuf.slice(12, off + 4);
    const parts = ip.split('.').map(Number);
    const res = Buffer.alloc(12 + qdSection.length + 16);
    id.copy(res, 0);
    res.writeUInt16BE(0x8180, 2);
    res.writeUInt16BE(1, 4);
    res.writeUInt16BE(1, 6);
    res.writeUInt16BE(0, 8);
    res.writeUInt16BE(0, 10);
    qdSection.copy(res, 12);
    const a = 12 + qdSection.length;
    res.writeUInt16BE(0xc00c, a);
    res.writeUInt16BE(1, a + 2);
    res.writeUInt16BE(1, a + 4);
    res.writeUInt32BE(10, a + 6);
    res.writeUInt16BE(4, a + 10);
    parts.forEach((b, i) => { res[a + 12 + i] = b; });
    return res;
  } catch (_) { return null; }
}

let fwdActive = 0;
const FWD_MAX = 8;

function forwardDns(msg, rinfo) {
  if (fwdActive >= FWD_MAX) return;
  fwdActive++;
  const sock = dgram.createSocket('udp4');
  let closed = false;
  const done = () => {
    if (closed) return;
    closed = true;
    fwdActive--;
    try { sock.close(); } catch (_) {}
  };
  sock.on('message', r => { dnsServer.send(r, rinfo.port, rinfo.address); done(); });
  sock.on('error', done);
  sock.send(msg, 53, '8.8.8.8');
  setTimeout(done, 3000);
}

const dnsServer = dgram.createSocket('udp4');
dnsServer.on('error', e => L.err(`DNS ${e.message}`));
dnsServer.on('message', (msg, rinfo) => {
  const name = parseDnsName(msg);
  if (name) {
    const mac = getMacCached(rinfo.address);
    if (mac && devices.has(mac)) {
      const d = devices.get(mac);
      if (!d.domains.includes(name)) {
        if (d.domains.length >= 200) d.domains.shift();
        d.domains.push(name);
      }
      pushLog(mac, rinfo.address, 'dns', name);
    }
  }
  if (isConnHost(name)) forwardDns(msg, rinfo);
  else {
    const reply = dnsReply(msg, GW);
    if (reply) dnsServer.send(reply, rinfo.port, rinfo.address);
  }
});

const sleep = ms => new Promise(r => setTimeout(r, ms));

setInterval(async () => {
  const macs = [...devices.keys()].filter(m => !FREE_MACS.has(m));
  for (const mac of macs) {
    await deauthMac(mac);
    await sleep(200);
  }
  if (macs.length) L.info(`Cleanup: ${macs.length} deautenticados`);
}, CLEAN_MS);

function getCookies(req) {
  const c = {};
  (req.headers.cookie || '').split(';').forEach(s => {
    const [k, ...v] = s.trim().split('=');
    if (k) c[k.trim()] = v.join('=');
  });
  return c;
}

function getToken(req) {
  if (req.headers['x-admin-token']) return req.headers['x-admin-token'];
  const ck = getCookies(req).at;
  if (ck) return ck;
  const u = new URL(req.url || '/', 'http://localhost');
  return u.searchParams.get('t') || null;
}

function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').replace('::ffff:', '');
}

function adminAuth(req, res, next) {
  const token = getToken(req);
  if (token && sessions.has(token)) return next();
  res.status(401).json({ err: 'Unauthorized' });
}

app.post('/api/login', async (req, res) => {
  const ip = getIP(req);
  const mac = getMac(ip);
  if (!mac || !FREE_MACS.has(mac)) {
    L.warn(`LOGIN deny mac=${mac || '?'} ip=${ip}`);
    return res.status(403).json({ err: 'Forbidden' });
  }
  const { user, pass } = req.body || {};
  if (ADMIN_USERS[user] && ADMIN_USERS[user] === pass) {
    const token = crypto.randomBytes(16).toString('hex');
    sessions.set(token, user);
    res.setHeader('Set-Cookie', `at=${token};Path=/;HttpOnly`);
    await authMac(mac, ip);
    L.ok(`LOGIN ok user=${user} ip=${ip} mac=${mac}`);
    res.json({ ok: true, token, user, free: FREE_MACS.has(mac) });
  } else {
    L.warn(`LOGIN fail user=${user} ip=${ip}`);
    res.status(401).json({ ok: false });
  }
});

app.post('/api/logout', adminAuth, (req, res) => {
  const user = sessions.get(getToken(req));
  sessions.delete(getToken(req));
  L.info(`LOGOUT user=${user}`);
  res.json({ ok: true });
});

app.get('/api/me', adminAuth, (req, res) => {
  res.json({ user: sessions.get(getToken(req)) });
});

app.get('/api/devices', adminAuth, (req, res) => res.json([...devices.values()]));

app.post('/api/deauth/:mac', adminAuth, async (req, res) => {
  const mac = req.params.mac;
  if (FREE_MACS.has(mac)) return res.status(400).json({ err: 'Cannot deauth free MAC' });
  await deauthMac(mac);
  res.json({ ok: true });
});

app.get('/api/log', adminAuth, (req, res) => res.json(log.slice(-200)));

app.get('/api/env', adminAuth, (req, res) => {
  const p = path.join(__dirname, '.env');
  res.json({ content: fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '' });
});

app.post('/api/env', adminAuth, (req, res) => {
  const { content } = req.body || {};
  if (typeof content !== 'string') return res.status(400).json({ err: 'invalid' });
  fs.writeFileSync(path.join(__dirname, '.env'), content, 'utf8');
  L.info(`ENV saved by ${sessions.get(getToken(req))}`);
  res.json({ ok: true });
});

app.post('/api/stop', adminAuth, (req, res) => {
  L.warn(`STOP requested by ${sessions.get(getToken(req))}`);
  res.json({ ok: true });
  setTimeout(() => process.exit(0), 300);
});

const wss = new WebSocketServer({ server, path: '/ws/shell' });
wss.on('connection', (ws, req) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').replace('::ffff:', '');
  const token = getToken(req);
  if (!token || !sessions.has(token)) { ws.close(1008, 'Unauthorized'); return; }
  const user = sessions.get(token);
  L.info(`WS shell opened user=${user} ip=${ip}`);
  let activeProc = null;

  ws.on('message', data => {
    const cmd = data.toString().trim();
    if (!cmd) return;
    if (activeProc) { try { activeProc.kill(); } catch (_) {} }
    L.info(`CMD [${user}] ${cmd}`);
    const proc = spawn('su', ['-c', cmd], { shell: false });
    activeProc = proc;
    let out = '', err = '';
    proc.stdout.on('data', d => { out += d.toString(); });
    proc.stderr.on('data', d => { err += d.toString(); });
    const timer = setTimeout(() => { try { proc.kill(); } catch (_) {} }, 10000);
    proc.on('close', () => {
      clearTimeout(timer);
      activeProc = null;
      if (ws.readyState === 1)
        ws.send(JSON.stringify({ stdout: out, stderr: err, err: null }));
    });
    proc.on('error', e => {
      if (ws.readyState === 1)
        ws.send(JSON.stringify({ stdout: '', stderr: '', err: e.message }));
    });
  });

  ws.on('close', () => {
    if (activeProc) { try { activeProc.kill(); } catch (_) {} }
    L.info(`WS shell closed user=${user}`);
  });
});

const CP_HTML = '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>';
const CP_CHECKS = {
  '/hotspot-detect.html':       CP_HTML,
  '/library/test/success.html': CP_HTML,
  '/bag':                       CP_HTML,
  '/kindle-wifi/wifistub.html': CP_HTML,
  '/connecttest.txt':           'Microsoft Connect Test',
  '/ncsi.txt':                  'Microsoft NCSI',
  '/success.txt':               'success\n',
  '/check_network_status.txt':  'NetworkManager is online\n',
  '/hotspotdetect.html':        CP_HTML,
  '/canonical.html':            CP_HTML,
  '/redirect':                  CP_HTML,
};
app.get(Object.keys(CP_CHECKS), (req, res) => {
  const mac = getMacCached(getIP(req));
  if (mac && authed.has(mac)) return res.send(CP_CHECKS[req.path]);
  res.redirect(302, PORTAL_URL);
});
app.get(['/generate_204', '/gen_204', '/204'], (req, res) => {
  const mac = getMacCached(getIP(req));
  if (mac && authed.has(mac)) return res.status(204).send();
  res.redirect(302, PORTAL_URL);
});

const BLOCKED = /^\/(\.env|server\.js|package\.json|\.git|x\.sh|\.npmrc)/i;
app.use((req, res, next) => BLOCKED.test(req.path) ? res.status(404).end() : next());
app.use(express.static(path.join(__dirname)));

app.post('/auth', async (req, res) => {
  const ip = getIP(req);
  const mac = getMac(ip);
  if (mac) { await authMac(mac, ip); res.json({ ok: true }); }
  else {
    L.warn(`AUTH fail: no MAC ip=${ip}`);
    res.json({ ok: false, err: 'MAC no encontrada' });
  }
});

(async () => {
  await initRules();
  dnsServer.bind(DNS_PORT, '0.0.0.0', () => L.info(`DNS :${DNS_PORT}`));
  server.listen(PORT, '0.0.0.0', () => L.ok(`Portal :${PORT}`));
})();
