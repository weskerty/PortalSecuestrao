'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dnsMod = require('dns');
const { spawn } = require('child_process');
const { WebSocketServer } = require('ws');

const C = require('./lib/config');
const { hasRoot } = require('./lib/sh');
const detectMod = require('./lib/detect');
const { Firewall } = require('./lib/fw');
const { Allowlist } = require('./lib/allowlist');
const { DnsProxy, safeName } = require('./lib/dnsproxy');
const { MacTable, MarkPool } = require('./lib/clients');

const DIR = __dirname;
const PUBLIC_DIR = path.join(DIR, 'public');
const TERMUX_SH = '/data/data/com.termux/files/usr/bin/bash';

/* ------------------------------------------------------------------- log --- */

const COLOR = { info: 36, ok: 32, warn: 33, err: 31 };
function stamp() { return new Date().toTimeString().slice(0, 8); }
function L(level, msg) {
  const c = COLOR[level] || 36;
  console.log(`\x1b[${c}m[${stamp()}]\x1b[0m ${msg}`);
}
L.info = m => L('info', m);
L.ok   = m => L('ok', m);
L.warn = m => L('warn', m);
L.err  = m => L('err', m);

/* ------------------------------------------------------------------ conf --- */

C.loadEnvFile(DIR, m => L.info(m));
C.ensureSeed(path.join(PUBLIC_DIR, 'index.default.html'), path.join(PUBLIC_DIR, 'index.html'), m => L.info(m));
const cfg = C.buildConfig(process.env);

for (const w of cfg.warn) L.warn(w);
if (cfg.fatal.length) {
  for (const f of cfg.fatal) L.err(f);
  L.err('Revisa el .env. No se arranca con valores que acabarian dentro de un comando de root.');
  process.exit(1);
}

/* Sin ADMIN_USERS el panel quedaba con admin:1234. Una clave aleatoria por
 * arranque es util para entrar una vez y no deja una puerta conocida. */
let generatedPass = null;
if (cfg.admin && !Object.keys(cfg.users).length) {
  generatedPass = crypto.randomBytes(6).toString('base64url');
  cfg.users.admin = generatedPass;
}

/* ----------------------------------------------------------------- state --- */

const authed = new Set();
const devices = new Map();
const sessions = new Map();
const logBuf = [];
const openTimers = new Map();
const loginAttempts = new Map();

const macs = new MacTable({ log: L });
const marks = new MarkPool(60);

const fw = new Firewall({
  iface: cfg.iface, gw: cfg.gw, port: cfg.port, dnsPort: cfg.dnsPort,
  freeMacs: cfg.freeMacs, isolate: cfg.isolate, blockIpv6: cfg.blockIpv6,
  snoopForceDns: cfg.snoopForceDns, speed: cfg.speed,
  log: (lvl, m) => L(lvl, m),
});

const allow = new Allowlist({
  staticRanges: cfg.staticRanges, widen: cfg.widen, max: cfg.snoopMax,
  ttlMs: cfg.snoopTtlMs, cachePath: cfg.snoopCache, dir: DIR, fw,
  log: (lvl, m) => L(lvl, m),
});

let net = { iface: cfg.iface, gw: cfg.gw, upIface: '', upKind: '', source: '' };
let portalUrl = '';

function pushLog(mac, ip, type, data) {
  if (logBuf.length >= cfg.logMax) logBuf.shift();
  logBuf.push({ ts: Date.now(), mac, ip, type, data });
}

/* --------------------------------------------------------------- clientes --- */

function isAuthedIp(ip) {
  const mac = macs.cached(ip);
  return Boolean(mac && authed.has(mac));
}

async function shapeAuth(mac, ip) {
  if (!cfg.speed || cfg.freeMacs.has(mac)) return;
  const stale = marks.byIp(ip);
  if (stale && stale !== mac) {
    const e = marks.release(stale);
    if (e) await fw.tcDel(e.mark, e.ip);
  }
  const mine = marks.used.get(mac);
  if (mine && mine.ip !== ip) await fw.tcDel(mine.mark, mine.ip);
  if (marks.full()) {
    const old = marks.oldest();
    const e = marks.release(old);
    if (e) { await fw.tcDel(e.mark, e.ip); L.warn(`tc: liberada la marca de ${old}`); }
  }
  const e = marks.take(mac, ip);
  await fw.tcAdd(e.mark, ip);
}

async function shapeFree(mac) {
  if (!cfg.speed) return;
  const e = marks.release(mac);
  if (e) await fw.tcDel(e.mark, e.ip);
}

async function authMac(mac, ip) {
  if (!C.isValidMac(mac)) return false;
  if (authed.has(mac)) return true;
  authed.add(mac);
  if (!devices.has(mac))
    devices.set(mac, {
      mac, ip, authedAt: Date.now(), restricted: false, restrictedAt: null,
      domains: [], free: cfg.freeMacs.has(mac),
    });

  if (!cfg.freeMacs.has(mac)) {
    const noWindow = cfg.openMs <= 0;
    await fw.openMac(mac, { restricted: noWindow });
    await shapeAuth(mac, ip);
    const d = devices.get(mac);
    if (noWindow && d) { d.restricted = true; d.restrictedAt = Date.now(); }
    if (!noWindow) {
      const t = setTimeout(() => { openTimers.delete(mac); restrictMac(mac); }, cfg.openMs);
      if (t.unref) t.unref();
      openTimers.set(mac, t);
    }
  }
  pushLog(mac, ip, 'auth', null);
  L.ok(`auth ${mac} ${ip}`);
  return true;
}

/* El temporizador de OPEN_MS puede dispararse despues de que el dispositivo ya
 * haya sido desautenticado; sin esta comprobacion insertaba una regla para una
 * MAC que ya no esta y quedaba viva hasta el siguiente arranque. */
async function restrictMac(mac) {
  if (!authed.has(mac)) return;
  if (cfg.freeMacs.has(mac)) return;
  await fw.restrictMac(mac);
  const d = devices.get(mac);
  if (d) { d.restricted = true; d.restrictedAt = Date.now(); }
  L.warn(`restrict ${mac}`);
}

async function deauthMac(mac) {
  const t = openTimers.get(mac);
  if (t) { clearTimeout(t); openTimers.delete(mac); }
  authed.delete(mac);
  await shapeFree(mac);
  await fw.closeMac(mac);
  devices.delete(mac);
  pushLog(mac, '', 'deauth', null);
  L.warn(`deauth ${mac}`);
}

/* ------------------------------------------------------------- allowlist --- */

function resolve4Via(server, host, timeoutMs = 5000) {
  return new Promise(resolve => {
    let done = false;
    const fin = v => { if (!done) { done = true; resolve(v); } };
    const timer = setTimeout(() => fin([]), timeoutMs);
    try {
      const r = new dnsMod.Resolver();
      r.setServers([server]);
      r.resolve4(host, (e, a) => {
        clearTimeout(timer);
        fin(!e && Array.isArray(a) ? a : []);
      });
    } catch (_) { clearTimeout(timer); fin([]); }
  });
}

async function resolve4All(host) {
  const lists = await Promise.all(cfg.resolvers.map(s => resolve4Via(s, host)));
  return [...new Set(lists.flat())];
}

async function resolveDomains({ applyRule = true } = {}) {
  const names = [...cfg.allowDomains];
  if (cfg.connAllow) names.push(...cfg.connDomains);
  if (!names.length) return 0;
  let added = 0;
  for (const d of names) {
    const addrs = await resolve4All(d);
    const ok = addrs.filter(C.isPublicUnicast);
    if (!ok.length) { L.warn(`sin respuesta util para ${d}`); continue; }
    for (const ip of ok) if (await allow.learn(ip, `boot:${d}`, { applyRule })) added++;
  }
  return added;
}

/* ------------------------------------------------------------------ http --- */

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));

function clientIp(req) {
  /* No hay proxy delante: X-Forwarded-For lo pone el propio cliente y confiar
   * en el permitia inyectar texto arbitrario donde antes se usaba la IP para
   * construir comandos. */
  return String(req.socket.remoteAddress || '').replace('::ffff:', '');
}

function isLoopback(ip) { return ip === '127.0.0.1' || ip === '::1'; }

function cookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/* El token solo viaja por cabecera o cookie. Aceptarlo por query lo deja
 * escrito en logs y en la cabecera Referer de cualquier recurso externo. */
function tokenOf(req) {
  return req.headers['x-admin-token'] || cookies(req).at || null;
}

function sessionOf(req) {
  const t = tokenOf(req);
  if (!t) return null;
  const s = sessions.get(t);
  if (!s) return null;
  if (cfg.sessionTtlMs && Date.now() - s.ts > cfg.sessionTtlMs) { sessions.delete(t); return null; }
  s.ts = Date.now();
  return { token: t, ...s };
}

function adminAuth(req, res, next) {
  const s = sessionOf(req);
  if (!s) return res.status(401).json({ err: 'Unauthorized' });
  req.session = s;
  next();
}

function loginBlocked(ip) {
  const a = loginAttempts.get(ip);
  return Boolean(a && a.fails >= 5 && Date.now() < a.until);
}
function loginFail(ip) {
  const a = loginAttempts.get(ip) || { fails: 0, until: 0 };
  a.fails++;
  if (a.fails >= 5) a.until = Date.now() + Math.min(30 * 60000, 60000 * 2 ** (a.fails - 5));
  loginAttempts.set(ip, a);
}

function samePass(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

if (!cfg.admin) {
  app.use((req, res, next) => (/^\/api(\/|$)/.test(req.path) ? res.status(404).end() : next()));
}

app.post('/api/login', async (req, res) => {
  const ip = clientIp(req);
  if (loginBlocked(ip)) {
    L.warn(`login bloqueado por intentos ip=${ip}`);
    return res.status(429).json({ err: 'Demasiados intentos, espera' });
  }
  const mac = isLoopback(ip) ? null : await macs.lookup(ip);
  const allowedHost = isLoopback(ip) || (mac && cfg.freeMacs.has(mac));
  if (!allowedHost) {
    loginFail(ip);
    L.warn(`login denegado mac=${mac || '?'} ip=${ip}`);
    return res.status(403).json({ err: 'Forbidden' });
  }
  const { user, pass } = req.body || {};
  const known = typeof user === 'string' && Object.prototype.hasOwnProperty.call(cfg.users, user);
  if (!known || !samePass(cfg.users[user], pass || '')) {
    loginFail(ip);
    L.warn(`login fallido user=${user} ip=${ip}`);
    return res.status(401).json({ ok: false });
  }
  loginAttempts.delete(ip);
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { user, ts: Date.now(), ip });
  res.setHeader('Set-Cookie', `at=${token};Path=/;HttpOnly;SameSite=Strict;Max-Age=${Math.floor(cfg.sessionTtlMs / 1000)}`);
  if (mac) await authMac(mac, ip);
  L.ok(`login ok user=${user} ip=${ip}`);
  res.json({ ok: true, user, free: Boolean(mac && cfg.freeMacs.has(mac)) });
});

app.post('/api/logout', adminAuth, (req, res) => {
  sessions.delete(req.session.token);
  res.setHeader('Set-Cookie', 'at=;Path=/;HttpOnly;SameSite=Strict;Max-Age=0');
  L.info(`logout ${req.session.user}`);
  res.json({ ok: true });
});

app.get('/api/me', adminAuth, (req, res) => res.json({ user: req.session.user }));

app.get('/api/status', adminAuth, (req, res) => {
  res.json({
    net,
    portalUrl,
    allow: allow.stats(),
    dns: dnsProxy ? dnsProxy.stats : null,
    devices: devices.size,
    authed: authed.size,
    openMs: cfg.openMs,
    speed: cfg.speed,
    isolate: cfg.isolate,
    blockIpv6: cfg.blockIpv6,
    snoop: cfg.snoop,
    adminShell: cfg.adminShell,
  });
});

app.get('/api/devices', adminAuth, (req, res) => res.json([...devices.values()]));

app.get('/api/allow', adminAuth, (req, res) => res.json({ fixed: allow.fixed, learned: allow.entries() }));

app.post('/api/deauth/:mac', adminAuth, async (req, res) => {
  const mac = String(req.params.mac || '').toLowerCase();
  if (!C.isValidMac(mac)) return res.status(400).json({ err: 'MAC invalida' });
  if (cfg.freeMacs.has(mac)) return res.status(400).json({ err: 'Es una MAC libre' });
  await deauthMac(mac);
  res.json({ ok: true });
});

app.get('/api/log', adminAuth, (req, res) => res.json(logBuf.slice(-200)));

app.get('/api/env', adminAuth, (req, res) => {
  const p = path.join(DIR, '.env');
  res.json({ content: fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '' });
});

/* Los valores de .env acaban dentro de comandos ejecutados como root, asi que
 * lo que se guarde tiene que pasar la misma validacion que al arrancar: con
 * ADMIN_SHELL=0 esta era la via que quedaba para ejecutar codigo arbitrario. */
app.post('/api/env', adminAuth, (req, res) => {
  const { content } = req.body || {};
  if (typeof content !== 'string') return res.status(400).json({ err: 'invalid' });
  const candidate = C.buildConfig(C.parseEnv(content));
  if (candidate.fatal.length)
    return res.status(400).json({ err: 'Valores invalidos', detail: candidate.fatal });
  fs.writeFileSync(path.join(DIR, '.env'), content, 'utf8');
  L.info(`.env guardado por ${req.session.user}`);
  res.json({
    ok: true,
    warn: candidate.warn,
    note: 'Guardado. Reinicia el proceso para aplicarlo (POST /api/stop si x.sh lo relanza).',
  });
});

app.post('/api/stop', adminAuth, (req, res) => {
  L.warn(`stop pedido por ${req.session.user}`);
  res.json({ ok: true });
  setTimeout(() => shutdown('api', EXIT.restart), 300);
});

/* -------------------------------------------------- portal cautivo (http) --- */

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
  res.set('Cache-Control', 'no-store');
  if (isAuthedIp(clientIp(req))) return res.send(CP_CHECKS[req.path]);
  res.redirect(302, portalUrl);
});

app.get(['/generate_204', '/gen_204', '/204'], (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (isAuthedIp(clientIp(req))) return res.status(204).end();
  res.redirect(302, portalUrl);
});

app.post('/auth', async (req, res) => {
  const ip = clientIp(req);
  const mac = await macs.lookup(ip);
  if (!mac) {
    L.warn(`auth sin MAC ip=${ip}`);
    return res.json({ ok: false, err: 'MAC no encontrada' });
  }
  await authMac(mac, ip);
  res.json({ ok: true });
});

if (cfg.admin) {
  app.get('/admin.html', (req, res) => res.sendFile(path.join(DIR, 'admin.html')));
}

/* Solo se sirve public/: con una lista negra sobre __dirname, cualquier
 * archivo nuevo en la carpeta (un .env.bak, notas, un volcado) queda publicado
 * hasta que alguien se acuerde de anadirlo a la lista. */
app.use(express.static(PUBLIC_DIR, { index: 'index.html', dotfiles: 'deny' }));

app.use((req, res) => {
  if (req.method === 'GET' && req.accepts('html')) return res.redirect(302, portalUrl);
  res.status(404).end();
});

/* --------------------------------------------------------------- ws shell --- */

let wss = null;
function setupShell(server) {
  if (!cfg.adminShell || wss) return;
  wss = new WebSocketServer({ server, path: '/ws/shell' });
  wss.on('connection', (ws, req) => {
    /* El WebSocket no pasa por CORS: sin comprobar Origin, cualquier pagina
     * que abra el admin puede conectarse con su cookie y ejecutar comandos. */
    const origin = req.headers.origin;
    if (origin) {
      let host = '';
      try { host = new URL(origin).host; } catch (_) {}
      if (host !== req.headers.host) { ws.close(1008, 'Origin'); return; }
    }
    const s = sessionOf(req);
    if (!s) { ws.close(1008, 'Unauthorized'); return; }
    const user = s.user;
    L.info(`shell abierta por ${user}`);
    let active = null;

    ws.on('message', data => {
      const cmd = data.toString().trim();
      if (!cmd) return;
      if (active) { try { active.kill(); } catch (_) {} }
      L.info(`cmd [${user}] ${cmd}`);
      const proc = spawn(TERMUX_SH, ['-c', cmd], {
        env: {
          PATH: `/data/data/com.termux/files/usr/bin:${process.env.PATH || '/system/bin'}`,
          HOME: '/data/data/com.termux/files/home',
          PREFIX: '/data/data/com.termux/files/usr',
          TMPDIR: '/data/data/com.termux/files/usr/tmp',
        },
      });
      active = proc;
      let out = '', err = '';
      proc.stdout.on('data', d => { out += d; });
      proc.stderr.on('data', d => { err += d; });
      const timer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch (_) {} }, 10000);
      proc.on('close', () => {
        clearTimeout(timer);
        active = null;
        if (ws.readyState === 1) ws.send(JSON.stringify({ stdout: out, stderr: err, err: null }));
      });
      proc.on('error', e => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ stdout: '', stderr: '', err: e.message }));
      });
    });

    ws.on('close', () => {
      if (active) { try { active.kill(); } catch (_) {} }
      L.info(`shell cerrada por ${user}`);
    });
  });
}

/* --------------------------------------------------------------- arranque --- */

let dnsProxy = null;
let servers = [];

function closeServers() {
  for (const s of servers) { try { s.close(); } catch (_) {} }
  servers = [];
  if (wss) { try { wss.close(); } catch (_) {} wss = null; }
}

function listenOn(addr) {
  return new Promise(resolve => {
    const srv = http.createServer(app);
    srv.on('error', e => { L.err(`http ${addr}: ${e.message}`); resolve(null); });
    srv.listen(cfg.port, addr, () => resolve(srv));
  });
}

async function bindServers() {
  closeServers();
  /* Escuchar en 0.0.0.0 publicaba el panel y el DNS en datos moviles y en
   * cualquier otra wifi del telefono. Solo el hotspot y loopback. */
  for (const addr of [net.gw, '127.0.0.1']) {
    const srv = await listenOn(addr);
    if (srv) { servers.push(srv); setupShell(srv); }
  }
  if (!servers.length) throw new Error(`no se pudo escuchar en ${net.gw}:${cfg.port}`);
  L.ok(`portal http://${net.gw}:${cfg.port}/`);

  if (dnsProxy) dnsProxy.stop();
  dnsProxy = new DnsProxy({
    port: cfg.dnsPort,
    bindAddr: net.gw,
    gw: net.gw,
    resolvers: cfg.resolvers,
    allowDomains: cfg.allowDomains,
    connDomains: cfg.connDomains,
    blockIpv6: cfg.blockIpv6,
    snoop: cfg.snoop,
    allowlist: allow,
    isAuthed: isAuthedIp,
    onQuery: recordQuery,
    log: (lvl, m) => L(lvl, m),
  });
  await dnsProxy.start();
  L.ok(`dns ${net.gw}:${cfg.dnsPort}`);
}

function recordQuery(ip, name) {
  const mac = macs.cached(ip);
  if (!mac) { macs.refresh().catch(() => {}); return; }
  const d = devices.get(mac);
  if (d) {
    if (!d.domains.includes(name)) {
      if (d.domains.length >= 200) d.domains.shift();
      d.domains.push(name);
    }
  }
  pushLog(mac, ip, 'dns', name);
}

async function waitForHotspot() {
  let warned = false;
  for (;;) {
    const r = await detectMod.detect({ iface: cfg.iface, gw: cfg.gw });
    if (r.ok) return r;
    if (!warned) {
      L.warn('No encuentro la interfaz del hotspot. Activa el anclaje; se vuelve a intentar cada 5s.');
      if (r.notes.length) for (const n of r.notes) L.warn(n);
      warned = true;
    }
    await new Promise(r2 => setTimeout(r2, 5000));
  }
}

async function applyNet(r, { first = false } = {}) {
  net = { iface: r.iface, gw: r.gw, upIface: r.upIface, upKind: r.upKind, source: r.source };
  portalUrl = `http://${r.gw}:${cfg.port}/`;
  fw.set({ iface: r.iface, gw: r.gw });

  const res = await fw.apply(allow.all());
  if (res.noRoot) {
    L.err('Sin root no se puede filtrar nada. El portal no arranca para no dar una falsa sensacion de control.');
    process.exit(1);
  }
  await fw.initTc();

  const v = await fw.verify();
  if (!v.ok) {
    L.err(`autotest de reglas FALLIDO: ${JSON.stringify(v)}`);
    L.err('El trafico NO esta filtrado. Revisa root, el modulo xt_mac y la interfaz.');
  } else {
    L.ok(`reglas activas y verificadas en ${r.iface}`);
  }

  await bindServers();
  if (!first) {
    for (const mac of [...devices.keys()]) await deauthMac(mac);
  }
  L.info(`hotspot ${r.iface} (${r.gw}) | salida ${r.upIface || '?'} [${r.upKind}] | deteccion: ${r.source || 'manual'}`);
  for (const n of r.notes) L.warn(n);
}

/* La interfaz y la subred del hotspot las elige la ROM y cambian al
 * reactivarlo. Si el DNAT sigue apuntando a la IP vieja, los clientes se
 * quedan sin DNS y nada lo delata. */
function startWatcher() {
  if (!cfg.detectMs) return;
  const timer = setInterval(async () => {
    try {
      /* ip addr e ip route se leen sin root; dumpsys solo se consulta cuando
       * algo cambio, para no invocar su cada pocos segundos. */
      const cheap = await detectMod.detect({ useRoot: false, iface: cfg.iface || net.iface, gw: cfg.gw });
      if (cheap.ok && cheap.iface === net.iface && cheap.gw === net.gw && fw.applied) {
        if (cheap.upIface && cheap.upIface !== net.upIface) {
          net.upIface = cheap.upIface;
          net.upKind = cheap.upKind;
          L.info(`la salida cambio a ${cheap.upIface} [${cheap.upKind}]`);
        }
        return;
      }

      const r = await detectMod.detect({ iface: cfg.iface, gw: cfg.gw });
      if (!r.ok) {
        if (fw.applied) {
          L.warn('el hotspot desaparecio; se retiran las reglas');
          await fw.teardown();
        }
        return;
      }
      if (r.iface !== net.iface || r.gw !== net.gw || !fw.applied) {
        L.warn(`cambio de red: ${net.iface}/${net.gw} -> ${r.iface}/${r.gw}`);
        await applyNet(r);
      } else if (r.upIface !== net.upIface) {
        net.upIface = r.upIface;
        net.upKind = r.upKind;
        L.info(`la salida cambio a ${r.upIface} [${r.upKind}]`);
      }
    } catch (e) { L.err(`watcher: ${e.message}`); }
  }, Math.max(3000, cfg.detectMs));
  if (timer.unref) timer.unref();
}

/* Codigos de salida: x.sh relanza solo con 70 (caida) y 75 (reinicio pedido
 * desde el panel). Con 0 y 1 se queda parado, para que Ctrl-C pare de verdad y
 * un error de configuracion no entre en bucle. */
const EXIT = { stop: 0, config: 1, crash: 70, restart: 75 };

let shuttingDown = false;
async function shutdown(why, code = EXIT.stop) {
  if (shuttingDown) return;
  shuttingDown = true;
  L.warn(`cerrando (${why})`);
  try { if (dnsProxy) dnsProxy.stop(); } catch (_) {}
  closeServers();
  allow.save();
  /* Las reglas son estado del kernel y sobreviven al proceso: si no se quitan,
   * el 53 sigue redirigido a un puerto muerto y el hotspot queda sin DNS. */
  try { await fw.teardown(); L.ok('reglas retiradas'); } catch (e) { L.err(`teardown: ${e.message}`); }
  process.exit(code);
}

for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => shutdown(sig));
process.on('uncaughtException', e => { L.err(`excepcion: ${e.stack || e.message}`); shutdown('uncaughtException', EXIT.crash); });
process.on('unhandledRejection', e => L.err(`promesa sin capturar: ${(e && e.message) || e}`));

(async () => {
  if (!await hasRoot()) {
    L.err('No hay root (su). Este portal no puede funcionar sin el.');
    process.exit(1);
  }

  const cached = await allow.loadInto();
  if (cached) L.info(`allowlist: ${cached} CIDR recuperados del cache`);
  await resolveDomains({ applyRule: false });

  const r = await waitForHotspot();
  await applyNet(r, { first: true });
  startWatcher();

  if (cfg.cleanMs > 0) {
    const t = setInterval(async () => {
      const list = [...devices.keys()].filter(m => !cfg.freeMacs.has(m));
      for (const mac of list) await deauthMac(mac);
      if (list.length) L.info(`limpieza: ${list.length} desautenticados`);
    }, cfg.cleanMs);
    if (t.unref) t.unref();
  }

  if (cfg.snoop && cfg.snoopRefreshMs > 0) {
    const t = setInterval(() => resolveDomains().catch(() => {}), cfg.snoopRefreshMs);
    if (t.unref) t.unref();
  }

  if (cfg.snoopTtlMs > 0) {
    const t = setInterval(() => {
      const n = allow.sweep();
      if (n) L.info(`allowlist: ${n} CIDR caducados`);
    }, Math.max(60000, Math.floor(cfg.snoopTtlMs / 10)));
    if (t.unref) t.unref();
  }

  const st = allow.stats();
  L.info(`allowlist: ${st.total} CIDR (${st.fixed} fijos, ${st.learned} aprendidos de ${st.max}) | snoop=${cfg.snoop ? 'on' : 'off'}${cfg.snoopForceDns ? ' force-dns' : ''} | widen=${cfg.widen.length}`);
  if (!st.total) L.warn('allowlist VACIA: nadie podra salir. Revisa ALLOW_RANGES / ALLOW_DOMAINS.');
  L.info(`panel=${cfg.admin ? 'on' : 'off'} shell=${cfg.adminShell ? 'ON' : 'off'} ipv6=${cfg.blockIpv6 ? 'bloqueado' : 'permitido'} aislamiento=${cfg.isolate ? 'on' : 'off'} openMs=${cfg.openMs}`);
  if (generatedPass) L.warn(`ADMIN_USERS vacio: usuario "admin" con clave temporal de este arranque: ${generatedPass}`);
  if (cfg.adminShell) L.warn('/ws/shell activo: ejecuta comandos en el telefono. ADMIN_SHELL=0 para quitarlo.');
})().catch(e => {
  L.err(`arranque: ${e.stack || e.message}`);
  process.exit(1);
});
