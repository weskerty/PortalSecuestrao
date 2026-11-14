'use strict';

const fs = require('fs');
const path = require('path');

/* Un valor entre comillas se toma literal hasta la comilla de cierre; sin
 * comillas, un " #" inicia comentario. Sin esto "IFACE_IN=wlan1 # la del
 * hotspot" acaba interpolado dentro de un su -c "iptables ...". */
function parseValue(raw) {
  let v = String(raw).replace(/\r/g, '').replace(/^\s+/, '');
  const q = v[0];
  if (q === '"' || q === '\'') {
    const end = v.indexOf(q, 1);
    return end > 0 ? v.slice(1, end) : v.slice(1);
  }
  const cut = v.search(/\s#/);
  if (cut >= 0) v = v.slice(0, cut);
  return v.trim();
}

/* El \r se normaliza antes de partir en lineas porque en JS "." no matchea los
 * terminadores de linea, \r incluido: con CRLF la regex de abajo no casa nada
 * y un .env editado en Windows se lee entero como vacio. */
function parseEnv(text) {
  const out = {};
  for (const line of String(text).replace(/\r\n?/g, '\n').split('\n')) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/);
    if (m) out[m[1]] = parseValue(m[2]);
  }
  return out;
}

function envKeys(text) { return Object.keys(parseEnv(text)); }

/* Incluye las claves comentadas. Comentar una opcion es una forma deliberada
 * de dejarla en su valor por defecto, asi que anadirla de vuelta al
 * actualizar seria deshacer una decision del usuario. */
function mentionedKeys(text) {
  const out = new Set();
  for (const line of String(text).replace(/\r\n?/g, '\n').split('\n')) {
    const m = line.match(/^\s*#*\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m) out.add(m[1]);
  }
  return out;
}

/* .env es de cada instalacion y no se versiona: si falta se siembra desde
 * .env.example, y si existe solo se le anaden las claves nuevas, para que una
 * actualizacion no pise valores ya ajustados. */
function ensureEnvFile(dir, log = () => {}) {
  const envPath = path.join(dir, '.env');
  const examplePath = path.join(dir, '.env.example');
  if (!fs.existsSync(examplePath)) return envPath;

  const example = fs.readFileSync(examplePath, 'utf8');
  if (!fs.existsSync(envPath)) {
    fs.writeFileSync(envPath, example, 'utf8');
    log('.env creado desde .env.example');
    return envPath;
  }

  const current = fs.readFileSync(envPath, 'utf8');
  const have = mentionedKeys(current);
  const defaults = parseEnv(example);
  const missing = Object.keys(defaults).filter(k => !have.has(k));
  if (!missing.length) return envPath;

  const add = missing.map(k => `${k}=${defaults[k]}`).join('\n');
  const sep = current.endsWith('\n') ? '' : '\n';
  fs.appendFileSync(envPath,
    `${sep}\n# --- claves nuevas anadidas automaticamente, revisalas ---\n${add}\n`, 'utf8');
  log(`.env: ${missing.length} clave(s) nueva(s): ${missing.join(', ')}`);
  return envPath;
}

/* Igual que .env: la plantilla se versiona y la copia de trabajo no, para que
 * una actualizacion no pise la personalizacion de cada instalacion. */
function ensureSeed(srcPath, dstPath, log = () => {}) {
  try {
    if (fs.existsSync(dstPath) || !fs.existsSync(srcPath)) return false;
    fs.copyFileSync(srcPath, dstPath);
    log(`${path.basename(dstPath)} creado desde ${path.basename(srcPath)}`);
    return true;
  } catch (_) { return false; }
}

function loadEnvFile(dir, log) {
  const envPath = ensureEnvFile(dir, log);
  if (!fs.existsSync(envPath)) return {};
  const parsed = parseEnv(fs.readFileSync(envPath, 'utf8'));
  for (const [k, v] of Object.entries(parsed))
    if (process.env[k] === undefined) process.env[k] = v;
  return parsed;
}

const csv = v => String(v || '').split(',').map(s => s.trim()).filter(Boolean);

const IFACE_RE  = /^[A-Za-z0-9._@-]{1,15}$/;
const IP_RE     = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const MAC_RE    = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

function isValidIp(ip) {
  return typeof ip === 'string' && IP_RE.test(ip) && ip.split('.').every(o => Number(o) <= 255);
}
function isValidMac(mac) { return typeof mac === 'string' && MAC_RE.test(mac); }
function isValidIface(n) { return typeof n === 'string' && IFACE_RE.test(n); }
function isValidDomain(d) {
  return typeof d === 'string' && d.length > 0 && d.length <= 253 && DOMAIN_RE.test(d);
}
function isValidCidr(c) {
  const m = String(c).match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!m) return false;
  const bits = Number(m[2]);
  return isValidIp(m[1]) && bits >= 0 && bits <= 32;
}

/* parseInt(x) || def descarta el 0, que es un valor valido para OPEN_MS,
 * CLEAN_MS y los *_MS de refresco. */
function num(v, def, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (v === undefined || v === null || String(v).trim() === '') return def;
  const n = Number(String(v).trim());
  if (!Number.isFinite(n) || n < min || n > max) return def;
  return Math.trunc(n);
}
function bool(v, def) {
  if (v === undefined || v === null || String(v).trim() === '') return def;
  return !/^(0|no|off|false)$/i.test(String(v).trim());
}

function ipToInt(ip) {
  const o = ip.split('.');
  if (o.length !== 4) return 0;
  return (((+o[0] << 24) | (+o[1] << 16) | (+o[2] << 8) | +o[3]) >>> 0);
}
function intToIp(n) {
  return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}
function maskOf(bits) { return bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0; }

function isPublicUnicast(ip) {
  if (!isValidIp(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a >= 224) return false;
  return true;
}

function parseWiden(spec) {
  const m = String(spec).match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+):(\d+)$/);
  if (!m || !isValidIp(m[1])) return null;
  const bits = Number(m[2]), to = Number(m[3]);
  if (bits < 0 || bits > 32 || to < 8 || to > 32 || to < bits) return null;
  const mask = maskOf(bits);
  return { base: (ipToInt(m[1]) & mask) >>> 0, mask, to };
}

function parseUsers(spec) {
  const out = {};
  for (const entry of csv(spec)) {
    const i = entry.indexOf(':');
    if (i <= 0) continue;
    const user = entry.slice(0, i).trim();
    const pass = entry.slice(i + 1).trim();
    if (user && pass) out[user] = pass;
  }
  return out;
}

function buildConfig(env = process.env) {
  const warn = [];
  const fatal = [];

  const iface = env.IFACE_IN ? String(env.IFACE_IN).trim() : '';
  if (iface && !isValidIface(iface)) fatal.push(`IFACE_IN invalido: ${JSON.stringify(iface)}`);
  const gw = env.GW ? String(env.GW).trim() : '';
  if (gw && !isValidIp(gw)) fatal.push(`GW invalido: ${JSON.stringify(gw)}`);

  const staticRanges = [];
  for (const r of csv(env.ALLOW_RANGES || env.WA_RANGES)) {
    const cidr = r.includes('/') ? r : `${r}/32`;
    if (!isValidCidr(cidr)) { warn.push(`ALLOW_RANGES: se ignora ${JSON.stringify(r)}`); continue; }
    staticRanges.push(cidr);
  }

  const norm = d => d.toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '');
  const allowDomains = [];
  for (const d of csv(env.ALLOW_DOMAINS || env.YESDOM)) {
    const name = norm(d);
    if (!isValidDomain(name)) { warn.push(`ALLOW_DOMAINS: se ignora ${JSON.stringify(d)}`); continue; }
    allowDomains.push(name);
  }
  const connDomains = [];
  for (const d of csv(env.CONNECTIVITY_DOMAINS)) {
    const name = norm(d);
    if (!isValidDomain(name)) { warn.push(`CONNECTIVITY_DOMAINS: se ignora ${JSON.stringify(d)}`); continue; }
    connDomains.push(name);
  }

  const freeMacs = new Set();
  for (const m of csv(env.FREE_MACS)) {
    const mac = m.toLowerCase();
    if (!isValidMac(mac)) { warn.push(`FREE_MACS: se ignora ${JSON.stringify(m)}`); continue; }
    freeMacs.add(mac);
  }

  const widen = [];
  for (const w of csv(env.SNOOP_WIDEN)) {
    const p = parseWiden(w);
    if (!p) { warn.push(`SNOOP_WIDEN: se ignora ${JSON.stringify(w)}`); continue; }
    widen.push(p);
  }

  const admin = bool(env.ADMIN, true);
  const users = parseUsers(env.ADMIN_USERS);

  const cfg = {
    iface, gw,
    port:      num(env.PORT, 8080, { min: 1, max: 65535 }),
    dnsPort:   num(env.DNS_PORT, 5454, { min: 1, max: 65535 }),
    detectMs:  num(env.DETECT_MS, 10000),
    blockIpv6: bool(env.BLOCK_IPV6, true),
    isolate:   bool(env.ISOLATE, true),

    admin,
    adminShell:   admin && bool(env.ADMIN_SHELL, false),
    users,
    sessionTtlMs: num(env.SESSION_TTL_MS, 86400000),

    openMs:  num(env.OPEN_MS, 7000),
    cleanMs: num(env.CLEAN_MS, 3600000),
    speed:   num(env.SPEED, 0),
    logMax:  num(env.LOG_MAX, 500, { min: 1 }),
    freeMacs,

    staticRanges,
    allowDomains,
    connDomains,
    connAllow: bool(env.CONN_ALLOW, true),

    snoop:          bool(env.SNOOP, true) && allowDomains.length > 0,
    snoopMax:       num(env.SNOOP_MAX, 256, { min: 1 }),
    snoopTtlMs:     num(env.SNOOP_TTL_MS, 86400000),
    snoopRefreshMs: num(env.SNOOP_REFRESH_MS, 1800000),
    snoopCache:     env.SNOOP_CACHE === undefined ? '.snoop.json' : String(env.SNOOP_CACHE).trim(),
    snoopForceDns:  bool(env.SNOOP_FORCE_DNS, false),
    widen,

    resolvers: csv(env.RESOLVERS).filter(isValidIp),
    warn, fatal,
  };
  if (!cfg.resolvers.length) cfg.resolvers = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

  for (const r of staticRanges)
    if (!isPublicUnicast(r.split('/')[0]))
      warn.push(`ALLOW_RANGES: ${r} es privado y con ISOLATE=1 quedara bloqueado`);

  return cfg;
}

module.exports = {
  parseEnv, parseValue, envKeys, mentionedKeys, ensureEnvFile, ensureSeed, loadEnvFile, buildConfig,
  csv, num, bool,
  isValidIp, isValidMac, isValidIface, isValidDomain, isValidCidr,
  isPublicUnicast, ipToInt, intToIp, maskOf, parseWiden, parseUsers,
};
