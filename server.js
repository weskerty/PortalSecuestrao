const express = require('express');
const { execSync, exec, spawn } = require('child_process');
const dgram = require('dgram');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const http = require('http');
const dnsMod = require('dns');

function loadEnv() {
  const p = path.join(__dirname, '.env');
  if (!fs.existsSync(p)) return;
  fs.readFileSync(p, 'utf8').split('\n').forEach(l => {
    const m = l.match(/^([^#=]+)=(.*)$/);
    if (m) process.env[m[1].trim()] = m[2].trim();
  });
}
loadEnv();

const PORT        = parseInt(process.env.PORT)     || 8080;
const DNS_PORT    = parseInt(process.env.DNS_PORT) || 5454;
const IFACE_IN    = process.env.IFACE_IN           || 'wlan2';
const OPEN_MS     = parseInt(process.env.OPEN_MS)  || 7000;
const LOG_MAX     = parseInt(process.env.LOG_MAX)  || 500;
const CLEAN_MS    = parseInt(process.env.CLEAN_MS) || 3600000;
const csv = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

// CIDRs permitidos de forma fija. WA_RANGES se mantiene como alias historico.
const STATIC_RANGES = csv(process.env.ALLOW_RANGES || process.env.WA_RANGES);
// Dominios permitidos: se resuelven al arrancar y se aprenden del trafico DNS
// real. YESDOM se mantiene como alias historico.
const ALLOW_DOMAINS = csv(process.env.ALLOW_DOMAINS || process.env.YESDOM)
  .map(d => d.toLowerCase().replace(/^\.+/, ''));
const CONN_HOSTS  = csv(process.env.CONNECTIVITY_DOMAINS);
const FREE_MACS   = new Set(csv(process.env.FREE_MACS).map(s => s.toLowerCase()));
const SPEED       = parseInt(process.env.SPEED) || 0;

/* --- Aprendizaje por DNS -------------------------------------------------
 * Generico: no sabe nada de ningun servicio concreto. Observa las respuestas
 * DNS que pasan por este servidor y, cuando el nombre consultado pertenece a
 * ALLOW_DOMAINS, mete las IPs devueltas en la allowlist al vuelo.
 *
 * SNOOP_WIDEN resuelve el problema de los CDN con balanceo geografico: una IP
 * suelta (/32) se queda obsoleta en cuanto el proveedor rota de PoP, pero
 * ensanchar a ciegas es peligroso si el destino es infraestructura compartida
 * (p.ej. AWS Global Accelerator, donde un /24 arrastra miles de servicios
 * ajenos). Con SNOOP_WIDEN declaras en que redes es seguro agrupar y a que
 * prefijo; fuera de ellas se usa /32.
 *   Formato: <red>/<mascara>:<prefijo_destino>,...
 *   Ejemplo: 57.144.0.0/14:24  -> dentro de 57.144.0.0/14, agrupa a /24
 */
const SNOOP            = (process.env.SNOOP || '1') !== '0' && ALLOW_DOMAINS.length > 0;
const SNOOP_MAX        = parseInt(process.env.SNOOP_MAX) || 256;
const SNOOP_REFRESH_MS = process.env.SNOOP_REFRESH_MS === undefined
  ? 1800000 : (parseInt(process.env.SNOOP_REFRESH_MS) || 0);
const SNOOP_CACHE      = process.env.SNOOP_CACHE === undefined
  ? '.snoop.json' : process.env.SNOOP_CACHE.trim();
const SNOOP_FORCE_DNS  = process.env.SNOOP_FORCE_DNS === '1';
const SNOOP_WIDEN      = csv(process.env.SNOOP_WIDEN).map(spec => {
  const m = spec.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+):(\d+)$/);
  if (!m) return null;
  const bits = parseInt(m[2]), to = parseInt(m[3]);
  if (bits < 0 || bits > 32 || to < 8 || to > 32 || to < bits) return null;
  return { base: ipToInt(m[1]) >>> 0, mask: bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0, to };
}).filter(Boolean);
const TERMUX_SH   = '/data/data/com.termux/files/usr/bin/bash';
const ADMIN_USERS = {};
(process.env.ADMIN_USERS || 'admin:1234').split(',').forEach(e => {
  const [u, ...rest] = e.split(':');
  if (u && rest.length) ADMIN_USERS[u.trim()] = rest.join(':').trim();
});

/* --- Superficie de administracion ---------------------------------------
 * ADMIN=0 apaga el panel entero: no se registra ninguna ruta /api/*, no se
 * sirve admin.html y no se abre el WebSocket. El portal sigue funcionando
 * (captura, login de clientes, filtrado); solo desaparece el control remoto,
 * que pasa a hacerse editando .env y reiniciando.
 *
 * ADMIN_SHELL=0 deja el panel de monitorizacion pero quita /ws/shell, que es
 * lo unico que ejecuta comandos arbitrarios en el telefono. Util cuando
 * quieres ver dispositivos y log sin exponer una shell.
 *
 * Por defecto ambos quedan en 1 para no cambiar el comportamiento de quien ya
 * usa el proyecto. En un despliegue publico lo recomendable es ADMIN_SHELL=0
 * como minimo, y ADMIN=0 si no necesitas el panel. */
const ADMIN       = (process.env.ADMIN || '1') !== '0';
const ADMIN_SHELL = ADMIN && (process.env.ADMIN_SHELL || '1') !== '0';

let ALLOW_RANGES = [...STATIC_RANGES];
const DNS_RESOLVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

/* Declaradas con "function" a proposito: se hoistean y SNOOP_WIDEN las usa
 * durante la inicializacion de los const de arriba. */
function ipToInt(ip) {
  const o = ip.split('.');
  if (o.length !== 4) return 0;
  return (((+o[0] << 24) | (+o[1] << 16) | (+o[2] << 8) | +o[3]) >>> 0);
}

/* Solo se aprenden direcciones unicast publicas. Sin este filtro, un dominio
 * de ALLOW_DOMAINS cuyo DNS devuelva una IP privada (ataque de tipo DNS
 * rebinding, o simplemente un registro mal puesto) abriria la red local a
 * todos los clientes del portal. Tambien descarta 0.0.0.0, que algunos
 * proveedores devuelven como "no aplica". */
function isPublicUnicast(ip) {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = o;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a >= 224) return false;
  return true;
}

/* Convierte una IP aprendida en el CIDR que se insertara en la allowlist,
 * aplicando las reglas de SNOOP_WIDEN. Por defecto /32. */
function toCidr(ip) {
  const n = ipToInt(ip);
  for (const w of SNOOP_WIDEN) {
    if ((n & w.mask) >>> 0 === w.base) {
      const m = w.to === 0 ? 0 : (0xFFFFFFFF << (32 - w.to)) >>> 0;
      const net = (n & m) >>> 0;
      return `${net >>> 24}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}/${w.to}`;
    }
  }
  return `${ip}/32`;
}

/* Extrae los registros A de una respuesta DNS. Resuelve punteros de
 * compresion al saltar nombres, que es lo que rompe los parsers ingenuos. */
function parseDnsAnswers(buf) {
  const out = [];
  try {
    const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
    if (an === 0) return out;
    let off = 12;
    const skipName = () => {
      while (off < buf.length) {
        const len = buf[off];
        if (len === 0) { off++; return; }
        if ((len & 0xC0) === 0xC0) { off += 2; return; }   // puntero: ocupa 2 bytes
        off += len + 1;
      }
    };
    for (let i = 0; i < qd; i++) { skipName(); off += 4; }
    for (let i = 0; i < an && off + 10 <= buf.length; i++) {
      skipName();
      const type = buf.readUInt16BE(off), cls = buf.readUInt16BE(off + 2);
      const rdlen = buf.readUInt16BE(off + 8);
      off += 10;
      if (type === 1 && cls === 1 && rdlen === 4 && off + 4 <= buf.length) {
        out.push(`${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`);
      }
      off += rdlen;
    }
  } catch (_) {}
  return out;
}

const learned = new Map();   // cidr -> { ts, src }

function saveSnoopCache() {
  if (!SNOOP_CACHE) return;
  try {
    fs.writeFileSync(path.join(__dirname, SNOOP_CACHE),
      JSON.stringify([...learned.entries()].map(([cidr, v]) => ({ cidr, ...v }))));
  } catch (_) {}
}

function loadSnoopCache() {
  if (!SNOOP_CACHE) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(__dirname, SNOOP_CACHE), 'utf8'));
    return Array.isArray(raw) ? raw.filter(e => e && typeof e.cidr === 'string') : [];
  } catch (_) { return []; }
}

/* Anade un CIDR aprendido a la allowlist en caliente. "-I" lo inserta al
 * principio de PORTAL_WA, por delante del "-j DROP" final, asi que empieza a
 * aplicar al instante sin reconstruir la cadena. */
async function learnCidr(cidr, src, opts = {}) {
  if (learned.has(cidr) || ALLOW_RANGES.includes(cidr)) return false;
  if (learned.size >= SNOOP_MAX) {
    L.warn(`SNOOP tope ${SNOOP_MAX} alcanzado, ignorando ${cidr}`);
    return false;
  }
  learned.set(cidr, { ts: Date.now(), src });
  ALLOW_RANGES.push(cidr);
  if (!opts.deferIpt) await ipt(`-I PORTAL_WA -d ${cidr} -j ACCEPT`);
  if (!opts.quiet) L.ok(`SNOOP +${cidr} (${src})`);
  saveSnoopCache();
  return true;
}

/* Consulta TODOS los resolvers y une los resultados. Uno solo devuelve el PoP
 * mas cercano a ese resolver, no el conjunto: preguntando a varios se
 * descubren los demas prefijos del mismo servicio. */
async function resolve4All(host) {
  const out = new Set();
  await Promise.all(DNS_RESOLVERS.map(srv => new Promise(res => {
    let done = false;
    const fin = () => { if (!done) { done = true; res(); } };
    const t = setTimeout(fin, 5000);
    try {
      const r = new dnsMod.Resolver();
      r.setServers([srv]);
      r.resolve4(host, (e, a) => {
        clearTimeout(t);
        if (!e && Array.isArray(a)) a.forEach(ip => out.add(ip));
        fin();
      });
    } catch (_) { clearTimeout(t); fin(); }
  })));
  return [...out];
}

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
const MAC_MISS_TTL = 2500;

const IP_RE  = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
function isValidIp(ip) { return typeof ip === 'string' && IP_RE.test(ip) && ip.split('.').every(o => Number(o) <= 255); }
function isValidMac(mac) { return typeof mac === 'string' && MAC_RE.test(mac); }

function getMac(ip) {
  if (!isValidIp(ip)) return null;
  const hit = macCache.get(ip);
  if (hit && Date.now() - hit.ts < (hit.mac ? MAC_TTL : MAC_MISS_TTL)) return hit.mac;
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
  macCache.set(ip, { mac, ts: Date.now() });
  return mac;
}

function getMacCached(ip) {
  const hit = macCache.get(ip);
  return (hit && hit.mac && Date.now() - hit.ts < MAC_TTL) ? hit.mac : null;
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

const markFree = [];
let markCtr = 1;
const markMap = new Map();
const MARK_MAX = 60;

function allocMark() { return markFree.length ? markFree.pop() : markCtr++; }
function freeMark(m) { markFree.push(m); }
function tcCmd(s) { run(`su -c "tc ${s}"`); }

async function initTc() {
  // Las marcas -t mangle -A FORWARD -d <ip> -j MARK son por IP, no viven en
  // una cadena propia, y sobreviven a un reinicio del proceso aunque el
  // Map markMap en memoria se resetee: se limpian aqui para no acumular
  // marcas huerfanas de sesiones de reinicios anteriores.
  await ipt(`-t mangle -F FORWARD`);
  if (!SPEED) return;
  tcCmd(`qdisc del dev ${IFACE_IN} root 2>/dev/null`);
  tcCmd(`qdisc add dev ${IFACE_IN} root handle 1: htb default 999`);
  tcCmd(`class add dev ${IFACE_IN} parent 1: classid 1:999 htb rate 1000mbit`);
  L.info(`TC SPEED=${SPEED}kb/s on ${IFACE_IN}`);
}

async function tcFree(mac, e) {
  markMap.delete(mac);
  freeMark(e.m);
  await ipt(`-t mangle -D FORWARD -d ${e.ip} -j MARK --set-mark ${e.m}`);
  tcCmd(`filter del dev ${IFACE_IN} parent 1: protocol ip handle ${e.m} fw`);
  tcCmd(`class del dev ${IFACE_IN} parent 1: classid 1:${e.m}`);
}

async function tcAuth(mac, ip) {
  if (!SPEED || FREE_MACS.has(mac) || markMap.has(mac)) return;
  for (const [oldMac, e] of markMap) {
    if (e.ip === ip) { await tcFree(oldMac, e); L.warn(`TC stale mac=${oldMac} ip=${ip}`); }
  }
  if (markMap.size >= MARK_MAX) {
    const [oldestMac, oldestE] = markMap.entries().next().value;
    await tcFree(oldestMac, oldestE);
    L.warn(`TC cap alcanzado, liberando mac=${oldestMac}`);
  }
  const m = allocMark();
  markMap.set(mac, { m, ip });
  tcCmd(`class add dev ${IFACE_IN} parent 1: classid 1:${m} htb rate ${SPEED}kbit burst ${Math.max(SPEED, 32)}k`);
  tcCmd(`filter add dev ${IFACE_IN} parent 1: protocol ip handle ${m} fw flowid 1:${m}`);
  await ipt(`-t mangle -A FORWARD -d ${ip} -j MARK --set-mark ${m}`);
}

async function tcDeauth(mac) {
  if (!SPEED) return;
  const e = markMap.get(mac);
  if (!e) return;
  await tcFree(mac, e);
}

/* Resuelve ALLOW_DOMAINS y SUMA lo encontrado a los rangos estaticos.
 * La version anterior pisaba ALLOW_RANGES con /32 sueltos, asi que perdia la
 * lista fija y se quedaba obsoleta en cuanto el proveedor rotaba de PoP.
 * opts.deferIpt = true durante el arranque, porque PORTAL_WA aun no existe:
 * initRules() volcara ALLOW_RANGES completo al crear la cadena. */
async function resolveAllowDomains(opts = {}) {
  if (!ALLOW_DOMAINS.length) return 0;
  let added = 0;
  for (const d of ALLOW_DOMAINS) {
    const addrs = await resolve4All(d);
    if (!addrs.length) { L.warn(`DOMAIN sin respuesta: ${d}`); continue; }
    const ok = addrs.filter(isPublicUnicast);
    for (const ip of ok) if (await learnCidr(toCidr(ip), `boot:${d}`, opts)) added++;
    L.ok(`DOMAIN ${d} -> ${ok.join(', ') || '(ninguna publica)'}`);
  }
  return added;
}

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
  // Cadena dedicada para las reglas por-MAC en FORWARD. Antes esas reglas se
  // insertaban directo en FORWARD y, como el proceso se reinicia seguido
  // (Termux muere por Android, cortes de luz, etc.) pero iptables es estado
  // del kernel que sobrevive al reinicio, cada reinicio dejaba huerfanas las
  // reglas ACCEPT/PORTAL_WA de dispositivos ya desconectados: se iban
  // acumulando para siempre y algunos MACs viejos quedaban con acceso total
  // permanente sin que devices/authed (en memoria) supieran que existian.
  // Con una cadena propia, basta un -F al arrancar para partir de cero.
  run(`su -c "iptables -N PORTAL_FWD 2>/dev/null"`);
  await ipt(`-F PORTAL_FWD`);
  run(`su -c "iptables -D FORWARD -i ${IFACE_IN} -j PORTAL_FWD 2>/dev/null"`);
  await ipt(`-I FORWARD -i ${IFACE_IN} -j PORTAL_FWD`);
  for (const r of ALLOW_RANGES) await ipt(`-A PORTAL_WA -d ${r} -j ACCEPT`);
  // OJO: antes habia un "-m state --state RELATED,ESTABLISHED -j ACCEPT" aqui.
  // Eso es innecesario para trafico WA legitimo (las reglas -d de arriba ya
  // aceptan cada paquete, sea NEW o ESTABLISHED, mientras el destino este en
  // ALLOW_RANGES) y ademas era un hueco: cualquier conexion larga abierta
  // durante la ventana OPEN_MS (7s libres) hacia CUALQUIER destino quedaba
  // "ESTABLISHED" y seguia aceptandose para siempre tras la restriccion,
  // sin importar a donde apuntara. Se quita para que PORTAL_WA solo deje
  // pasar trafico realmente destinado a los rangos permitidos.
  await ipt(`-A PORTAL_WA -j DROP`);
  run(`su -c "iptables -D INPUT -i ${IFACE_IN} -p tcp --dport ${PORT} -j ACCEPT 2>/dev/null"`);
  await ipt(`-I INPUT -i ${IFACE_IN} -p tcp --dport ${PORT} -j ACCEPT`);
  for (const mac of FREE_MACS) {
    run(`su -c "iptables -D PORTAL_FWD -m mac --mac-source ${mac} -j ACCEPT 2>/dev/null"`);
    await ipt(`-I PORTAL_FWD -m mac --mac-source ${mac} -j ACCEPT`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p udp --dport 53 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 443 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 80 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -d ${GW} -p tcp --dport 80 -j REDIRECT --to-port ${PORT}`);
    L.ok(`FREE_MAC pre-auth: ${mac}`);
  }
}

async function restrictMac(mac) {
  await ipt(`-D PORTAL_FWD -m mac --mac-source ${mac} -j ACCEPT`);
  if (!FREE_MACS.has(mac)) await ipt(`-I PORTAL_FWD -m mac --mac-source ${mac} -j PORTAL_WA`);
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
    /* Con SNOOP_FORCE_DNS=1 NO se exime el 53: el DNS del dispositivo sigue
     * pasando por este servidor, que es lo que permite aprender las IPs de
     * ALLOW_DOMAINS del trafico real. Por defecto (0) se mantiene el
     * comportamiento original: tras autenticar, el DNS va directo al resolver. */
    if (!SNOOP_FORCE_DNS)
      await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p udp --dport 53 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 80 -j RETURN`);
    await ipt(`-t nat -I PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 443 -j RETURN`);
    await ipt(`-I PORTAL_FWD -m mac --mac-source ${mac} -j ACCEPT`);
    await tcAuth(mac, ip);
    setTimeout(() => restrictMac(mac), OPEN_MS);
  }
  pushLog(mac, ip, 'auth', null);
  L.ok(`AUTH ${mac} ${ip}`);
}

async function deauthMac(mac) {
  authed.delete(mac);
  await tcDeauth(mac);
  if (!SNOOP_FORCE_DNS)
    await ipt(`-t nat -D PORTAL_PRE -m mac --mac-source ${mac} -p udp --dport 53 -j RETURN`);
  await ipt(`-t nat -D PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 80 -j RETURN`);
  await ipt(`-t nat -D PORTAL_PRE -m mac --mac-source ${mac} -p tcp --dport 443 -j RETURN`);
  await ipt(`-D PORTAL_FWD -m mac --mac-source ${mac} -j ACCEPT`);
  await ipt(`-D PORTAL_FWD -m mac --mac-source ${mac} -j PORTAL_WA`);
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

function isAllowedDomain(name) {
  return ALLOW_DOMAINS.some(d => name === d || name.endsWith('.' + d));
}

/* Nucleo del aprendizaje: lee las IPs de una respuesta DNS ya validada como
 * perteneciente a ALLOW_DOMAINS y las mete en la allowlist. Se lanza sin await
 * para no frenar la respuesta al cliente; la cola ipt() serializa el resto. */
function snoopResponse(buf, qname) {
  for (const ip of parseDnsAnswers(buf)) {
    if (!isPublicUnicast(ip)) continue;
    learnCidr(toCidr(ip), `snoop:${qname}`).catch(() => {});
  }
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

function forwardDns(msg, rinfo, idx = 0, qname = '') {
  if (idx >= DNS_RESOLVERS.length) return;
  if (fwdActive >= FWD_MAX) return;
  fwdActive++;
  const sock = dgram.createSocket('udp4');
  let closed = false;
  const done = (ok) => {
    if (closed) return;
    closed = true;
    fwdActive--;
    try { sock.close(); } catch (_) {}
    if (!ok) forwardDns(msg, rinfo, idx + 1, qname);
  };
  sock.on('message', r => {
    dnsServer.send(r, rinfo.port, rinfo.address);
    if (SNOOP && qname && isAllowedDomain(qname)) snoopResponse(r, qname);
    done(true);
  });
  sock.on('error', () => done(false));
  sock.send(msg, 53, DNS_RESOLVERS[idx]);
  setTimeout(() => done(false), 5000);
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
  if (isConnHost(name) || isAllowedDomain(name)) forwardDns(msg, rinfo, 0, name);
  else {
    const reply = dnsReply(msg, GW);
    if (reply) dnsServer.send(reply, rinfo.port, rinfo.address);
  }
});

const CLEAN_CONCURRENCY = 5;

setInterval(async () => {
  const macs = [...devices.keys()].filter(m => !FREE_MACS.has(m));
  for (let i = 0; i < macs.length; i += CLEAN_CONCURRENCY) {
    await Promise.all(macs.slice(i, i + CLEAN_CONCURRENCY).map(deauthMac));
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
  // No hay reverse proxy delante de este portal: el cliente en el hotspot
  // habla directo con este proceso, asi que X-Forwarded-For es un header
  // que el propio cliente puede falsificar libremente. Confiar en el
  // permitia inyectar comandos via getMac() -> `su -c "ip neigh show <ip>"`.
  // Se usa unicamente la IP real del socket.
  return (req.socket.remoteAddress || '').replace('::ffff:', '');
}

function adminAuth(req, res, next) {
  const token = getToken(req);
  if (token && sessions.has(token)) return next();
  res.status(401).json({ err: 'Unauthorized' });
}

// Freno simple de fuerza bruta por IP: sin esto, cualquiera en el hotspot
// podia probar contraseñas para ADMIN_USERS sin limite, y ese login abre
// paso al shell remoto (/ws/shell). 5 intentos fallidos = 60s de bloqueo,
// doblando el bloqueo en cada racha de fallos subsiguiente.
const loginAttempts = new Map();
function loginBlocked(ip) {
  const a = loginAttempts.get(ip);
  return a && a.fails >= 5 && Date.now() < a.until;
}
function loginFail(ip) {
  const a = loginAttempts.get(ip) || { fails: 0, until: 0 };
  a.fails++;
  if (a.fails >= 5) a.until = Date.now() + Math.min(30 * 60000, 60000 * Math.pow(2, a.fails - 5));
  loginAttempts.set(ip, a);
}
function loginOk(ip) { loginAttempts.delete(ip); }

/* Con ADMIN=0 el panel no existe: este guard atrapa cualquier /api/* antes de
 * que llegue a su handler y responde 404, asi no se filtra ni que la ruta
 * existe. Se usa app.use con test manual y no un patron de ruta porque este
 * proyecto va con Express 5, donde los comodines tipo '/api/*' cambiaron de
 * sintaxis. "/auth" (el login de los CLIENTES del portal) no empieza por
 * /api, asi que no se ve afectado. */
if (!ADMIN) {
  app.use((req, res, next) => /^\/api(\/|$)/.test(req.path) ? res.status(404).end() : next());
}

app.post('/api/login', async (req, res) => {
  const ip = getIP(req);
  if (loginBlocked(ip)) {
    L.warn(`LOGIN blocked (bruteforce) ip=${ip}`);
    return res.status(429).json({ err: 'Demasiados intentos, espera' });
  }
  const mac = getMac(ip);
  if (!mac || !FREE_MACS.has(mac)) {
    loginFail(ip);
    L.warn(`LOGIN deny mac=${mac || '?'} ip=${ip}`);
    return res.status(403).json({ err: 'Forbidden' });
  }
  const { user, pass } = req.body || {};
  if (ADMIN_USERS[user] && ADMIN_USERS[user] === pass) {
    loginOk(ip);
    const token = crypto.randomBytes(16).toString('hex');
    sessions.set(token, user);
    res.setHeader('Set-Cookie', `at=${token};Path=/;HttpOnly`);
    await authMac(mac, ip);
    L.ok(`LOGIN ok user=${user} ip=${ip} mac=${mac}`);
    res.json({ ok: true, token, user, free: FREE_MACS.has(mac) });
  } else {
    loginFail(ip);
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
  const mac = (req.params.mac || '').toLowerCase();
  if (!isValidMac(mac)) return res.status(400).json({ err: 'MAC invalida' });
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
  // Los valores de .env se cargan una sola vez al arrancar (const's arriba),
  // guardar aqui NO los aplica en caliente. Se avisa explicitamente para
  // no dar la falsa impresion de que el cambio ya esta activo.
  res.json({ ok: true, note: 'Guardado. Reinicia el proceso (POST /api/stop) para aplicar los cambios.' });
});

app.post('/api/stop', adminAuth, (req, res) => {
  L.warn(`STOP requested by ${sessions.get(getToken(req))}`);
  res.json({ ok: true });
  setTimeout(() => process.exit(0), 300);
});

/* Con ADMIN_SHELL=0 el WebSocket no se crea siquiera: el endpoint /ws/shell no
 * existe y no hay forma de llegar al spawn(). Es la unica parte del panel que
 * ejecuta comandos arbitrarios en el telefono. */
const wss = ADMIN_SHELL ? new WebSocketServer({ server, path: '/ws/shell' }) : null;
wss?.on('connection', (ws, req) => {
  const ip = getIP(req);
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
    const proc = spawn(TERMUX_SH, ['-c', cmd], {
      env: {
        PATH: `/data/data/com.termux/files/usr/bin:${process.env.PATH || '/system/bin:/system/xbin'}`,
        HOME: '/data/data/com.termux/files/home',
        PREFIX: '/data/data/com.termux/files/usr',
        TMPDIR: '/data/data/com.termux/files/usr/tmp',
      }
    });
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

const BLOCKED = /^\/(\.env(\.|$)|server\.js|package(-lock)?\.json|\.git(\/|$)|x\.sh|\.npmrc|node_modules(\/|$)|\.snoop\.json$|\.gitattributes$)/i;
/* admin.html lo sirve express.static, asi que sin esto seguiria descargandose
 * con ADMIN=0 (solo la UI, las /api ya dan 404, pero no hay motivo para
 * entregarla ni para anunciar que el panel existe). */
const BLOCKED_ADMIN = /^\/admin\.html$/i;
app.use((req, res, next) =>
  (BLOCKED.test(req.path) || (!ADMIN && BLOCKED_ADMIN.test(req.path)))
    ? res.status(404).end() : next());
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
  /* Lo aprendido en arranques anteriores se recupera ANTES de construir
   * PORTAL_WA, asi el portal ya nace con la allowlist completa en vez de tener
   * que reaprenderla con la primera consulta de cada cliente. */
  for (const e of loadSnoopCache())
    await learnCidr(e.cidr, e.src || 'cache', { deferIpt: true, quiet: true });
  await resolveAllowDomains({ deferIpt: true });
  await initRules();
  await initTc();
  if (SNOOP && SNOOP_REFRESH_MS > 0)
    setInterval(() => resolveAllowDomains().catch(() => {}), SNOOP_REFRESH_MS);
  L.info(`Allowlist: ${ALLOW_RANGES.length} CIDR (${STATIC_RANGES.length} fijos, ${learned.size} aprendidos)` +
         ` | SNOOP=${SNOOP ? 'on' : 'off'}${SNOOP_FORCE_DNS ? ' force-dns' : ''}` +
         ` | widen=${SNOOP_WIDEN.length}`);
  if (!ALLOW_RANGES.length) L.warn('Allowlist VACIA: nadie podra salir. Revisa ALLOW_RANGES / ALLOW_DOMAINS.');
  L.info(`Panel: ADMIN=${ADMIN ? 'on' : 'OFF'} shell=${ADMIN_SHELL ? 'on' : 'OFF'}`);
  if (ADMIN && !process.env.ADMIN_USERS)
    L.warn('ADMIN_USERS sin definir: se esta usando el default admin:1234. Cambialo o pon ADMIN=0.');
  if (ADMIN_SHELL)
    L.warn('/ws/shell activo: ejecuta comandos en el telefono. Pon ADMIN_SHELL=0 si no lo necesitas.');
  dnsServer.bind(DNS_PORT, '0.0.0.0', () => L.info(`DNS :${DNS_PORT}`));
  server.listen(PORT, '0.0.0.0', () => L.ok(`Portal :${PORT}`));
})();
