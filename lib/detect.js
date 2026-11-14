'use strict';

const { sh, suScript } = require('./sh');
const { isValidIp, isValidIface, ipToInt, maskOf, intToIp } = require('./config');

/* "30: wlan0    inet 192.168.100.76/24 brd ... scope global wlan0\ ..." */
function parseIpAddr(text) {
  const out = [];
  for (const line of String(text).split('\n')) {
    const m = line.match(/^\s*\d+:\s*([^\s:]+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/);
    if (!m) continue;
    const [, name, ip, bits] = m;
    if (!isValidIface(name) || !isValidIp(ip)) continue;
    out.push({ name, ip, prefix: Number(bits) });
  }
  return out;
}

/* En Android las default routes viven en tablas por red (1010 rmnet, 1030
 * wlan...), asi que la tabla main suele no tener ninguna: "ip route get" es lo
 * unico que resuelve aplicando las ip rules. */
function parseRouteGet(text) {
  const line = String(text).split('\n')[0] || '';
  const dev = line.match(/\bdev\s+([^\s]+)/);
  const via = line.match(/\bvia\s+(\d+\.\d+\.\d+\.\d+)/);
  const src = line.match(/\bsrc\s+(\d+\.\d+\.\d+\.\d+)/);
  if (!dev || !isValidIface(dev[1])) return null;
  return {
    iface: dev[1],
    via: via && isValidIp(via[1]) ? via[1] : null,
    src: src && isValidIp(src[1]) ? src[1] : null,
  };
}

/*  Tether state:
 *    wlan0 - AvailableState - lastError = 0
 *    wlan1 - TetheredState - lastError = 0
 *    Current upstream interface(s): [wlan0]
 */
function parseTethering(text) {
  const downstreams = [];
  let upstream = null;
  const regexs = [];
  for (const line of String(text).split('\n')) {
    const t = line.match(/^\s*([^\s]+)\s+-\s+TetheredState\b/);
    if (t && isValidIface(t[1])) downstreams.push(t[1]);

    const u = line.match(/Current upstream(?: interface\(s\))?:\s*\[?([^\]\s,]+)/);
    if (u && isValidIface(u[1]) && u[1] !== 'null') upstream = u[1];

    const r = line.match(/tetherable\w*Regexs:\s*\[([^\]]*)\]/);
    if (r) for (const p of r[1].split(',').map(s => s.trim()).filter(Boolean)) regexs.push(p);
  }
  return { downstreams, upstream, regexs };
}

function regexsToMatcher(patterns) {
  const compiled = [];
  for (const p of patterns) {
    try { compiled.push(new RegExp(`^${p}$`)); } catch (_) {}
  }
  if (!compiled.length) return () => false;
  return name => compiled.some(re => re.test(name));
}

const DEFAULT_AP_PATTERNS = ['softap\\d', 'ap\\d', 'wlan\\d', 'swlan\\d', 'rndis\\d', 'usb\\d', 'bt-pan', 'bnep\\d', 'eth\\d'];

function isPrivate(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function networkOf(ip, prefix) {
  const m = maskOf(prefix);
  return `${intToIp((ipToInt(ip) & m) >>> 0)}/${prefix}`;
}

async function readState({ useRoot = true } = {}) {
  const [addrR, routeR] = await Promise.all([
    sh('ip -o -4 addr', { timeout: 6000 }),
    sh('ip route get 1.1.1.1', { timeout: 6000 }),
  ]);

  let tether = { downstreams: [], upstream: null, regexs: [] };
  if (useRoot) {
    const t = await suScript('dumpsys tethering', { timeout: 15000 });
    if (t.code === 0 && t.out) tether = parseTethering(t.out);
  }

  return {
    addrs: parseIpAddr(addrR.out),
    route: parseRouteGet(routeR.out),
    tether,
  };
}

function classifyUpstream(name) {
  if (!name) return 'desconocido';
  if (/^(rmnet|ccmni|pdp|clat)/.test(name)) return 'datos moviles';
  if (/^wlan/.test(name)) return 'wifi';
  if (/^(eth|usb|rndis)/.test(name)) return 'cable';
  return name;
}

/* Elige la interfaz del hotspot. Prioridad: lo que declara el servicio de
 * tethering de Android; si no esta disponible, la unica interfaz UP con IPv4
 * privada que no sea la de salida. */
function choose(state, { iface = '', gw = '' } = {}) {
  const notes = [];
  const byName = new Map(state.addrs.map(a => [a.name, a]));
  const upIface = state.tether.upstream || (state.route && state.route.iface) || '';

  let picked = '';
  let source = '';

  if (iface) {
    picked = iface;
    source = 'IFACE_IN';
    if (!byName.has(iface)) notes.push(`IFACE_IN=${iface} no tiene IPv4; el hotspot puede estar apagado`);
  } else {
    const tethered = state.tether.downstreams.filter(n => n !== upIface && byName.has(n));
    if (tethered.length) {
      picked = tethered[0];
      source = 'dumpsys tethering';
      if (tethered.length > 1) notes.push(`varias interfaces compartiendo (${tethered.join(', ')}), se usa ${picked}`);
    } else {
      const match = regexsToMatcher(state.tether.regexs.length ? state.tether.regexs : DEFAULT_AP_PATTERNS);
      const cands = state.addrs.filter(a =>
        a.name !== 'lo' && a.name !== upIface && isPrivate(a.ip) && match(a.name));
      if (cands.length === 1) {
        picked = cands[0].name;
        source = 'descarte';
      } else if (cands.length > 1) {
        picked = cands[0].name;
        source = 'descarte';
        notes.push(`varias candidatas (${cands.map(c => c.name).join(', ')}), se usa ${picked}`);
      }
    }
  }

  const addr = byName.get(picked);
  const resolvedGw = gw || (addr ? addr.ip : '');

  return {
    iface: picked,
    gw: resolvedGw,
    gwSource: gw ? 'GW' : (addr ? 'ip addr' : ''),
    prefix: addr ? addr.prefix : 24,
    network: addr ? networkOf(addr.ip, addr.prefix) : '',
    upIface,
    upKind: classifyUpstream(upIface),
    upGw: state.route ? state.route.via : null,
    source,
    notes,
    ok: Boolean(picked && resolvedGw),
  };
}

async function detect(opts = {}) {
  const state = await readState(opts);
  return choose(state, opts);
}

module.exports = {
  detect, readState, choose,
  parseIpAddr, parseRouteGet, parseTethering,
  classifyUpstream, regexsToMatcher, networkOf, isPrivate,
};
