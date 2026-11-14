'use strict';

/* Fixtures tomadas de un Redmi ginkgo con MIUI / Android 13, hotspot activo.
 * node tests/run.js */

const assert = require('assert');
const cfg = require('../lib/config');
const det = require('../lib/detect');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log(`  ok   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
}
function group(name) { console.log(`\n${name}`); }

/* ------------------------------------------------------------------ env --- */

group('.env: comentarios en linea y comillas');

t('quita el comentario en linea (caso real del .env del telefono)', () => {
  const e = cfg.parseEnv('OPEN_MS=7000 # Permite 7 Segundos de conexion abierta.');
  assert.strictEqual(e.OPEN_MS, '7000');
});

t('quita el comentario con comillas dentro (caso del .env.example)', () => {
  const e = cfg.parseEnv('IFACE_IN=wlan2            # interfaz del hotspot ("ip addr" para verla)');
  assert.strictEqual(e.IFACE_IN, 'wlan2');
});

t('un valor entre comillas conserva el #', () => {
  const e = cfg.parseEnv('ADMIN_USERS="admin:cla#ve con espacio"');
  assert.strictEqual(e.ADMIN_USERS, 'admin:cla#ve con espacio');
});

t('# sin espacio delante no corta (es parte del valor)', () => {
  const e = cfg.parseEnv('ADMIN_USERS=admin:abc#def');
  assert.strictEqual(e.ADMIN_USERS, 'admin:abc#def');
});

t('quita el CR de un .env editado en Windows', () => {
  const e = cfg.parseEnv('IFACE_IN=wlan1\r\nPORT=8080\r');
  assert.strictEqual(e.IFACE_IN, 'wlan1');
  assert.strictEqual(e.PORT, '8080');
});

t('ignora lineas comentadas', () => {
  const e = cfg.parseEnv('# GW=192.168.43.1\n#YESDOM=whatsapp.com\nPORT=1');
  assert.deepStrictEqual(Object.keys(e), ['PORT']);
});

group('.env: anadir claves nuevas al actualizar');

t('una clave comentada NO se vuelve a anadir', () => {
  const have = cfg.mentionedKeys([
    'ADMIN_USERS=x',
    '#SPEED=500',
    '#   OPEN_MS=0',
    '# ALLOW_DOMAINS=telegram.org',
  ].join('\n'));
  for (const k of ['ADMIN_USERS', 'SPEED', 'OPEN_MS', 'ALLOW_DOMAINS']) assert.ok(have.has(k), k);
});

t('la prosa de los comentarios no cuenta como clave', () => {
  const have = cfg.mentionedKeys([
    '#   Formato: red/mascara:prefijo',
    '# Por que existe: un CDN rota de PoP',
  ].join('\n'));
  assert.strictEqual(have.size, 0, [...have].join(','));
});

t('una clave que no aparece de ninguna forma si se detecta como nueva', () => {
  assert.strictEqual(cfg.mentionedKeys('PORT=8080').has('BLOCK_IPV6'), false);
});

group('.env: numeros y booleanos');

t('OPEN_MS=0 vale 0 y no cae al default', () => {
  assert.strictEqual(cfg.num('0', 7000), 0);
});

t('vacio cae al default', () => {
  assert.strictEqual(cfg.num('', 7000), 7000);
  assert.strictEqual(cfg.num(undefined, 7000), 7000);
});

t('basura cae al default', () => {
  assert.strictEqual(cfg.num('abc', 7000), 7000);
});

t('ADMIN_SHELL por defecto apagado', () => {
  const c = cfg.buildConfig({});
  assert.strictEqual(c.adminShell, false);
});

t('ADMIN_SHELL=1 lo enciende, ADMIN=0 lo fuerza apagado', () => {
  assert.strictEqual(cfg.buildConfig({ ADMIN_SHELL: '1' }).adminShell, true);
  assert.strictEqual(cfg.buildConfig({ ADMIN: '0', ADMIN_SHELL: '1' }).adminShell, false);
});

group('.env: validacion de valores que llegan a un shell');

t('IFACE_IN con comando inyectado es fatal', () => {
  const c = cfg.buildConfig({ IFACE_IN: 'wlan1"; reboot; echo "' });
  assert.ok(c.fatal.length > 0, 'deberia marcar fatal');
  assert.ok(/IFACE_IN/.test(c.fatal[0]));
});

t('IFACE_IN con el comentario sin limpiar es fatal', () => {
  const c = cfg.buildConfig({ IFACE_IN: 'wlan2 # interfaz del hotspot' });
  assert.ok(c.fatal.length > 0);
});

t('GW invalido es fatal', () => {
  assert.ok(cfg.buildConfig({ GW: '999.1.1.1' }).fatal.length > 0);
});

t('MAC invalida se descarta con aviso', () => {
  const c = cfg.buildConfig({ FREE_MACS: '00:08:22:6c:de:fb,no-es-una-mac' });
  assert.strictEqual(c.freeMacs.size, 1);
  assert.ok(c.warn.some(w => /FREE_MACS/.test(w)));
});

t('CIDR invalido se descarta', () => {
  const c = cfg.buildConfig({ ALLOW_RANGES: '1.2.3.0/24,1.2.3.4/99,nope' });
  assert.deepStrictEqual(c.staticRanges, ['1.2.3.0/24']);
});

t('una IP suelta en ALLOW_RANGES se normaliza a /32', () => {
  assert.deepStrictEqual(cfg.buildConfig({ ALLOW_RANGES: '3.33.221.48' }).staticRanges, ['3.33.221.48/32']);
});

t('WA_RANGES y YESDOM siguen funcionando', () => {
  const c = cfg.buildConfig({ WA_RANGES: '157.240.0.0/16', YESDOM: 'whatsapp.net' });
  assert.deepStrictEqual(c.staticRanges, ['157.240.0.0/16']);
  assert.deepStrictEqual(c.allowDomains, ['whatsapp.net']);
});

group('allowlist: rangos y widen');

t('no se aprenden IPs privadas ni reservadas', () => {
  for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '224.0.0.1', '0.0.0.0'])
    assert.strictEqual(cfg.isPublicUnicast(ip), false, ip);
  for (const ip of ['157.240.1.1', '3.33.221.48', '8.8.8.8'])
    assert.strictEqual(cfg.isPublicUnicast(ip), true, ip);
});

t('SNOOP_WIDEN 57.144.0.0/14:24 agrupa a /24 dentro del rango', () => {
  const w = cfg.parseWiden('57.144.0.0/14:24');
  assert.ok(w);
  assert.strictEqual(w.to, 24);
  assert.strictEqual(w.base, cfg.ipToInt('57.144.0.0'));
});

t('SNOOP_WIDEN rechaza un prefijo destino mas ancho que la red', () => {
  assert.strictEqual(cfg.parseWiden('57.144.0.0/24:14'), null);
});

/* --------------------------------------------------------------- detect --- */

const IP_ADDR_HOTSPOT_ON = [
  '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever',
  '30: wlan0    inet 192.168.100.76/24 brd 192.168.100.255 scope global wlan0\\       valid_lft forever preferred_lft forever',
  '32: wlan1    inet 192.168.174.95/24 brd 192.168.174.255 scope global wlan1\\       valid_lft forever preferred_lft forever',
].join('\n');

const IP_ADDR_HOTSPOT_OFF = [
  '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever',
  '30: wlan0    inet 192.168.100.76/24 brd 192.168.100.255 scope global wlan0\\       valid_lft forever preferred_lft forever',
].join('\n');

const ROUTE_GET = '1.1.1.1 via 192.168.100.1 dev wlan0 table 1030 src 192.168.100.76 uid 10169 \n    cache ';
const ROUTE_GET_MOBILE = '1.1.1.1 via 10.113.44.1 dev rmnet_data0 table 1010 src 10.113.44.72 uid 10169 \n    cache ';

const DUMPSYS_ON = `Tethering:
  Callbacks registered: 8
  Configuration:
    tetherableUsbRegexs: [usb\\d, rndis\\d]
    tetherableWifiRegexs: [softap0, wlan\\d]
    tetherableBluetoothRegexs: [bnep\\d, bt-pan]
  Tether state:
    wlan0 - AvailableState - lastError = 0
    wlan1 - TetheredState - lastError = 0
    Upstream wanted: true
    Current upstream interface(s): [wlan0]
  Hardware offload:
    Current upstream: wlan0`;

const DUMPSYS_OFF = `Tethering:
  Configuration:
    tetherableWifiRegexs: [softap0, wlan\\d]
  Tether state:
    Upstream wanted: false`;

group('deteccion: parsers contra salida real del telefono');

t('ip -o -4 addr', () => {
  assert.deepStrictEqual(det.parseIpAddr(IP_ADDR_HOTSPOT_ON), [
    { name: 'lo', ip: '127.0.0.1', prefix: 8 },
    { name: 'wlan0', ip: '192.168.100.76', prefix: 24 },
    { name: 'wlan1', ip: '192.168.174.95', prefix: 24 },
  ]);
});

t('ip route get da la interfaz de salida (wifi)', () => {
  assert.deepStrictEqual(det.parseRouteGet(ROUTE_GET),
    { iface: 'wlan0', via: '192.168.100.1', src: '192.168.100.76' });
});

t('ip route get da la interfaz de salida (datos moviles)', () => {
  const r = det.parseRouteGet(ROUTE_GET_MOBILE);
  assert.strictEqual(r.iface, 'rmnet_data0');
  assert.strictEqual(det.classifyUpstream(r.iface), 'datos moviles');
});

t('dumpsys tethering: downstream, upstream y regexs', () => {
  const p = det.parseTethering(DUMPSYS_ON);
  assert.deepStrictEqual(p.downstreams, ['wlan1']);
  assert.strictEqual(p.upstream, 'wlan0');
  assert.ok(p.regexs.includes('wlan\\d'));
  assert.ok(p.regexs.includes('softap0'));
});

t('los regexs de la ROM matchean softap0 y wlan1', () => {
  const m = det.regexsToMatcher(det.parseTethering(DUMPSYS_ON).regexs);
  assert.strictEqual(m('wlan1'), true);
  assert.strictEqual(m('softap0'), true);
  assert.strictEqual(m('rmnet_data0'), false);
});

group('deteccion: eleccion de interfaz y gateway');

t('hotspot activo: elige wlan1 y su IP real, no 192.168.43.1', () => {
  const r = det.choose({
    addrs: det.parseIpAddr(IP_ADDR_HOTSPOT_ON),
    route: det.parseRouteGet(ROUTE_GET),
    tether: det.parseTethering(DUMPSYS_ON),
  });
  assert.strictEqual(r.iface, 'wlan1');
  assert.strictEqual(r.gw, '192.168.174.95');
  assert.strictEqual(r.upIface, 'wlan0');
  assert.strictEqual(r.upKind, 'wifi');
  assert.strictEqual(r.source, 'dumpsys tethering');
  assert.strictEqual(r.ok, true);
});

t('sin dumpsys: por descarte tambien elige wlan1', () => {
  const r = det.choose({
    addrs: det.parseIpAddr(IP_ADDR_HOTSPOT_ON),
    route: det.parseRouteGet(ROUTE_GET),
    tether: { downstreams: [], upstream: null, regexs: [] },
  });
  assert.strictEqual(r.iface, 'wlan1');
  assert.strictEqual(r.gw, '192.168.174.95');
  assert.strictEqual(r.source, 'descarte');
});

t('nunca elige la interfaz de salida como hotspot', () => {
  const r = det.choose({
    addrs: det.parseIpAddr(IP_ADDR_HOTSPOT_OFF),
    route: det.parseRouteGet(ROUTE_GET),
    tether: det.parseTethering(DUMPSYS_OFF),
  });
  assert.notStrictEqual(r.iface, 'wlan0');
  assert.strictEqual(r.ok, false);
});

t('hotspot apagado: ok=false (hay que avisar, no arrancar a ciegas)', () => {
  const r = det.choose({
    addrs: det.parseIpAddr(IP_ADDR_HOTSPOT_OFF),
    route: det.parseRouteGet(ROUTE_GET),
    tether: det.parseTethering(DUMPSYS_OFF),
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.iface, '');
});

t('IFACE_IN manual gana, y avisa si no tiene IP', () => {
  const r = det.choose({
    addrs: det.parseIpAddr(IP_ADDR_HOTSPOT_OFF),
    route: det.parseRouteGet(ROUTE_GET),
    tether: det.parseTethering(DUMPSYS_OFF),
  }, { iface: 'wlan1' });
  assert.strictEqual(r.iface, 'wlan1');
  assert.strictEqual(r.source, 'IFACE_IN');
  assert.ok(r.notes.some(n => /no tiene IPv4/.test(n)));
});

t('GW manual gana sobre la IP detectada', () => {
  const r = det.choose({
    addrs: det.parseIpAddr(IP_ADDR_HOTSPOT_ON),
    route: det.parseRouteGet(ROUTE_GET),
    tether: det.parseTethering(DUMPSYS_ON),
  }, { gw: '192.168.174.1' });
  assert.strictEqual(r.gw, '192.168.174.1');
  assert.strictEqual(r.gwSource, 'GW');
});

t('red del hotspot para las reglas de aislamiento', () => {
  assert.strictEqual(det.networkOf('192.168.174.95', 24), '192.168.174.0/24');
});

/* ------------------------------------------------------------------ dns --- */

const dns = require('../lib/dnsmsg');

function encName(name) {
  const parts = String(name).split('.').filter(Boolean);
  return Buffer.concat([
    ...parts.map(p => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'latin1')])),
    Buffer.from([0]),
  ]);
}

function mkQuery(name, type = 1, id = 0x1234) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(0x0100, 2);
  h.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([h, encName(name), tail]);
}

function mkResponse(qname, records, { id = 0x1234, qtype = 1 } = {}) {
  const head = mkQuery(qname, qtype, id);
  head.writeUInt16BE(0x8180, 2);
  head.writeUInt16BE(records.length, 6);
  const recs = records.map(r => {
    const rd = r.type === dns.TYPE.CNAME ? encName(r.target) : Buffer.from(r.ip.split('.').map(Number));
    const mid = Buffer.alloc(10);
    mid.writeUInt16BE(r.type, 0);
    mid.writeUInt16BE(1, 2);
    mid.writeUInt32BE(r.ttl || 60, 4);
    mid.writeUInt16BE(rd.length, 8);
    return Buffer.concat([encName(r.name), mid, rd]);
  });
  return Buffer.concat([head, ...recs]);
}

group('dns: lectura de paquetes');

t('lee la pregunta de una consulta A', () => {
  const q = dns.questionOf(mkQuery('api.whatsapp.net', 1, 0xbeef));
  assert.strictEqual(q.name, 'api.whatsapp.net');
  assert.strictEqual(q.type, 1);
  assert.strictEqual(q.id, 0xbeef);
});

t('lee una consulta HTTPS (tipo 65), que Android hace sin parar', () => {
  assert.strictEqual(dns.questionOf(mkQuery('whatsapp.net', 65)).type, 65);
});

t('un paquete truncado no revienta', () => {
  assert.strictEqual(dns.questionOf(Buffer.from([0, 1, 2])), null);
  assert.strictEqual(dns.parseMessage(Buffer.alloc(0)), null);
});

t('un puntero circular no cuelga el proceso', () => {
  const b = Buffer.alloc(16);
  b.writeUInt16BE(1, 0);
  b.writeUInt16BE(1, 4);
  b[12] = 0xC0; b[13] = 0x0C;
  assert.strictEqual(dns.readName(b, 12), null);
});

group('dns: solo se aprenden las IPs del nombre consultado');

t('acepta las A del propio nombre', () => {
  const r = mkResponse('whatsapp.net', [
    { name: 'whatsapp.net', type: 1, ip: '157.240.1.1' },
    { name: 'whatsapp.net', type: 1, ip: '157.240.1.2' },
  ]);
  assert.deepStrictEqual(dns.answerIps(dns.parseMessage(r), 'whatsapp.net'), ['157.240.1.1', '157.240.1.2']);
});

t('sigue la cadena de CNAME', () => {
  const r = mkResponse('api.whatsapp.net', [
    { name: 'api.whatsapp.net', type: 5, target: 'edge.whatsapp.net' },
    { name: 'edge.whatsapp.net', type: 1, ip: '157.240.9.9' },
  ]);
  assert.deepStrictEqual(dns.answerIps(dns.parseMessage(r), 'api.whatsapp.net'), ['157.240.9.9']);
});

t('descarta A de un nombre ajeno colado en la misma respuesta', () => {
  const r = mkResponse('whatsapp.net', [
    { name: 'whatsapp.net', type: 1, ip: '157.240.1.1' },
    { name: 'atacante.example', type: 1, ip: '1.2.3.4' },
  ]);
  assert.deepStrictEqual(dns.answerIps(dns.parseMessage(r), 'whatsapp.net'), ['157.240.1.1']);
});

t('un CNAME ajeno no abre la cadena', () => {
  const r = mkResponse('whatsapp.net', [
    { name: 'otro.example', type: 5, target: 'malo.example' },
    { name: 'malo.example', type: 1, ip: '1.2.3.4' },
  ]);
  assert.deepStrictEqual(dns.answerIps(dns.parseMessage(r), 'whatsapp.net'), []);
});

group('dns: construccion de respuestas');

t('hijack: devuelve la IP del gateway', () => {
  const res = dns.buildResponse(mkQuery('instagram.com'), { ips: ['192.168.174.95'] });
  const m = dns.parseMessage(res);
  assert.strictEqual(m.an.length, 1);
  assert.strictEqual(m.an[0].ip, '192.168.174.95');
  assert.strictEqual(m.flags & 0x0F, dns.RCODE.OK);
  assert.strictEqual(m.id, 0x1234);
});

t('NODATA para AAAA: rcode 0 y cero respuestas', () => {
  const res = dns.buildResponse(mkQuery('whatsapp.net', 28), { ips: [] });
  const m = dns.parseMessage(res);
  assert.strictEqual(m.an.length, 0);
  assert.strictEqual(m.flags & 0x0F, dns.RCODE.OK);
  assert.strictEqual(m.qd[0].type, 28, 'la pregunta se devuelve tal cual');
});

t('NXDOMAIN para un dominio no permitido ya autenticado', () => {
  const res = dns.buildResponse(mkQuery('instagram.com'), { rcode: dns.RCODE.NXDOMAIN });
  assert.strictEqual(dns.parseMessage(res).flags & 0x0F, dns.RCODE.NXDOMAIN);
});

t('la respuesta conserva el id de la consulta', () => {
  const res = dns.buildResponse(mkQuery('x.com', 1, 0x7a7a), { ips: ['1.1.1.1'] });
  assert.strictEqual(res.readUInt16BE(0), 0x7a7a);
});

t('QR y RA puestos, RD copiado', () => {
  const f = dns.parseMessage(dns.buildResponse(mkQuery('x.com'), { ips: [] })).flags;
  assert.ok(f & 0x8000, 'QR');
  assert.ok(f & 0x0080, 'RA');
  assert.ok(f & 0x0100, 'RD');
});

group('dns: match por sufijo');

t('ejemplo.com cubre api.ejemplo.com', () => {
  assert.strictEqual(dns.suffixMatch('api.ejemplo.com', ['ejemplo.com']), true);
});

t('noejemplo.com NO lo cubre', () => {
  assert.strictEqual(dns.suffixMatch('noejemplo.com', ['ejemplo.com']), false);
});

/* ------------------------------------------------------------------- fw --- */

const { Firewall } = require('../lib/fw');

function rulesFor(over = {}) {
  const fw = new Firewall(Object.assign({
    iface: 'wlan1', gw: '192.168.174.95', port: 8080, dnsPort: 5454,
    freeMacs: new Set(['00:08:22:6c:de:fb']),
    isolate: true, blockIpv6: true, snoopForceDns: false, speed: 0,
    log: () => {},
  }, over));
  return fw.buildRules(['157.240.0.0/16']).map(r => (typeof r === 'string' ? r : r.cmd));
}

const idx = (rules, re) => rules.findIndex(r => re.test(r));

group('firewall: estructura de cadenas');

t('PORTAL_FWD acaba en DROP (lo desconocido no sale)', () => {
  const r = rulesFor();
  const fwd = r.filter(x => x.includes('-A PORTAL_FWD'));
  assert.ok(/-A PORTAL_FWD -j DROP$/.test(fwd[fwd.length - 1]), fwd[fwd.length - 1]);
});

t('PORTAL_WA acaba en DROP', () => {
  const wa = rulesFor().filter(x => x.includes('-A PORTAL_WA'));
  assert.ok(/-A PORTAL_WA -j DROP$/.test(wa[wa.length - 1]));
});

t('hay reset rapido antes del DROP, no solo silencio', () => {
  const r = rulesFor();
  assert.ok(r.some(x => /-A PORTAL_FWD -p tcp -j REJECT --reject-with tcp-reset/.test(x)));
  assert.ok(r.some(x => /-A PORTAL_WA -p tcp -j REJECT --reject-with tcp-reset/.test(x)));
});

t('las reglas por MAC viven en su cadena, saltada desde PORTAL_FWD', () => {
  const r = rulesFor();
  assert.ok(r.some(x => /-A PORTAL_FWD -j PORTAL_MAC$/.test(x)));
});

t('el aislamiento va ANTES del salto por MAC', () => {
  const r = rulesFor();
  const iso = idx(r, /-A PORTAL_FWD -o wlan1 -j DROP/);
  const mac = idx(r, /-A PORTAL_FWD -j PORTAL_MAC$/);
  assert.ok(iso >= 0 && mac >= 0, 'faltan reglas');
  assert.ok(iso < mac, 'un cliente autenticado se saltaria el aislamiento');
});

t('con ISOLATE=1 no se alcanzan las redes privadas', () => {
  const r = rulesFor();
  for (const d of ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'])
    assert.ok(r.some(x => x.includes(`-A PORTAL_FWD -d ${d} -j DROP`)), d);
});

t('con ISOLATE=0 esas reglas desaparecen', () => {
  const r = rulesFor({ isolate: false });
  assert.ok(!r.some(x => x.includes('-d 192.168.0.0/16 -j DROP')));
  assert.ok(!r.some(x => /-A PORTAL_FWD -o wlan1 -j DROP/.test(x)));
});

t('el 443 ya no se redirige al portal (rompia TLS y HSTS)', () => {
  const r = rulesFor();
  assert.ok(!r.some(x => x.includes('--dport 443')), r.filter(x => x.includes('443')).join('\n'));
});

t('el 53 se redirige al DNS propio y el 80 al portal', () => {
  const r = rulesFor();
  assert.ok(r.some(x => x.includes('-A PORTAL_PRE -p udp --dport 53 -j DNAT --to-destination 192.168.174.95:5454')));
  assert.ok(r.some(x => x.includes('-A PORTAL_PRE -p tcp --dport 80 -j REDIRECT --to-port 8080')));
});

t('los clientes solo alcanzan el portal, el DNS, DHCP e ICMP del telefono', () => {
  const r = rulesFor();
  const inRules = r.filter(x => x.includes('-A PORTAL_IN'));
  assert.ok(inRules.some(x => x.includes('--dport 67:68')), 'sin DHCP no hay IP para los clientes');
  assert.ok(inRules.some(x => x.includes('--dport 5454')));
  assert.ok(inRules.some(x => x.includes('--dport 8080')));
  assert.ok(/-A PORTAL_IN -j DROP$/.test(inRules[inRules.length - 1]));
});

t('una FREE_MAC pasa entera y conserva el acceso al portal', () => {
  const r = rulesFor();
  assert.ok(r.some(x => /-A PORTAL_MAC -m mac --mac-source 00:08:22:6c:de:fb -j ACCEPT/.test(x)));
  assert.ok(r.some(x => /-A PORTAL_PRE -m mac --mac-source 00:08:22:6c:de:fb -d 192.168.174.95 -p tcp --dport 80 -j REDIRECT/.test(x)));
});

t('IPv6: se corta el anuncio de router y el reenvio', () => {
  const r = rulesFor();
  assert.ok(r.some(x => /ip6tables -A PORTAL6_OUT -p icmpv6 --icmpv6-type router-advertisement -j DROP/.test(x)));
  assert.ok(r.some(x => /ip6tables -A PORTAL6_FWD -j DROP/.test(x)));
  assert.ok(r.some(x => /ip6tables -I FORWARD -i wlan1 -j PORTAL6_FWD/.test(x)));
});

t('con BLOCK_IPV6=0 no se toca ip6tables', () => {
  assert.ok(!rulesFor({ blockIpv6: false }).some(x => x.startsWith('ip6tables')));
});

t('mangle usa cadena propia y no vacia la del sistema', () => {
  const r = rulesFor();
  assert.ok(r.some(x => x.includes('-t mangle -F PORTAL_MANGLE')));
  assert.ok(!r.some(x => /-t mangle -F FORWARD/.test(x)), 'eso borraria las reglas de tethering de Android');
});

t('los saltos se insertan al principio de las cadenas del sistema', () => {
  const r = rulesFor();
  for (const re of [
    /^iptables -I FORWARD -i wlan1 -j PORTAL_FWD$/,
    /^iptables -I INPUT -i wlan1 -j PORTAL_IN$/,
    /^iptables -t nat -I PREROUTING -i wlan1 -j PORTAL_PRE$/,
  ]) assert.ok(r.some(x => re.test(x)), String(re));
});

group('firewall: reglas por dispositivo');

t('al autenticar, la MAC pasa y su NAT se exime', async () => {
  const seen = [];
  const fw = new Firewall({ iface: 'wlan1', gw: '1.2.3.4', port: 80, dnsPort: 53, freeMacs: new Set(), log: () => {} });
  fw.exec = async rules => { seen.push(...rules.map(r => (typeof r === 'string' ? r : r.cmd))); return { ok: true, failed: [] }; };
  await fw.openMac('aa:bb:cc:dd:ee:ff');
  assert.ok(seen.some(x => /-t nat -I PORTAL_PRE -m mac --mac-source aa:bb:cc:dd:ee:ff -j RETURN/.test(x)));
  assert.ok(seen.some(x => /-I PORTAL_MAC -m mac --mac-source aa:bb:cc:dd:ee:ff -j ACCEPT/.test(x)));
});

t('con SNOOP_FORCE_DNS el 53 sigue capturado tras autenticar', async () => {
  const seen = [];
  const fw = new Firewall({ iface: 'wlan1', gw: '1.2.3.4', port: 80, dnsPort: 53, freeMacs: new Set(), snoopForceDns: true, log: () => {} });
  fw.exec = async rules => { seen.push(...rules.map(r => (typeof r === 'string' ? r : r.cmd))); return { ok: true, failed: [] }; };
  await fw.openMac('aa:bb:cc:dd:ee:ff');
  assert.ok(seen.some(x => /-m mac --mac-source aa:bb:cc:dd:ee:ff -p tcp -j RETURN/.test(x)));
  assert.ok(!seen.some(x => /--mac-source aa:bb:cc:dd:ee:ff -j RETURN$/.test(x)));
});

t('al restringir se quita el ACCEPT y se manda al jardin', async () => {
  const seen = [];
  const fw = new Firewall({ iface: 'wlan1', gw: '1.2.3.4', port: 80, dnsPort: 53, freeMacs: new Set(), log: () => {} });
  fw.exec = async rules => { seen.push(...rules.map(r => (typeof r === 'string' ? r : r.cmd))); return { ok: true, failed: [] }; };
  await fw.restrictMac('aa:bb:cc:dd:ee:ff');
  assert.ok(seen.some(x => /-D PORTAL_MAC .* -j ACCEPT/.test(x)));
  assert.ok(seen.some(x => /-I PORTAL_MAC .* -j PORTAL_WA/.test(x)));
});

t('una MAC invalida no llega nunca a un comando', async () => {
  const fw = new Firewall({ iface: 'wlan1', gw: '1.2.3.4', port: 80, dnsPort: 53, freeMacs: new Set(), log: () => {} });
  let called = false;
  fw.exec = async () => { called = true; return { ok: true, failed: [] }; };
  await fw.openMac('aa:bb:cc:dd:ee:ff; reboot');
  await fw.restrictMac('../../etc');
  await fw.addAllow('1.2.3.4/32; reboot');
  assert.strictEqual(called, false);
});

t('apply se niega con una interfaz o un gateway invalidos', async () => {
  const fw = new Firewall({ iface: 'wlan1"; reboot; echo "', gw: '1.2.3.4', port: 80, dnsPort: 53, freeMacs: new Set(), log: () => {} });
  fw.exec = async () => ({ ok: true, failed: [] });
  await assert.rejects(() => fw.apply([]), /interfaz invalida/);
  fw.iface = 'wlan1';
  fw.gw = 'no-es-ip';
  await assert.rejects(() => fw.apply([]), /gateway invalido/);
});

console.log(`\n${pass} ok, ${fail} fallos\n`);
process.exit(fail ? 1 : 0);
