'use strict';

const { suScript } = require('./sh');
const { isValidIp, isValidMac, isValidIface, isValidCidr } = require('./config');

const CH = {
  in:     'PORTAL_IN',
  fwd:    'PORTAL_FWD',
  mac:    'PORTAL_MAC',
  wa:     'PORTAL_WA',
  pre:    'PORTAL_PRE',
  mangle: 'PORTAL_MANGLE',
  in6:    'PORTAL6_IN',
  fwd6:   'PORTAL6_FWD',
  out6:   'PORTAL6_OUT',
};

/* Destinos que nunca deben salir del jardin: la red del propio telefono, la
 * LAN desde la que comparte y el rango CGNAT del operador. Sin esto un cliente
 * autenticado alcanza el router de casa o los demas clientes del hotspot. */
const PRIVATE_DESTS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];
const NEVER_DESTS   = ['127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4'];

/* Un bloqueo silencioso deja a la app esperando el timeout; un reset hace que
 * falle al instante y que el sistema operativo saque antes el aviso de portal
 * cautivo. El DROP final cubre el caso de un kernel sin xt_REJECT. */
function closeChain(ipt, chain) {
  return [
    opt(`${ipt} -A ${chain} -p tcp -j REJECT --reject-with tcp-reset`),
    opt(`${ipt} -A ${chain} -p udp -j REJECT --reject-with icmp-port-unreachable`),
    `${ipt} -A ${chain} -j DROP`,
  ];
}

function opt(cmd) { return { cmd, optional: true }; }
function asRule(r) { return typeof r === 'string' ? { cmd: r, optional: false } : r; }

class Firewall {
  constructor(opts) {
    this.log = opts.log || (() => {});
    this.set(opts);
    this.queue = Promise.resolve();
    this.applied = false;
  }

  set({ iface, gw, port, dnsPort, freeMacs, isolate, blockIpv6, snoopForceDns, speed }) {
    if (iface !== undefined) this.iface = iface;
    if (gw !== undefined) this.gw = gw;
    if (port !== undefined) this.port = port;
    if (dnsPort !== undefined) this.dnsPort = dnsPort;
    if (freeMacs !== undefined) this.freeMacs = freeMacs;
    if (isolate !== undefined) this.isolate = isolate;
    if (blockIpv6 !== undefined) this.blockIpv6 = blockIpv6;
    if (snoopForceDns !== undefined) this.snoopForceDns = snoopForceDns;
    if (speed !== undefined) this.speed = speed;
  }

  /* Toda escritura pasa por aqui en serie: iptables no es reentrante y dos
   * lotes solapados pueden dejar reglas a medias. */
  run(rules, label) {
    const task = () => this.exec(rules, label);
    const next = this.queue.then(task, task);
    this.queue = next.catch(() => {});
    return next;
  }

  async exec(rules, label) {
    const list = rules.map(asRule).filter(r => r.cmd);
    if (!list.length) return { ok: true, failed: [] };
    const script = list
      .map((r, i) => (r.optional ? `${r.cmd} >/dev/null 2>&1` : `${r.cmd} || echo "__FAIL__ ${i}"`))
      .join('\n');
    const res = await suScript(script, { timeout: 60000 });

    const failed = [];
    for (const m of String(res.out).matchAll(/__FAIL__ (\d+)/g)) {
      const r = list[Number(m[1])];
      if (r) failed.push(r.cmd);
    }
    if (res.code === 127) {
      this.log('err', `${label}: no se pudo obtener root (${res.err.trim() || 'su fallo'})`);
      return { ok: false, failed: list.map(r => r.cmd), noRoot: true };
    }
    if (res.code === 124) this.log('err', `${label}: timeout aplicando reglas`);
    for (const f of failed) this.log('err', `regla rechazada: ${f}`);
    if (failed.length && res.err.trim()) this.log('err', `iptables: ${res.err.trim().split('\n')[0]}`);
    return { ok: failed.length === 0 && res.code === 0, failed, stderr: res.err };
  }

  /* Borra los saltos a cadenas PORTAL_* sea cual sea la interfaz que nombren.
   * Hace falta porque las reglas sobreviven al proceso y al reiniciar la
   * interfaz del hotspot puede haber cambiado de nombre o de IP. */
  purgeScript() {
    return `
purge() {
  bin="$1"; tbl="$2"; chain="$3"
  "$bin" -t "$tbl" -S "$chain" 2>/dev/null | grep -- '-j PORTAL' | sed 's/^-A /-D /' | while IFS= read -r r; do
    "$bin" -t "$tbl" $r >/dev/null 2>&1
  done
}
for b in iptables ip6tables; do
  command -v "$b" >/dev/null 2>&1 || continue
  purge "$b" filter INPUT
  purge "$b" filter FORWARD
  purge "$b" filter OUTPUT
  purge "$b" nat PREROUTING
  purge "$b" mangle FORWARD
done`.trim();
  }

  macRules(prefix, mac) {
    return `-m mac --mac-source ${mac} ${prefix}`;
  }

  buildRules(allowRanges) {
    const { iface, gw, port, dnsPort } = this;
    const ipt = 'iptables';
    const r = [];

    for (const c of [CH.in, CH.fwd, CH.mac, CH.wa]) {
      r.push(opt(`${ipt} -N ${c}`));
      r.push(`${ipt} -F ${c}`);
    }
    r.push(opt(`${ipt} -t nat -N ${CH.pre}`), `${ipt} -t nat -F ${CH.pre}`);
    r.push(opt(`${ipt} -t mangle -N ${CH.mangle}`), `${ipt} -t mangle -F ${CH.mangle}`);

    /* --- clientes -> el propio telefono --- */
    r.push(`${ipt} -A ${CH.in} -p udp --dport 67:68 -j ACCEPT`);
    r.push(`${ipt} -A ${CH.in} -p udp --dport ${dnsPort} -j ACCEPT`);
    r.push(`${ipt} -A ${CH.in} -p tcp --dport ${port} -j ACCEPT`);
    r.push(`${ipt} -A ${CH.in} -p icmp -j ACCEPT`);
    if (this.isolate) r.push(...closeChain(ipt, CH.in));

    /* --- clientes -> fuera --- */
    for (const d of NEVER_DESTS) r.push(`${ipt} -A ${CH.fwd} -d ${d} -j DROP`);
    if (this.isolate) {
      r.push(`${ipt} -A ${CH.fwd} -o ${iface} -j DROP`);
      for (const d of PRIVATE_DESTS) r.push(`${ipt} -A ${CH.fwd} -d ${d} -j DROP`);
    }
    r.push(`${ipt} -A ${CH.fwd} -j ${CH.mac}`);
    r.push(...closeChain(ipt, CH.fwd));

    /* --- jardin vallado --- */
    for (const c of allowRanges) {
      if (!isValidCidr(c)) continue;
      r.push(`${ipt} -A ${CH.wa} -d ${c} -j ACCEPT`);
    }
    r.push(...closeChain(ipt, CH.wa));

    /* --- captura --- */
    for (const mac of this.freeMacs) {
      r.push(`${ipt} -t nat -A ${CH.pre} -m mac --mac-source ${mac} -d ${gw} -p tcp --dport 80 -j REDIRECT --to-port ${port}`);
      r.push(`${ipt} -t nat -A ${CH.pre} -m mac --mac-source ${mac} -j RETURN`);
      r.push(`${ipt} -A ${CH.mac} -m mac --mac-source ${mac} -j ACCEPT`);
    }
    r.push(`${ipt} -t nat -A ${CH.pre} -p udp --dport 53 -j DNAT --to-destination ${gw}:${dnsPort}`);
    r.push(`${ipt} -t nat -A ${CH.pre} -p tcp --dport 80 -j REDIRECT --to-port ${port}`);

    /* --- saltos --- */
    r.push(`${ipt} -I INPUT -i ${iface} -j ${CH.in}`);
    r.push(`${ipt} -I FORWARD -i ${iface} -j ${CH.fwd}`);
    r.push(`${ipt} -t nat -I PREROUTING -i ${iface} -j ${CH.pre}`);
    r.push(`${ipt} -t mangle -I FORWARD -j ${CH.mangle}`);

    if (this.blockIpv6) r.push(...this.ipv6Rules());
    return r;
  }

  /* El muro es solo IPv4: si el operador da IPv6 al anclaje, los clientes
   * salen por v6 sin pasar por ninguna de las reglas de arriba. Se corta el
   * anuncio de router para que no lleguen a configurar una direccion v6, y se
   * tira el reenvio por si la configuran igual. */
  ipv6Rules() {
    const ipt = 'ip6tables';
    const { iface } = this;
    const r = [];
    for (const c of [CH.in6, CH.fwd6, CH.out6]) {
      r.push(opt(`${ipt} -N ${c}`));
      r.push(opt(`${ipt} -F ${c}`));
    }
    r.push(opt(`${ipt} -A ${CH.out6} -p icmpv6 --icmpv6-type router-advertisement -j DROP`));
    r.push(opt(`${ipt} -A ${CH.out6} -p udp --sport 547 -j DROP`));
    r.push(opt(`${ipt} -A ${CH.fwd6} -j DROP`));
    r.push(opt(`${ipt} -A ${CH.in6} -j DROP`));
    r.push(opt(`${ipt} -I OUTPUT -o ${iface} -j ${CH.out6}`));
    r.push(opt(`${ipt} -I FORWARD -i ${iface} -j ${CH.fwd6}`));
    r.push(opt(`${ipt} -I FORWARD -o ${iface} -j ${CH.fwd6}`));
    r.push(opt(`${ipt} -I INPUT -i ${iface} -j ${CH.in6}`));
    return r;
  }

  async apply(allowRanges) {
    if (!isValidIface(this.iface)) throw new Error(`interfaz invalida: ${this.iface}`);
    if (!isValidIp(this.gw)) throw new Error(`gateway invalido: ${this.gw}`);
    const res = await this.run([{ cmd: this.purgeScript(), optional: true }, ...this.buildRules(allowRanges)], 'apply');
    this.applied = res.ok;
    return res;
  }

  async teardown() {
    const ipt = 'iptables';
    const flush = [{ cmd: this.purgeScript(), optional: true }];
    for (const c of [CH.in, CH.fwd, CH.mac, CH.wa]) {
      flush.push(opt(`${ipt} -F ${c}`), opt(`${ipt} -X ${c}`));
    }
    flush.push(opt(`${ipt} -t nat -F ${CH.pre}`), opt(`${ipt} -t nat -X ${CH.pre}`));
    flush.push(opt(`${ipt} -t mangle -F ${CH.mangle}`), opt(`${ipt} -t mangle -X ${CH.mangle}`));
    for (const c of [CH.in6, CH.fwd6, CH.out6]) {
      flush.push(opt(`ip6tables -F ${c}`), opt(`ip6tables -X ${c}`));
    }
    if (this.speed && isValidIface(this.iface))
      flush.push(opt(`tc qdisc del dev ${this.iface} root`));
    this.applied = false;
    return this.run(flush, 'teardown');
  }

  /* Comprueba que las reglas estan de verdad en el kernel. Un fallo de su o un
   * modulo ausente deja el portal arrancado sin filtrar nada, y eso tiene que
   * ser un error visible y no un arranque aparentemente correcto. */
  async verify() {
    const script = [
      `iptables -S FORWARD | grep -c -- "-j ${CH.fwd}"`,
      `iptables -t nat -S PREROUTING | grep -c -- "-j ${CH.pre}"`,
      `iptables -S ${CH.wa} | grep -c -- "-j DROP"`,
      `iptables -S ${CH.fwd} | grep -c -- "-j ${CH.mac}"`,
    ].join('\n');
    const res = await suScript(script, { timeout: 20000 });
    const n = String(res.out).trim().split('\n').map(x => parseInt(x, 10) || 0);
    const report = {
      fwdJump: n[0] > 0,
      natJump: n[1] > 0,
      waClosed: n[2] > 0,
      macChain: n[3] > 0,
    };
    report.ok = Object.values(report).every(Boolean);
    return report;
  }

  addAllow(cidr) {
    if (!isValidCidr(cidr)) return Promise.resolve({ ok: false });
    return this.run([`iptables -I ${CH.wa} -d ${cidr} -j ACCEPT`], 'addAllow');
  }

  delAllow(cidr) {
    if (!isValidCidr(cidr)) return Promise.resolve({ ok: false });
    return this.run([opt(`iptables -D ${CH.wa} -d ${cidr} -j ACCEPT`)], 'delAllow');
  }

  /* restricted = true aplica el jardin en el mismo lote que la exencion de
   * NAT. Con OPEN_MS=0 no debe quedar ni un instante con acceso total, y la
   * cola serializa los lotes pero no los fusiona. */
  openMac(mac, { restricted = false } = {}) {
    if (!isValidMac(mac)) return Promise.resolve({ ok: false });
    const natSkip = this.snoopForceDns
      ? `iptables -t nat -I ${CH.pre} -m mac --mac-source ${mac} -p tcp -j RETURN`
      : `iptables -t nat -I ${CH.pre} -m mac --mac-source ${mac} -j RETURN`;
    return this.run([
      natSkip,
      `iptables -I ${CH.mac} -m mac --mac-source ${mac} -j ${restricted ? CH.wa : 'ACCEPT'}`,
    ], 'openMac');
  }

  restrictMac(mac) {
    if (!isValidMac(mac)) return Promise.resolve({ ok: false });
    return this.run([
      opt(`iptables -D ${CH.mac} -m mac --mac-source ${mac} -j ACCEPT`),
      `iptables -I ${CH.mac} -m mac --mac-source ${mac} -j ${CH.wa}`,
    ], 'restrictMac');
  }

  closeMac(mac) {
    if (!isValidMac(mac)) return Promise.resolve({ ok: false });
    return this.run([
      opt(`iptables -t nat -D ${CH.pre} -m mac --mac-source ${mac} -j RETURN`),
      opt(`iptables -t nat -D ${CH.pre} -m mac --mac-source ${mac} -p tcp -j RETURN`),
      opt(`iptables -D ${CH.mac} -m mac --mac-source ${mac} -j ACCEPT`),
      opt(`iptables -D ${CH.mac} -m mac --mac-source ${mac} -j ${CH.wa}`),
    ], 'closeMac');
  }

  /* --- limitador de velocidad por cliente --- */

  initTc() {
    if (!this.speed || !isValidIface(this.iface)) return Promise.resolve({ ok: true });
    const d = this.iface;
    return this.run([
      opt(`tc qdisc del dev ${d} root`),
      `tc qdisc add dev ${d} root handle 1: htb default 999`,
      `tc class add dev ${d} parent 1: classid 1:999 htb rate 1000mbit`,
    ], 'initTc');
  }

  tcAdd(mark, ip) {
    if (!this.speed || !isValidIp(ip)) return Promise.resolve({ ok: true });
    const d = this.iface, s = this.speed;
    return this.run([
      `tc class add dev ${d} parent 1: classid 1:${mark} htb rate ${s}kbit burst ${Math.max(s, 32)}k`,
      `tc filter add dev ${d} parent 1: protocol ip handle ${mark} fw flowid 1:${mark}`,
      `iptables -t mangle -A ${CH.mangle} -d ${ip} -j MARK --set-mark ${mark}`,
    ], 'tcAdd');
  }

  tcDel(mark, ip) {
    if (!this.speed) return Promise.resolve({ ok: true });
    const d = this.iface;
    return this.run([
      opt(`iptables -t mangle -D ${CH.mangle} -d ${ip} -j MARK --set-mark ${mark}`),
      opt(`tc filter del dev ${d} parent 1: protocol ip handle ${mark} fw`),
      opt(`tc class del dev ${d} parent 1: classid 1:${mark}`),
    ], 'tcDel');
  }
}

module.exports = { Firewall, CH, PRIVATE_DESTS, NEVER_DESTS };
