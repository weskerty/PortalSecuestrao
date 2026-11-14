'use strict';

const dgram = require('dgram');
const crypto = require('crypto');
const dnsMsg = require('./dnsmsg');
const { TYPE, RCODE } = dnsMsg;

/* Se admite el guion bajo porque hay nombres reales que lo llevan al principio
 * de una etiqueta (_dns.resolver.arpa de RFC 9462, _tcp de los SRV) y Android
 * los consulta; lo que queda fuera es cualquier caracter que tenga significado
 * en HTML o en un shell. */
const NAME_RE = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/;

/* Las etiquetas DNS admiten bytes arbitrarios, asi que un cliente puede
 * consultar un "dominio" con un payload dentro. Todo lo que se guarde o se
 * muestre en el panel pasa por aqui primero. */
function safeName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= 253 && NAME_RE.test(name);
}

const GLOBAL_INFLIGHT_MAX = 256;
const CLIENT_INFLIGHT_MAX = 16;

class DnsProxy {
  constructor(opts) {
    this.port = opts.port;
    this.bindAddr = opts.bindAddr || '0.0.0.0';
    this.gw = opts.gw;
    this.resolvers = opts.resolvers;
    this.upPort = opts.upPort || 53;
    this.timeoutMs = opts.timeoutMs || 1500;
    this.allowDomains = opts.allowDomains || [];
    this.connDomains = opts.connDomains || [];
    this.blockIpv6 = opts.blockIpv6 !== false;
    this.snoop = Boolean(opts.snoop);
    this.allowlist = opts.allowlist || null;
    this.isAuthed = opts.isAuthed || (() => false);
    this.onQuery = opts.onQuery || (() => {});
    this.log = opts.log || (() => {});

    this.sock = null;
    this.up = null;
    this.pending = new Map();
    this.perClient = new Map();
    this.stats = { queries: 0, forwarded: 0, hijacked: 0, nodata: 0, nxdomain: 0, servfail: 0, dropped: 0 };
  }

  setGw(gw) { this.gw = gw; }

  isAllowed(name) { return dnsMsg.suffixMatch(name, this.allowDomains); }
  isConn(name) { return dnsMsg.suffixMatch(name, this.connDomains); }

  start() {
    return new Promise((resolve, reject) => {
      this.sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      this.up = dgram.createSocket({ type: 'udp4', reuseAddr: true });

      this.sock.on('error', e => { this.log('err', `dns: ${e.message}`); reject(e); });
      this.up.on('error', e => this.log('err', `dns upstream: ${e.message}`));
      this.sock.on('message', (msg, rinfo) => this.onClient(msg, rinfo));
      this.up.on('message', (msg, rinfo) => this.onUpstream(msg, rinfo));

      this.up.bind(0, () => {
        this.sock.bind(this.port, this.bindAddr, () => resolve());
      });
    });
  }

  stop() {
    for (const p of this.pending.values()) clearTimeout(p.timer);
    this.pending.clear();
    for (const s of [this.sock, this.up]) { try { s && s.close(); } catch (_) {} }
    this.sock = this.up = null;
  }

  reply(buf, rinfo) {
    if (!this.sock || !buf) return;
    this.sock.send(buf, rinfo.port, rinfo.address, () => {});
  }

  onClient(msg, rinfo) {
    const q = dnsMsg.questionOf(msg);
    if (!q || (q.flags & 0x8000)) return;
    this.stats.queries++;

    const name = q.name;
    if (safeName(name)) this.onQuery(rinfo.address, name);

    const allowed = this.isAllowed(name);
    const conn = this.isConn(name);

    if (q.type === TYPE.AAAA && this.blockIpv6) {
      this.stats.nodata++;
      return this.reply(dnsMsg.buildResponse(msg, { ips: [] }), rinfo);
    }

    if (allowed || conn) return this.forward(msg, rinfo, q);

    if (q.type !== TYPE.A) {
      this.stats.nodata++;
      return this.reply(dnsMsg.buildResponse(msg, { ips: [] }), rinfo);
    }

    /* Un dispositivo sin autenticar tiene que ver la IP del portal para que el
     * sistema detecte el portal cautivo. Uno ya autenticado no: devolverle el
     * gateway solo hace que su app intente hablar TLS con el portal, asi que
     * se le dice que el nombre no existe. */
    if (this.isAuthed(rinfo.address)) {
      this.stats.nxdomain++;
      return this.reply(dnsMsg.buildResponse(msg, { rcode: RCODE.NXDOMAIN }), rinfo);
    }
    this.stats.hijacked++;
    return this.reply(dnsMsg.buildResponse(msg, { ips: [this.gw], ttl: 10, authoritative: true }), rinfo);
  }

  countClient(ip, delta) {
    const n = (this.perClient.get(ip) || 0) + delta;
    if (n <= 0) this.perClient.delete(ip);
    else this.perClient.set(ip, n);
    return n;
  }

  forward(msg, rinfo, q) {
    if (this.pending.size >= GLOBAL_INFLIGHT_MAX ||
        (this.perClient.get(rinfo.address) || 0) >= CLIENT_INFLIGHT_MAX) {
      this.stats.dropped++;
      return this.reply(dnsMsg.buildResponse(msg, { rcode: RCODE.SERVFAIL }), rinfo);
    }

    let id = crypto.randomInt(0, 65536);
    for (let i = 0; i < 8 && this.pending.has(id); i++) id = crypto.randomInt(0, 65536);
    if (this.pending.has(id)) {
      this.stats.dropped++;
      return this.reply(dnsMsg.buildResponse(msg, { rcode: RCODE.SERVFAIL }), rinfo);
    }

    const out = dnsMsg.withId(msg, id);
    const entry = {
      clientId: q.id,
      qname: q.name,
      qtype: q.type,
      rinfo,
      req: msg,
      client: rinfo.address,
      timer: null,
    };
    entry.timer = setTimeout(() => {
      this.pending.delete(id);
      this.countClient(entry.client, -1);
      this.stats.servfail++;
      this.reply(dnsMsg.buildResponse(entry.req, { rcode: RCODE.SERVFAIL }), entry.rinfo);
    }, this.timeoutMs);

    this.pending.set(id, entry);
    this.countClient(rinfo.address, 1);
    this.stats.forwarded++;

    /* A todos los resolvers a la vez: cada uno responde con el PoP mas cercano
     * a el, y el primero que contesta es el mas rapido para este cliente. */
    for (const srv of this.resolvers) {
      try { this.up.send(out, this.upPort, srv, () => {}); } catch (_) {}
    }
  }

  /* Solo se acepta la respuesta si viene del puerto 53 de un resolver
   * configurado, el id coincide con el que generamos y la pregunta que
   * devuelve es la que hicimos. */
  onUpstream(msg, rinfo) {
    if (rinfo.port !== this.upPort || !this.resolvers.includes(rinfo.address)) return;
    if (!Buffer.isBuffer(msg) || msg.length < 12) return;
    const id = msg.readUInt16BE(0);
    const entry = this.pending.get(id);
    if (!entry) return;
    const q = dnsMsg.questionOf(msg);
    if (!q || q.name !== entry.qname || q.type !== entry.qtype) return;

    clearTimeout(entry.timer);
    this.pending.delete(id);
    this.countClient(entry.client, -1);

    if (this.snoop && this.allowlist && (this.isAllowed(entry.qname) || this.isConn(entry.qname))) {
      const parsed = dnsMsg.parseMessage(msg);
      for (const ip of dnsMsg.answerIps(parsed, entry.qname))
        this.allowlist.learn(ip, `dns:${entry.qname}`).catch(() => {});
    }

    this.reply(dnsMsg.withId(msg, entry.clientId), entry.rinfo);
  }
}

module.exports = { DnsProxy, safeName };
