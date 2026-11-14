'use strict';

const fs = require('fs');
const { sh } = require('./sh');
const { isValidIp, isValidMac } = require('./config');

/* La tabla entera se lee de una vez y se cachea: antes era un "su -c ip neigh"
 * sincrono por cada IP en la ruta de la peticion, que con su timeout de 5s
 * congelaba el DNS y el HTTP de todos los clientes a la vez. En Android 13
 * /proc/net/arp y "ip neigh" se leen sin root. */
class MacTable {
  constructor({ ttlMs = 5000, log = () => {} } = {}) {
    this.ttlMs = ttlMs;
    this.log = log;
    this.map = new Map();
    this.ts = 0;
    this.inflight = null;
  }

  parseArp(text) {
    const out = new Map();
    for (const line of String(text).split('\n').slice(1)) {
      const c = line.trim().split(/\s+/);
      if (c.length < 4) continue;
      const [ip, , , mac] = c;
      if (!isValidIp(ip) || !isValidMac(mac) || mac === '00:00:00:00:00:00') continue;
      out.set(ip, mac.toLowerCase());
    }
    return out;
  }

  parseNeigh(text) {
    const out = new Map();
    for (const line of String(text).split('\n')) {
      const m = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+.*\blladdr\s+([0-9a-f:]{17})/i);
      if (m && isValidIp(m[1]) && isValidMac(m[2])) out.set(m[1], m[2].toLowerCase());
    }
    return out;
  }

  async refresh() {
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      let table = new Map();
      try {
        table = this.parseArp(fs.readFileSync('/proc/net/arp', 'utf8'));
      } catch (_) {}
      if (!table.size) {
        const r = await sh('ip neigh show', { timeout: 4000 });
        if (r.code === 0) table = this.parseNeigh(r.out);
      }
      if (table.size) { this.map = table; this.ts = Date.now(); }
      this.inflight = null;
      return this.map;
    })();
    return this.inflight;
  }

  cached(ip) {
    if (!isValidIp(ip)) return null;
    return this.map.get(ip) || null;
  }

  async lookup(ip) {
    if (!isValidIp(ip)) return null;
    const hit = this.map.get(ip);
    if (hit && Date.now() - this.ts < this.ttlMs) return hit;
    await this.refresh();
    return this.map.get(ip) || null;
  }
}

/* Marcas para tc. Se reutilizan al liberar porque el handle del filtro fw es
 * el propio numero de marca y tc no admite valores arbitrariamente grandes. */
class MarkPool {
  constructor(max = 60) {
    this.max = max;
    this.free = [];
    this.next = 1;
    this.used = new Map();
  }
  take(key, ip) {
    const prev = this.used.get(key);
    if (prev && prev.ip === ip) return prev;
    if (prev) this.release(key);
    const mark = this.free.length ? this.free.pop() : this.next++;
    const e = { mark, ip };
    this.used.set(key, e);
    return e;
  }
  release(key) {
    const e = this.used.get(key);
    if (!e) return null;
    this.used.delete(key);
    this.free.push(e.mark);
    return e;
  }
  full() { return this.used.size >= this.max; }
  oldest() { return this.used.keys().next().value; }
  byIp(ip) {
    for (const [k, e] of this.used) if (e.ip === ip) return k;
    return null;
  }
}

module.exports = { MacTable, MarkPool };
