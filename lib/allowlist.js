'use strict';

const fs = require('fs');
const path = require('path');
const { isValidCidr, isPublicUnicast, ipToInt, intToIp, maskOf } = require('./config');

function splitCidr(cidr) {
  const [ip, bits] = String(cidr).split('/');
  const b = Number(bits);
  const mask = maskOf(b);
  return { net: (ipToInt(ip) & mask) >>> 0, bits: b, mask };
}

class Allowlist {
  constructor({ staticRanges = [], widen = [], max = 256, ttlMs = 0, cachePath = '', dir = '.', fw = null, log = () => {} } = {}) {
    this.widen = widen;
    this.max = max;
    this.ttlMs = ttlMs;
    this.cachePath = cachePath ? path.join(dir, cachePath) : '';
    this.fw = fw;
    this.log = log;
    this.fixed = [];
    for (const c of staticRanges) if (isValidCidr(c)) this.fixed.push(c);
    this.learned = new Map();
    this.saveTimer = null;
  }

  /* Un /32 dentro de un /24 que ya esta permitido no aporta nada y solo gasta
   * una regla de iptables y un hueco del tope. */
  covered(cidr) {
    const q = splitCidr(cidr);
    for (const c of this.all()) {
      const e = splitCidr(c);
      if (e.bits <= q.bits && ((q.net & e.mask) >>> 0) === e.net) return c;
    }
    return null;
  }

  toCidr(ip) {
    const n = ipToInt(ip);
    for (const w of this.widen) {
      if (((n & w.mask) >>> 0) === w.base) {
        const m = maskOf(w.to);
        return `${intToIp((n & m) >>> 0)}/${w.to}`;
      }
    }
    return `${ip}/32`;
  }

  all() { return [...this.fixed, ...this.learned.keys()]; }
  size() { return this.fixed.length + this.learned.size; }

  async learn(ip, src, { applyRule = true, quiet = false } = {}) {
    if (!isPublicUnicast(ip)) return false;
    return this.learnCidr(this.toCidr(ip), src, { applyRule, quiet });
  }

  async learnCidr(cidr, src, { applyRule = true, quiet = false } = {}) {
    if (!isValidCidr(cidr)) return false;
    const existing = this.learned.get(cidr);
    if (existing) { existing.ts = Date.now(); return false; }
    if (this.covered(cidr)) return false;

    if (this.learned.size >= this.max && !this.evictOldest()) {
      if (!quiet) this.log('warn', `allowlist llena (${this.max}), se ignora ${cidr}`);
      return false;
    }

    this.learned.set(cidr, { ts: Date.now(), src });
    if (applyRule && this.fw) await this.fw.addAllow(cidr);
    if (!quiet) this.log('ok', `allow +${cidr} (${src})`);
    this.saveSoon();
    return true;
  }

  evictOldest() {
    let oldest = null, oldestTs = Infinity;
    for (const [cidr, v] of this.learned) if (v.ts < oldestTs) { oldestTs = v.ts; oldest = cidr; }
    if (!oldest) return false;
    this.drop(oldest, 'tope alcanzado');
    return true;
  }

  drop(cidr, why) {
    if (!this.learned.delete(cidr)) return false;
    if (this.fw) this.fw.delAllow(cidr).catch(() => {});
    this.log('warn', `allow -${cidr} (${why})`);
    this.saveSoon();
    return true;
  }

  /* Sin esto la lista solo crece: se llena de IPs que el proveedor ya no usa,
   * agota el tope y deja de aprender las nuevas. */
  sweep() {
    if (!this.ttlMs) return 0;
    const cutoff = Date.now() - this.ttlMs;
    let n = 0;
    for (const [cidr, v] of [...this.learned]) if (v.ts < cutoff) { this.drop(cidr, 'caducado'); n++; }
    return n;
  }

  touch(cidr) {
    const e = this.learned.get(cidr);
    if (e) e.ts = Date.now();
  }

  saveSoon() {
    if (!this.cachePath || this.saveTimer) return;
    this.saveTimer = setTimeout(() => { this.saveTimer = null; this.save(); }, 2000);
    if (this.saveTimer.unref) this.saveTimer.unref();
  }

  /* tmp + rename para que un corte a mitad de escritura no deje el cache a
   * medias; aun asi load() tolera un JSON roto. */
  save() {
    if (!this.cachePath) return;
    const data = JSON.stringify([...this.learned.entries()].map(([cidr, v]) => ({ cidr, ...v })));
    const tmp = `${this.cachePath}.tmp`;
    try {
      fs.writeFileSync(tmp, data, 'utf8');
      fs.renameSync(tmp, this.cachePath);
    } catch (_) {
      try { fs.unlinkSync(tmp); } catch (_) {}
    }
  }

  load() {
    if (!this.cachePath) return [];
    try {
      const raw = JSON.parse(fs.readFileSync(this.cachePath, 'utf8'));
      if (!Array.isArray(raw)) return [];
      const cutoff = this.ttlMs ? Date.now() - this.ttlMs : 0;
      return raw.filter(e => e && isValidCidr(e.cidr) && (!cutoff || Number(e.ts) >= cutoff));
    } catch (_) { return []; }
  }

  async loadInto() {
    let n = 0;
    for (const e of this.load()) {
      this.learned.set(e.cidr, { ts: Number(e.ts) || Date.now(), src: e.src || 'cache' });
      n++;
      if (this.learned.size >= this.max) break;
    }
    return n;
  }

  stats() {
    return { total: this.size(), fixed: this.fixed.length, learned: this.learned.size, max: this.max };
  }

  entries() {
    return [...this.learned.entries()].map(([cidr, v]) => ({ cidr, ...v }));
  }
}

module.exports = { Allowlist, splitCidr };
