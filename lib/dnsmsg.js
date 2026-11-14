'use strict';

const TYPE = { A: 1, NS: 2, CNAME: 5, AAAA: 28, HTTPS: 65 };
const RCODE = { OK: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

/* Lee un nombre siguiendo punteros de compresion. El contador de saltos corta
 * los punteros circulares, que de otro modo cuelgan el proceso con un paquete
 * de 12 bytes. */
function readName(buf, off) {
  const parts = [];
  let jumps = 0;
  let next = -1;
  let pos = off;
  while (pos >= 0 && pos < buf.length) {
    const len = buf[pos];
    if (len === 0) { pos++; break; }
    if ((len & 0xC0) === 0xC0) {
      if (pos + 1 >= buf.length) return null;
      const ptr = ((len & 0x3F) << 8) | buf[pos + 1];
      if (next < 0) next = pos + 2;
      if (++jumps > 16 || ptr >= buf.length) return null;
      pos = ptr;
      continue;
    }
    if ((len & 0xC0) !== 0) return null;
    if (pos + 1 + len > buf.length) return null;
    parts.push(buf.toString('latin1', pos + 1, pos + 1 + len));
    pos += len + 1;
  }
  if (pos > buf.length) return null;
  return { name: parts.join('.').toLowerCase(), next: next >= 0 ? next : pos };
}

function parseMessage(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  const msg = {
    id: buf.readUInt16BE(0),
    flags: buf.readUInt16BE(2),
    qd: [],
    an: [],
    qdEnd: 12,
  };
  const qdCount = buf.readUInt16BE(4);
  const anCount = buf.readUInt16BE(6);
  let off = 12;

  for (let i = 0; i < qdCount; i++) {
    const n = readName(buf, off);
    if (!n || n.next + 4 > buf.length) return null;
    msg.qd.push({ name: n.name, type: buf.readUInt16BE(n.next), cls: buf.readUInt16BE(n.next + 2) });
    off = n.next + 4;
  }
  msg.qdEnd = off;

  for (let i = 0; i < anCount; i++) {
    const n = readName(buf, off);
    if (!n || n.next + 10 > buf.length) break;
    const type = buf.readUInt16BE(n.next);
    const cls = buf.readUInt16BE(n.next + 2);
    const ttl = buf.readUInt32BE(n.next + 4);
    const rdlen = buf.readUInt16BE(n.next + 8);
    const rdOff = n.next + 10;
    if (rdOff + rdlen > buf.length) break;
    const rec = { name: n.name, type, cls, ttl, rdlen };
    if (type === TYPE.A && rdlen === 4) {
      rec.ip = `${buf[rdOff]}.${buf[rdOff + 1]}.${buf[rdOff + 2]}.${buf[rdOff + 3]}`;
    } else if (type === TYPE.CNAME) {
      const t = readName(buf, rdOff);
      if (t) rec.target = t.name;
    }
    msg.an.push(rec);
    off = rdOff + rdlen;
  }
  return msg;
}

/* Solo se devuelven las A que cuelgan del nombre consultado o de su cadena de
 * CNAME. Una respuesta puede traer registros de otros nombres en la misma
 * seccion, y aceptarlos a ciegas permite meter en la allowlist IPs que no
 * pertenecen al dominio permitido. */
function answerIps(msg, qname) {
  if (!msg || !msg.an.length) return [];
  const chain = new Set([String(qname).toLowerCase()]);
  const ips = [];
  for (const rec of msg.an) {
    if (rec.cls !== 1) continue;
    if (!chain.has(rec.name)) continue;
    if (rec.type === TYPE.CNAME && rec.target) chain.add(rec.target);
    else if (rec.type === TYPE.A && rec.ip) ips.push(rec.ip);
  }
  return ips;
}

function questionOf(buf) {
  const msg = parseMessage(buf);
  if (!msg || !msg.qd.length) return null;
  return { id: msg.id, flags: msg.flags, qdEnd: msg.qdEnd, ...msg.qd[0] };
}

/* La respuesta reutiliza la cabecera y la seccion de pregunta del paquete
 * original, y apunta cada respuesta al nombre en el offset 12 por compresion.
 * Se descarta la seccion adicional (EDNS incluido): ar=0. */
function buildResponse(req, { rcode = RCODE.OK, ips = [], ttl = 30, authoritative = false } = {}) {
  const q = questionOf(req);
  if (!q) return null;
  const head = req.subarray(0, q.qdEnd);
  const body = Buffer.alloc(ips.length * 16);
  let p = 0;
  for (const ip of ips) {
    const o = ip.split('.').map(Number);
    if (o.length !== 4 || o.some(n => !Number.isInteger(n) || n < 0 || n > 255)) continue;
    body.writeUInt16BE(0xC00C, p);
    body.writeUInt16BE(TYPE.A, p + 2);
    body.writeUInt16BE(1, p + 4);
    body.writeUInt32BE(ttl, p + 6);
    body.writeUInt16BE(4, p + 10);
    body[p + 12] = o[0]; body[p + 13] = o[1]; body[p + 14] = o[2]; body[p + 15] = o[3];
    p += 16;
  }
  const out = Buffer.concat([head, body.subarray(0, p)]);
  const rd = req.readUInt16BE(2) & 0x0100;
  let flags = 0x8000 | rd | 0x0080 | (rcode & 0x0F);
  if (authoritative) flags |= 0x0400;
  out.writeUInt16BE(flags, 2);
  out.writeUInt16BE(1, 4);
  out.writeUInt16BE(p / 16, 6);
  out.writeUInt16BE(0, 8);
  out.writeUInt16BE(0, 10);
  return out;
}

function withId(buf, id) {
  const out = Buffer.from(buf);
  out.writeUInt16BE(id, 0);
  return out;
}

function suffixMatch(name, list) {
  if (!name) return false;
  return list.some(d => name === d || name.endsWith('.' + d));
}

module.exports = {
  TYPE, RCODE, readName, parseMessage, questionOf, answerIps, buildResponse, withId, suffixMatch,
};
