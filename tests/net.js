'use strict';

/* Prueba de integracion del proxy DNS: levanta un resolver falso y un cliente
 * de verdad sobre loopback. No hace falta root ni hotspot.
 * node tests/net.js */

const assert = require('assert');
const dgram = require('dgram');
const { DnsProxy, safeName } = require('../lib/dnsproxy');
const { Allowlist } = require('../lib/allowlist');
const dns = require('../lib/dnsmsg');

let pass = 0, fail = 0;
const results = [];
async function t(name, fn) {
  try { await fn(); pass++; results.push(`  ok   ${name}`); }
  catch (e) { fail++; results.push(`  FAIL ${name}\n       ${e.message}`); }
}

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
function mkAnswer(req, ips) {
  return dns.buildResponse(req, { ips, ttl: 60 });
}

const UP_PORT = 15353;
const PROXY_PORT = 15354;
const GW = '127.0.0.1';

function startFakeResolver({ silent = false, ips = ['157.240.1.10'] } = {}) {
  const sock = dgram.createSocket('udp4');
  const seen = [];
  sock.on('message', (msg, rinfo) => {
    seen.push(msg);
    if (silent) return;
    sock.send(mkAnswer(msg, ips), rinfo.port, rinfo.address, () => {});
  });
  return new Promise(res => sock.bind(UP_PORT, GW, () => res({ sock, seen })));
}

function ask(buf, { timeout = 2500 } = {}) {
  return new Promise((resolve, reject) => {
    const c = dgram.createSocket('udp4');
    const timer = setTimeout(() => { c.close(); reject(new Error('sin respuesta del portal')); }, timeout);
    c.on('message', m => { clearTimeout(timer); c.close(); resolve(m); });
    c.on('error', e => { clearTimeout(timer); c.close(); reject(e); });
    c.send(buf, PROXY_PORT, GW);
  });
}

async function withProxy(opts, fn) {
  const allow = new Allowlist({ max: 64, cachePath: '', log: () => {} });
  const proxy = new DnsProxy(Object.assign({
    port: PROXY_PORT,
    bindAddr: GW,
    gw: '192.168.174.95',
    resolvers: [GW],
    upPort: UP_PORT,
    timeoutMs: 600,
    allowDomains: ['whatsapp.net'],
    connDomains: ['captive.apple.com'],
    blockIpv6: true,
    snoop: true,
    allowlist: allow,
    isAuthed: () => false,
    log: () => {},
  }, opts));
  await proxy.start();
  try { await fn(proxy, allow); } finally { proxy.stop(); }
}

(async () => {
  /* --- reenvio y aprendizaje --- */
  {
    const up = await startFakeResolver({ ips: ['157.240.1.10', '157.240.1.11'] });
    await withProxy({}, async (proxy, allow) => {
      await t('un dominio permitido se reenvia y se responde al cliente', async () => {
        const res = await ask(mkQuery('api.whatsapp.net', 1, 0xaa01));
        const m = dns.parseMessage(res);
        assert.strictEqual(m.id, 0xaa01, 'el id del cliente se conserva');
        assert.deepStrictEqual(m.an.map(a => a.ip), ['157.240.1.10', '157.240.1.11']);
      });

      await t('las IPs de la respuesta entran en la allowlist', async () => {
        assert.ok(allow.all().includes('157.240.1.10/32'), `allowlist: ${allow.all()}`);
        assert.ok(allow.all().includes('157.240.1.11/32'));
      });

      await t('un dominio de comprobacion de conectividad tambien se reenvia', async () => {
        const res = await ask(mkQuery('captive.apple.com', 1, 0xaa02));
        assert.ok(dns.parseMessage(res).an.length > 0);
      });
    });
    up.sock.close();
  }

  /* --- hijack, NXDOMAIN y NODATA --- */
  {
    const up = await startFakeResolver();
    await withProxy({}, async () => {
      await t('sin autenticar, un dominio no permitido apunta al portal', async () => {
        const res = await ask(mkQuery('instagram.com', 1, 0xbb01));
        const m = dns.parseMessage(res);
        assert.deepStrictEqual(m.an.map(a => a.ip), ['192.168.174.95']);
      });
      await t('la consulta no permitida no se reenvia al resolver', async () => {
        assert.strictEqual(up.seen.length, 0, `se reenviaron ${up.seen.length}`);
      });
    });

    await withProxy({ isAuthed: () => true }, async () => {
      await t('ya autenticado, un dominio no permitido da NXDOMAIN', async () => {
        const res = await ask(mkQuery('instagram.com', 1, 0xbb02));
        const m = dns.parseMessage(res);
        assert.strictEqual(m.flags & 0x0F, dns.RCODE.NXDOMAIN);
        assert.strictEqual(m.an.length, 0);
      });
    });

    await withProxy({}, async () => {
      await t('AAAA de un dominio permitido da NODATA (el muro es solo IPv4)', async () => {
        const res = await ask(mkQuery('whatsapp.net', 28, 0xbb03));
        const m = dns.parseMessage(res);
        assert.strictEqual(m.flags & 0x0F, dns.RCODE.OK);
        assert.strictEqual(m.an.length, 0);
        assert.strictEqual(m.qd[0].type, 28);
      });
      await t('HTTPS (65) de un dominio no permitido da NODATA, no un registro A', async () => {
        const res = await ask(mkQuery('instagram.com', 65, 0xbb04));
        const m = dns.parseMessage(res);
        assert.strictEqual(m.an.length, 0);
      });
    });
    up.sock.close();
  }

  /* --- fallos del upstream --- */
  {
    const up = await startFakeResolver({ silent: true });
    await withProxy({}, async () => {
      await t('si el resolver no contesta se devuelve SERVFAIL, no silencio', async () => {
        const res = await ask(mkQuery('whatsapp.net', 1, 0xcc01), { timeout: 3000 });
        assert.strictEqual(dns.parseMessage(res).flags & 0x0F, dns.RCODE.SERVFAIL);
      });
    });
    up.sock.close();
  }

  /* --- respuestas que no hay que creer --- */
  {
    const sock = dgram.createSocket('udp4');
    await new Promise(r => sock.bind(UP_PORT, GW, r));
    sock.on('message', (msg, rinfo) => {
      /* Mismo id, pero contestando por otro nombre. */
      const fake = dns.buildResponse(mkQuery('otra-cosa.example', 1, msg.readUInt16BE(0)), { ips: ['1.2.3.4'] });
      sock.send(fake, rinfo.port, rinfo.address, () => {});
    });
    await withProxy({}, async (proxy, allow) => {
      await t('una respuesta cuya pregunta no coincide se descarta (acaba en SERVFAIL)', async () => {
        const res = await ask(mkQuery('whatsapp.net', 1, 0xdd01), { timeout: 3000 });
        assert.strictEqual(dns.parseMessage(res).flags & 0x0F, dns.RCODE.SERVFAIL);
      });
      await t('y esa IP no entra en la allowlist', async () => {
        assert.ok(!allow.all().includes('1.2.3.4/32'), `allowlist: ${allow.all()}`);
      });
    });
    sock.close();
  }

  /* --- limite por cliente --- */
  {
    const up = await startFakeResolver({ silent: true });
    await withProxy({ timeoutMs: 1500 }, async (proxy) => {
      await t('un cliente que inunda recibe SERVFAIL en vez de tumbar el servicio', async () => {
        const tries = [];
        for (let i = 0; i < 24; i++) tries.push(ask(mkQuery(`n${i}.whatsapp.net`, 1, 0xe000 + i), { timeout: 2500 }).catch(() => null));
        const got = (await Promise.all(tries)).filter(Boolean);
        const servfail = got.filter(r => (dns.parseMessage(r).flags & 0x0F) === dns.RCODE.SERVFAIL);
        assert.ok(servfail.length >= 8, `solo ${servfail.length} SERVFAIL de ${got.length} respuestas`);
        assert.ok(proxy.pending.size <= 16, `en vuelo: ${proxy.pending.size}`);
      });
    });
    up.sock.close();
  }

  /* --- nombres peligrosos --- */
  await t('un nombre DNS con payload no se guarda ni se muestra', () => {
    assert.strictEqual(safeName('<img src=x onerror=alert(1)>'), false);
    assert.strictEqual(safeName('a"b.com'), false);
    assert.strictEqual(safeName('api.whatsapp.net'), true);
    assert.strictEqual(safeName('_dns.resolver.arpa'), true);
  });

  /* --- allowlist --- */
  await t('un /32 contenido en un /24 ya permitido no anade regla', async () => {
    const a = new Allowlist({ widen: [], max: 10, cachePath: '', staticRanges: ['57.144.1.0/24'], log: () => {} });
    assert.strictEqual(await a.learn('57.144.1.9', 'test'), false);
    assert.strictEqual(a.learned.size, 0);
  });

  await t('al llegar al tope se expulsa el mas antiguo', async () => {
    const a = new Allowlist({ max: 2, cachePath: '', log: () => {} });
    await a.learn('1.1.1.1', 'a');
    await new Promise(r => setTimeout(r, 5));
    await a.learn('2.2.2.2', 'b');
    await new Promise(r => setTimeout(r, 5));
    await a.learn('3.3.3.3', 'c');
    assert.strictEqual(a.learned.size, 2);
    assert.ok(!a.all().includes('1.1.1.1/32'), 'deberia haber caido la primera');
    assert.ok(a.all().includes('3.3.3.3/32'));
  });

  await t('los CIDR caducados se barren', async () => {
    const a = new Allowlist({ max: 10, ttlMs: 20, cachePath: '', log: () => {} });
    await a.learn('8.8.8.8', 'x');
    await new Promise(r => setTimeout(r, 40));
    assert.strictEqual(a.sweep(), 1);
    assert.strictEqual(a.learned.size, 0);
  });

  await t('el widen agrupa al prefijo declarado', async () => {
    const { parseWiden } = require('../lib/config');
    const a = new Allowlist({ widen: [parseWiden('57.144.0.0/14:24')], max: 10, cachePath: '', log: () => {} });
    await a.learn('57.144.103.7', 'x');
    assert.deepStrictEqual(a.all(), ['57.144.103.0/24']);
  });

  console.log(results.join('\n'));
  console.log(`\n${pass} ok, ${fail} fallos\n`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
