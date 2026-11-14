'use strict';

const { exec, spawn } = require('child_process');
const fs = require('fs');

const SU_CANDIDATES = [
  '/data/data/com.termux/files/usr/bin/su',
  '/debug_ramdisk/su',
  '/system/bin/su',
  '/system/xbin/su',
  '/sbin/su',
];

let suPath = null;
function findSu() {
  if (suPath !== null) return suPath;
  suPath = SU_CANDIDATES.find(p => { try { return fs.existsSync(p); } catch (_) { return false; } }) || '';
  return suPath;
}

function sh(cmd, { timeout = 8000 } = {}) {
  return new Promise(resolve => {
    exec(cmd, { timeout, maxBuffer: 4 << 20 }, (e, out, err) => {
      resolve({ code: e ? (e.code === undefined ? 1 : e.code) : 0, out: String(out || ''), err: String(err || '') });
    });
  });
}

/* su -c no admite encadenar varios comandos en este entorno, y anidar comillas
 * dentro de su -c "..." es la via por la que un valor de .env se convierte en
 * inyeccion de shell. Se pasa el script por stdin a un solo su: sin comillas
 * que escapar y una sola invocacion para todo el lote. */
function suScript(script, { timeout = 30000 } = {}) {
  const su = findSu();
  if (!su) return Promise.resolve({ code: 127, out: '', err: 'no se encontro el binario su' });
  return new Promise(resolve => {
    let done = false;
    let out = '', err = '';
    let proc;
    try {
      proc = spawn(su, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (e) {
      return resolve({ code: 127, out: '', err: e.message });
    }
    const finish = code => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ code, out, err });
    };
    const timer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch (_) {}
      finish(124);
    }, timeout);
    proc.stdout.on('data', d => { out += d; });
    proc.stderr.on('data', d => { err += d; });
    proc.on('error', e => { err += e.message; finish(127); });
    proc.on('close', code => finish(code === null ? 1 : code));
    try {
      proc.stdin.write(script.endsWith('\n') ? script : script + '\n');
      proc.stdin.end();
    } catch (e) {
      err += e.message;
      finish(1);
    }
  });
}

async function hasRoot() {
  const r = await suScript('id -u', { timeout: 10000 });
  return r.code === 0 && r.out.trim().startsWith('0');
}

module.exports = { sh, suScript, hasRoot, findSu };
