'use strict';
// Preloaded into every node process in the sandbox (NODE_OPTIONS=--require). Records what the code does
// as JSON lines. Best effort: code running in the same process can tamper with it, so the authoritative
// records are strace and the fake-network logs. This layer's job is readable detail and, above all,
// the decoded source that reaches eval / Function / vm.
(function () {
  const LOG = process.env.SBX_HOOK_LOG;
  if (!LOG) return;
  const fs = require('fs');
  const crypto = require('crypto');
  const appendFileSync = fs.appendFileSync.bind(fs);
  const now = Date.now.bind(Date);
  const OFF = (process.env.SBX_OFF || '').split(',');
  const MAX_EVENTS = 20000;
  let count = 0;

  function clip(v, n) {
    try {
      const s = typeof v === 'string' ? v : Buffer.isBuffer(v) ? v.toString('utf8') : String(v);
      return s.length > n ? s.slice(0, n) + '…[+' + (s.length - n) + ']' : s;
    } catch (e) { return ''; }
  }
  function emit(type, data) {
    try {
      if (count >= MAX_EVENTS) return;
      count++;
      appendFileSync(LOG, JSON.stringify(Object.assign({ t: now(), pid: process.pid, ppid: process.ppid, type }, data)) + '\n');
      if (count === MAX_EVENTS) appendFileSync(LOG, JSON.stringify({ type: 'truncated', pid: process.pid }) + '\n');
    } catch (e) { /* never break the package's own flow */ }
  }
  function wrap(obj, name, make) {
    try {
      const orig = obj[name];
      if (typeof orig === 'function') obj[name] = make(orig);
    } catch (e) { /* ignore */ }
  }
  function caller() {
    try { return new Error().stack.split('\n').slice(3, 5).map((s) => s.trim()).join(' | '); } catch (e) { return ''; }
  }

  emit('start', { argv: process.argv.slice(0, 6).map((a) => clip(a, 200)), cwd: process.cwd() });
  process.on('exit', (code) => emit('exit', { code }));

  // --- child processes
  const cp = require('child_process');
  for (const n of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
    wrap(cp, n, (orig) => function (...args) {
      emit('spawn', {
        api: n,
        cmd: clip(args[0], 1500),
        args: Array.isArray(args[1]) ? args[1].slice(0, 25).map((a) => clip(a, 300)) : undefined,
        at: caller(),
      });
      return orig.apply(this, args);
    });
  }

  // --- network
  const net = require('net');
  wrap(net.Socket.prototype, 'connect', (orig) => function (...args) {
    try {
      const o = args[0];
      let host, port, sockPath;
      if (o && typeof o === 'object') { host = o.host; port = o.port; sockPath = o.path; }
      else if (typeof o === 'number' || (typeof o === 'string' && /^\d+$/.test(o))) { port = +o; host = typeof args[1] === 'string' ? args[1] : 'localhost'; }
      else if (typeof o === 'string') sockPath = o;
      emit('connect', { host, port, path: sockPath, at: caller() });
    } catch (e) { /* ignore */ }
    return orig.apply(this, args);
  });

  function describeRequest(args, defaultProto) {
    let url, opts = {};
    const a0 = args[0];
    if (typeof a0 === 'string') { url = a0; if (args[1] && typeof args[1] === 'object') opts = args[1]; }
    else if (a0 && typeof a0.href === 'string') { url = a0.href; if (args[1] && typeof args[1] === 'object') opts = args[1]; }
    else if (a0 && typeof a0 === 'object') opts = a0;
    if (!url) url = (opts.protocol || defaultProto) + '//' + (opts.hostname || opts.host || 'localhost') + (opts.port ? ':' + opts.port : '') + (opts.path || '/');
    return { url: clip(url, 1500), method: opts.method || 'GET', headers: opts.headers ? clip(JSON.stringify(opts.headers), 800) : undefined };
  }
  const http = require('http');
  const https = require('https');
  for (const [mod, proto] of [[http, 'http:'], [https, 'https:']]) {
    for (const n of ['request', 'get']) {
      wrap(mod, n, (orig) => function (...args) {
        const info = describeRequest(args, proto);
        const req = orig.apply(this, args);
        try {
          const chunks = []; let size = 0;
          const cap = (c) => { if (c && typeof c !== 'function' && size < 32768) { const b = Buffer.isBuffer(c) ? c : Buffer.from(String(c)); chunks.push(b); size += b.length; } };
          const ow = req.write.bind(req), oe = req.end.bind(req);
          req.write = function (c, ...r) { cap(c); return ow(c, ...r); };
          req.end = function (c, ...r) {
            cap(c);
            emit('http', Object.assign({ at: caller(), body: clip(Buffer.concat(chunks).toString('utf8'), 32768) }, info));
            return oe(c, ...r);
          };
        } catch (e) { /* ignore */ }
        return req;
      });
    }
  }
  if (typeof globalThis.fetch === 'function') {
    wrap(globalThis, 'fetch', (orig) => function (input, init) {
      try {
        const url = typeof input === 'string' ? input : input && input.url ? input.url : String(input);
        const body = init && init.body != null ? clip(init.body, 32768) : undefined;
        emit('http', { url: clip(url, 1500), method: (init && init.method) || 'GET', body, via: 'fetch', at: caller() });
      } catch (e) { /* ignore */ }
      return orig.apply(this, arguments);
    });
  }
  const dns = require('dns');
  for (const n of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveMx', 'resolveAny', 'reverse']) {
    wrap(dns, n, (orig) => function (...args) { emit('dns', { api: n, host: clip(args[0], 300) }); return orig.apply(this, args); });
    if (dns.promises) wrap(dns.promises, n, (orig) => function (...args) { emit('dns', { api: 'promises.' + n, host: clip(args[0], 300) }); return orig.apply(this, args); });
  }
  try {
    const dgram = require('dgram');
    wrap(dgram.Socket.prototype, 'send', (orig) => function (...args) {
      const numeric = typeof args[1] === 'number' && typeof args[2] === 'number';
      emit('udp', { port: numeric ? args[3] : args[1], address: numeric ? args[4] : args[2], data: clip(args[0], 500) });
      return orig.apply(this, args);
    });
  } catch (e) { /* ignore */ }

  // --- environment
  if (!OFF.includes('env')) try {
    const seen = new Set();
    const real = process.env;
    process.env = new Proxy(real, {
      get(t, k) {
        if (typeof k === 'string' && !seen.has(k) && !/^(PATH|HOME|PWD|SHELL|LANG|TERM|USER|NODE_OPTIONS|SBX_.*|npm_.*|INIT_CWD|_)$/.test(k)) { seen.add(k); emit('env', { op: 'get', key: k }); }
        return t[k];
      },
      set(t, k, v) { t[k] = v; return true; },
      has(t, k) { return k in t; },
      deleteProperty(t, k) { return delete t[k]; },
      getOwnPropertyDescriptor(t, k) { return Reflect.getOwnPropertyDescriptor(t, k); },
      defineProperty(t, k, d) { return Reflect.defineProperty(t, k, d); },
      ownKeys(t) { emit('env', { op: 'dump', at: caller() }); return Reflect.ownKeys(t); },
    });
  } catch (e) { /* ignore */ }

  // --- machine recon (and, in the "hostile" run, fake identity)
  const os = require('os');
  const fakeHost = process.env.SBX_FAKE_HOSTNAME, fakeUser = process.env.SBX_FAKE_USER;
  for (const n of ['hostname', 'userInfo', 'networkInterfaces', 'cpus', 'platform', 'release', 'arch']) {
    wrap(os, n, (orig) => function (...args) {
      emit('recon', { api: 'os.' + n });
      if (n === 'hostname' && fakeHost) return fakeHost;
      const out = orig.apply(this, args);
      if (n === 'userInfo' && fakeUser && out) return Object.assign({}, out, { username: fakeUser });
      return out;
    });
  }

  // --- probes that check whether we are in a container / VM
  const PROBE = /\.dockerenv|\/proc\/(1|self)\/cgroup|\/sys\/class\/dmi|\/proc\/(cpuinfo|version)|virtualbox|vmware|qemu|hypervisor/i;
  for (const n of ['existsSync', 'statSync', 'lstatSync', 'accessSync', 'readFileSync', 'readFile', 'openSync']) {
    wrap(fs, n, (orig) => function (...args) {
      try { if (typeof args[0] === 'string' && PROBE.test(args[0])) emit('probe', { api: 'fs.' + n, path: args[0] }); } catch (e) { /* ignore */ }
      return orig.apply(this, args);
    });
  }

  // --- dynamic code: log the decoded source, then run it
  function emitCode(api, code) {
    try {
      const s = clip(code, 200000);
      emit('eval', { api, length: String(code).length, sha256: crypto.createHash('sha256').update(String(code)).digest('hex'), code: clip(s, 4000), at: caller() });
    } catch (e) { /* ignore */ }
  }
  if (!OFF.includes('eval')) try {
    const origEval = globalThis.eval;
    // Replacing eval makes every call an indirect (global-scope) eval. Give the code the module helpers a
    // direct eval would have had, based on the calling file, so malware that uses require() still runs.
    const Mod = require('module');
    globalThis.eval = function (x) {
      if (typeof x === 'string') {
        emitCode('eval', x);
        try {
          const m = (new Error().stack.split('\n')[2] || '').match(/\(?(\/[^():]+):\d+:\d+\)?$/);
          if (m) { globalThis.require = Mod.createRequire(m[1]); globalThis.__filename = m[1]; globalThis.__dirname = require('path').dirname(m[1]); }
        } catch (e) { /* ignore */ }
      }
      return origEval(x);
    };
  } catch (e) { /* ignore */ }
  if (!OFF.includes('function')) try {
    const OrigFunction = Function;
    const Wrapped = new Proxy(OrigFunction, {
      apply(t, th, args) { emitCode('Function', args.map(String).join('\n')); return Reflect.apply(t, th, args); },
      construct(t, args, nt) { emitCode('Function', args.map(String).join('\n')); return Reflect.construct(t, args, nt); },
    });
    globalThis.Function = Wrapped;
    Object.defineProperty(OrigFunction.prototype, 'constructor', { value: Wrapped, writable: true, configurable: true });
  } catch (e) { /* ignore */ }
  if (!OFF.includes('vm')) try {
    const vm = require('vm');
    for (const n of ['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction']) {
      wrap(vm, n, (orig) => function (...args) { emitCode('vm.' + n, args[0]); return orig.apply(this, args); });
    }
    const OrigScript = vm.Script;
    vm.Script = class extends OrigScript { constructor(code, ...rest) { emitCode('vm.Script', code); super(code, ...rest); } };
  } catch (e) { /* ignore */ }
  if (!OFF.includes('module')) try {
    const Module = require('module');
    wrap(Module.prototype, '_compile', (orig) => function (content, filename) {
      try { if (typeof filename === 'string' && !fs.existsSync(filename)) emitCode('module._compile', content); } catch (e) { /* ignore */ }
      return orig.apply(this, arguments);
    });
  } catch (e) { /* ignore */ }
})();
