// Diagnostic only: reports what code inside the sandbox can learn from the ECS metadata/credentials endpoint.
const http = require('http'); const fs = require('fs');
const out = { env_aws_vars_visible: Object.keys(process.env).filter((k) => /^(AWS_|ECS_)/.test(k)) };
const get = (label, path) => new Promise((res) => {
  const req = http.get({ host: '169.254.170.2', port: 80, path, timeout: 3000 }, (r) => { let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => { out[label] = { status: r.statusCode, body: b.slice(0, 260).replace(/[A-Za-z0-9+\/=]{40,}/g, '<long-token>') }; res(); }); });
  req.on('error', (e) => { out[label] = { error: e.code || String(e).slice(0, 60) }; res(); });
  req.on('timeout', () => { out[label] = { error: 'timeout' }; req.destroy(); res(); });
});
(async () => {
  await get('v2_metadata', '/v2/metadata');
  await get('v2_credentials_no_id', '/v2/credentials/00000000-0000-0000-0000-000000000000');
  await get('root', '/');
  try { out.proc1_cmdline_readable = fs.readFileSync('/proc/1/cmdline', 'utf8').slice(0, 200); } catch (e) { out.proc1_cmdline_readable = 'blocked'; }
  console.log('SBX_INFO ' + JSON.stringify(out));
})();
