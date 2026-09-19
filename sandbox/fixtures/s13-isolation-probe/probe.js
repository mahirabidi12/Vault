// Tries to break out. EVERY check must report "blocked". Results go to stdout as JSON.
const fs = require('fs'); const net = require('net'); const dgram = require('dgram'); const cp = require('child_process');
const results = {}; const pending = [];
const tcp = (label, host, port) => pending.push(new Promise((res) => { const s = net.connect({ host, port, timeout: 2000 }, () => { results[label] = 'REACHED'; s.destroy(); res(); }); s.on('error', () => { results[label] = 'blocked'; res(); }); s.on('timeout', () => { results[label] = 'blocked'; s.destroy(); res(); }); }));
tcp('internet_1.1.1.1:443', '1.1.1.1', 443); tcp('internet_8.8.8.8:53', '8.8.8.8', 53);
tcp('imds_169.254.169.254:80', '169.254.169.254', 80);
const u = dgram.createSocket('udp4'); pending.push(new Promise((res) => { const t = setTimeout(() => { results['dns_8.8.8.8:53_udp'] = 'blocked'; try { u.close(); } catch (e) {} res(); }, 2000); u.on('message', () => { results['dns_8.8.8.8:53_udp'] = 'REACHED'; clearTimeout(t); res(); }); u.on('error', () => { results['dns_8.8.8.8:53_udp'] = 'blocked'; clearTimeout(t); res(); }); u.send(Buffer.from('000001000001000000000000076578616d706c6503636f6d0000010001', 'hex'), 53, '8.8.8.8'); }));

// The VPC's own DNS resolvers recurse to the real internet unless DNS Firewall stops them. Any real answer is a leak path.
for (const resolver of ['10.42.0.2', '169.254.169.253']) {
  const label = 'vpc_resolver_' + resolver + '_real_domain';
  const sock = dgram.createSocket('udp4');
  pending.push(new Promise((res) => {
    const t = setTimeout(() => { results[label] = 'blocked'; try { sock.close(); } catch (e) {} res(); }, 3000);
    sock.on('message', (msg) => { results[label] = msg.length > 7 && (msg[6] << 8 | msg[7]) > 0 ? 'REACHED' : 'blocked'; clearTimeout(t); try { sock.close(); } catch (e) {} res(); });
    sock.on('error', () => { results[label] = 'blocked'; clearTimeout(t); res(); });
    sock.send(Buffer.from('123401000001000000000000076578616d706c6503636f6d0000010001', 'hex'), 53, resolver);
  }));
}

// The ECS task metadata endpoint is reachable from every Fargate task and cannot be blocked from inside. What matters
// is that no AWS credentials can be obtained through it. The task has no IAM role, so any credentials request must fail.
pending.push(new Promise((res) => {
  const req = require('http').get({ host: '169.254.170.2', port: 80, path: '/v2/credentials/00000000-0000-0000-0000-000000000000', timeout: 3000 }, (r) => {
    let body = ''; r.on('data', (c) => (body += c)); r.on('end', () => { results['ecs_credentials_obtainable'] = /AccessKeyId|SecretAccessKey/.test(body) ? 'REACHED' : 'blocked'; results['info_ecs_metadata_endpoint_http_status'] = r.statusCode; res(); });
  });
  req.on('error', () => { results['ecs_credentials_obtainable'] = 'blocked'; res(); });
  req.on('timeout', () => { req.destroy(); results['ecs_credentials_obtainable'] = 'blocked'; res(); });
}));
if (Object.keys(process.env).some((k) => /^AWS_CONTAINER_CREDENTIALS|^AWS_SESSION_TOKEN$/.test(k))) results['aws_credential_env_visible'] = 'REACHED'; else results['aws_credential_env_visible'] = 'blocked';
const tryFs = (label, fn) => { try { fn(); results[label] = 'ALLOWED'; } catch (e) { results[label] = 'blocked'; } };
tryFs('write_/usr/bin/x', () => fs.writeFileSync('/usr/bin/sbx-x', 'x'));
tryFs('write_/etc/passwd', () => fs.appendFileSync('/etc/passwd', 'x'));
tryFs('write_/opt/sbx/hook.js', () => fs.appendFileSync('/opt/sbx/hook.js', '//x'));
tryFs('read_/opt/sbx/ca.key', () => fs.readFileSync('/opt/sbx/ca.key'));
tryFs('read_/proc/1/environ', () => { const e = fs.readFileSync('/proc/1/environ', 'utf8'); if (/AWS_CONTAINER|SBX_/.test(e) === false && e.length === 0) throw new Error('empty'); if (e.length === 0) throw new Error('empty'); });
tryFs('read_supervisor_cmdline_has_bucket', () => { if (!/pkgguard-reportsbucket|s3:\/\//.test(fs.readFileSync('/proc/1/cmdline', 'utf8'))) throw new Error('nothing'); });
tryFs('read_supervisor_strace_log', () => fs.readFileSync('/var/sbx/strace-install.txt'));
tryFs('list_supervisor_state', () => { if (fs.readdirSync('/var/sbx').length === 0) throw new Error('empty'); });
const sh = (label, cmd) => { try { cp.execSync(cmd, { stdio: 'ignore', timeout: 3000 }); results[label] = 'ALLOWED'; } catch (e) { results[label] = 'blocked'; } };
sh('setuid_root', 'su -c id root </dev/null'); sh('mount_tmpfs', 'mount -t tmpfs none /mnt'); sh('kill_pid1', 'kill -9 1'); sh('chown_root', 'chown root /tmp');
tryFs('env_has_aws_creds', () => { if (Object.keys(process.env).some((k) => /^AWS_(CONTAINER|SESSION|ACCESS)/.test(k) && !/^AWS_ACCESS_KEY_ID$|^AWS_SECRET_ACCESS_KEY$/.test(k))) return; throw new Error('none'); });
Promise.all(pending).then(() => { console.log('SBX_PROBE ' + JSON.stringify(results)); });
