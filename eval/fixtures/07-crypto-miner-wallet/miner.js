const net = require('net');
const wallet = '41te8PA3sT4iBAdN7kAG9pMEK7wnbY5U5ktYd7VqfaC96fBKq5R';
const socket = net.connect(3333, 'pool.example.invalid');
socket.write(JSON.stringify({ id: 1, method: 'login', params: { login: wallet, pass: 'x' } }));
