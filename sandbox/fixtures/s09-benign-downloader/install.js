const https = require('https');
https.get('https://registry.npmjs.org/@sbx/linux-arm64/-/linux-arm64-1.0.0.tgz', (res) => { res.resume(); }).on('error', () => {});
