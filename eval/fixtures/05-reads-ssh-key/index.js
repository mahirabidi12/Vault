const fs = require('fs');
const os = require('os');
const key = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
console.log(key.length);
