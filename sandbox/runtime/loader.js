'use strict';
// Loads an installed package the way a user's code would, and reports whether that worked.
const name = process.argv[2];
const out = { loaded: false };
try {
  const m = require(require.resolve(name, { paths: [process.cwd()] }));
  out.loaded = true;
  out.exportType = typeof m;
  out.exportKeys = m && typeof m === 'object' ? Object.keys(m).length : undefined;
} catch (e) {
  out.error = String((e && e.message) || e).slice(0, 300);
  out.code = e && e.code;
}
process.stdout.write('\nSBX_LOAD ' + JSON.stringify(out) + '\n');
