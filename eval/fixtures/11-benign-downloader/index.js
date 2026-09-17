const https = require('https');
function download(url, destStream) {
  https.get(url, (res) => res.pipe(destStream));
}
module.exports = { download };
