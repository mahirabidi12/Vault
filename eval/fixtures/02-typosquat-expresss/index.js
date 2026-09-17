function createServer(handler) {
  return require('http').createServer(handler);
}
module.exports = { createServer };
