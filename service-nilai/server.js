const app = require('./app');
const config = require('../shared/config');

const server = app.listen(config.portNilai, () => {
  console.log(`[SERVICE-NILAI] Berjalan pada port ${config.portNilai}`);
  console.log(`[SERVICE-NILAI] Health check: http://localhost:${config.portNilai}/health`);
});

process.on('SIGTERM', () => {
  console.log('[SERVICE-NILAI] Menerima SIGTERM, menutup server...');
  server.close(() => process.exit(0));
});

module.exports = server;

