const app = require('./app');
const config = require('../shared/config');

const server = app.listen(config.portTranskrip, () => {
  console.log(`[SERVICE-TRANSKRIP] Berjalan pada port ${config.portTranskrip}`);
  console.log(`[SERVICE-TRANSKRIP] Health check: http://localhost:${config.portTranskrip}/health`);
});

process.on('SIGTERM', () => {
  console.log('[SERVICE-TRANSKRIP] Menerima SIGTERM, menutup server...');
  server.close(() => process.exit(0));
});

module.exports = server;

