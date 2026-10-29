const app = require('./app');
const config = require('../shared/config');

const server = app.listen(config.portGateway, () => {
  console.log(`[API-GATEWAY] PEP berjalan pada port ${config.portGateway}`);
  console.log(`[API-GATEWAY] Health check: http://localhost:${config.portGateway}/health`);
});

process.on('SIGTERM', () => {
  console.log('[API-GATEWAY] Menerima SIGTERM, menutup server...');
  server.close(() => process.exit(0));
});

module.exports = server;
