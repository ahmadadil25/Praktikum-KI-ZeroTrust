const express = require('express');
const config = require('../shared/config');
const {
  handleLogin,
  handleRefresh,
  handleLogout,
  handleServiceToken,
} = require('./auth.controller');
const { enforcePolicy } = require('./pep.middleware');
const { createServiceProxy } = require('./proxy');

const app = express();

app.use(express.json());

// 1. Health Check Endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'api-gateway',
    role: 'Policy Enforcement Point (PEP)',
    port: config.portGateway,
    timestamp: new Date().toISOString(),
  });
});

// 2. Authentication & Token Management Endpoints (Public via Gateway)
app.post('/auth/login', handleLogin);
app.post('/auth/refresh', handleRefresh);
app.post('/auth/logout', handleLogout);
app.post('/auth/service', handleServiceToken);

// 3. Protected Business Endpoints (Subject to PEP Policy Enforcement & Proxy)
// Service Nilai (port 3001)
app.use(
  ['/nilai', '/kelas'],
  enforcePolicy,
  createServiceProxy(config.serviceNilaiUrl)
);

// Service Transkrip (port 3002)
app.use(
  '/transkrip',
  enforcePolicy,
  createServiceProxy(config.serviceTranskripUrl)
);

// Rute umum root
app.get('/', (req, res) => {
  res.status(200).json({
    name: 'Zero Trust API Gateway (PEP)',
    description: 'NIST SP 800-207 Policy Enforcement Point for Sistem Nilai',
    version: '1.0.0',
    endpoints: {
      auth: ['POST /auth/login', 'POST /auth/refresh', 'POST /auth/logout', 'POST /auth/service'],
      nilai: ['GET /nilai', 'GET /nilai/:id', 'PUT /nilai/:id', 'POST /kelas/:id/finalisasi'],
      transkrip: ['GET /transkrip/:nim', 'POST /transkrip/sinkron'],
    },
  });
});

// 4. Centralized Error Handler (tanpa membocorkan stack trace ke client)
app.use((err, req, res, next) => {
  console.error('[GATEWAY ERROR]', err.message);
  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    reason: 'Terjadi kesalahan internal pada API Gateway',
  });
});

module.exports = app;
