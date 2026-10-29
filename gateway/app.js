const express = require('express');
const config = require('../shared/config');

const app = express();

app.use(express.json());

// Endpoint Health Check untuk API Gateway (PEP)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'api-gateway',
    role: 'Policy Enforcement Point (PEP)',
    port: config.portGateway,
    timestamp: new Date().toISOString(),
  });
});

// Placeholder rute untuk tahap selanjutnya (Auth, Nilai, Transkrip proxy)
app.get('/', (req, res) => {
  res.status(200).json({
    name: 'Zero Trust API Gateway (PEP)',
    description: 'NIST SP 800-207 Policy Enforcement Point for Sistem Nilai',
    version: '1.0.0',
    healthCheck: '/health',
  });
});

module.exports = app;
