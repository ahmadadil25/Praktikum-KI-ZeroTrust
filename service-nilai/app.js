const express = require('express');
const config = require('../shared/config');

const app = express();

app.use(express.json());

// Endpoint Health Check untuk Service Nilai
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'service-nilai',
    role: 'Resource Service (Nilai & Kelas)',
    port: config.portNilai,
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (req, res) => {
  res.status(200).json({
    name: 'Service Nilai',
    description: 'Resource Service untuk pengelolaan nilai dan kelas',
    version: '1.0.0',
    healthCheck: '/health',
  });
});

module.exports = app;
