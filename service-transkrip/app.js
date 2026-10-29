const express = require('express');
const config = require('../shared/config');

const app = express();

app.use(express.json());

// Endpoint Health Check untuk Service Transkrip
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'service-transkrip',
    role: 'Resource Service (Transkrip Akademik)',
    port: config.portTranskrip,
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (req, res) => {
  res.status(200).json({
    name: 'Service Transkrip',
    description: 'Resource Service untuk transkrip akademik mahasiswa',
    version: '1.0.0',
    healthCheck: '/health',
  });
});

module.exports = app;
