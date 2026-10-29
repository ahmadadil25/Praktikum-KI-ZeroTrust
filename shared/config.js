const path = require('path');
const dotenv = require('dotenv');

// Load environment variables dari file .env di root proyek
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const config = {
  env: process.env.NODE_ENV || 'development',

  // Ports
  portGateway: parseInt(process.env.PORT_GATEWAY, 10) || 3000,
  portNilai: parseInt(process.env.PORT_NILAI, 10) || 3001,
  portTranskrip: parseInt(process.env.PORT_TRANSKRIP, 10) || 3002,

  // Service URLs
  serviceNilaiUrl: process.env.SERVICE_NILAI_URL || 'http://localhost:3001',
  serviceTranskripUrl: process.env.SERVICE_TRANSKRIP_URL || 'http://localhost:3002',
  gatewayUrl: process.env.GATEWAY_URL || 'http://localhost:3000',

  // JWT Configuration
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || '[REDACTED-SECRET]',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '10m',
    refreshSecret: process.env.JWT_REFRESH_SECRET || '[REDACTED-SECRET]',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '1d',
    serviceSecret: process.env.JWT_SERVICE_SECRET || '[REDACTED-SECRET]',
    serviceExpiresIn: process.env.JWT_SERVICE_EXPIRES_IN || '5m',
  },

  // Gateway Shared Secret (PEP to internal Resource Services)
  gatewaySecret: process.env.GATEWAY_SECRET || '[REDACTED-SECRET]',

  // Service Client Credentials (for Service Nilai -> Gateway /auth/service)
  serviceAuth: {
    clientId: process.env.SERVICE_CLIENT_ID || 'service-nilai-client',
    clientSecret: process.env.SERVICE_CLIENT_SECRET || '[REDACTED-SECRET]',
  },

  // Database Path (resolved to absolute path)
  dbPath: path.resolve(__dirname, '..', process.env.DB_PATH || './data/database.sqlite'),

  // Access Policy Time Window
  accessHours: {
    start: parseInt(process.env.ACCESS_HOURS_START, 10) || 7,
    end: parseInt(process.env.ACCESS_HOURS_END, 10) || 21,
    timezone: process.env.ACCESS_TIMEZONE || 'Asia/Jakarta',
  },
};

// Validasi keamanan: peringatan jika kunci secret menggunakan nilai default di lingkungan produksi
if (process.env.NODE_ENV === 'production') {
  if (config.jwt.accessSecret.includes('default') || config.gatewaySecret.includes('default')) {
    console.warn('[SECURITY WARNING] Kunci secret default terdeteksi pada mode produksi! Harap atur environment variables yang aman.');
  }
}

module.exports = config;

