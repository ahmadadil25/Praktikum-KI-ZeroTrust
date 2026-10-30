const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const dotenv = require('dotenv');

// Load environment variables dari file .env di root proyek
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const env = process.env.NODE_ENV || 'development';
const isProduction = env === 'production';
const localSecretsPath = path.resolve(__dirname, '../.local-secrets.json');

function loadLocalSecrets() {
  try {
    return JSON.parse(fs.readFileSync(localSecretsPath, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const secrets = {
    JWT_ACCESS_SECRET: crypto.randomBytes(32).toString('hex'),
    JWT_REFRESH_SECRET: crypto.randomBytes(32).toString('hex'),
    JWT_SERVICE_SECRET: crypto.randomBytes(32).toString('hex'),
    GATEWAY_SECRET: crypto.randomBytes(32).toString('hex'),
    SERVICE_CLIENT_SECRET: crypto.randomBytes(32).toString('hex'),
  };

  try {
    fs.writeFileSync(localSecretsPath, `${JSON.stringify(secrets, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    return secrets;
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    return JSON.parse(fs.readFileSync(localSecretsPath, 'utf8'));
  }
}

const localSecrets = isProduction ? null : loadLocalSecrets();

function isWeakSecret(value) {
  return /change[-_ ]?me|replace[-_ ]?with|placeholder/i.test(value)
    || /^(?:zt-|default-|service-nilai-internal)/i.test(value);
}

function getSecret(name) {
  const value = process.env[name];

  if (isProduction) {
    if (!value || isWeakSecret(value) || value.length < 32) {
      throw new Error(`${name} wajib diatur ke secret acak minimal 32 karakter pada mode production.`);
    }
    return value;
  }

  // Satu file lokal yang diabaikan Git menjaga secret tetap sama di semua proses layanan.
  return value && !isWeakSecret(value) ? value : localSecrets[name];
}

const accessSecret = getSecret('JWT_ACCESS_SECRET');
const refreshSecret = getSecret('JWT_REFRESH_SECRET');
const serviceSecret = getSecret('JWT_SERVICE_SECRET');
const gatewaySecret = getSecret('GATEWAY_SECRET');
const serviceClientSecret = getSecret('SERVICE_CLIENT_SECRET');
const serviceClientId = process.env.SERVICE_CLIENT_ID || 'service-nilai-client';

if (isProduction) {
  if (!process.env.SERVICE_CLIENT_ID || isWeakSecret(serviceClientId)) {
    throw new Error('SERVICE_CLIENT_ID wajib diatur pada mode production.');
  }

  const secrets = [accessSecret, refreshSecret, serviceSecret, gatewaySecret, serviceClientSecret];
  if (new Set(secrets).size !== secrets.length) {
    throw new Error('Setiap kunci JWT, gateway, dan service client harus berbeda pada mode production.');
  }
}

const config = {
  env,

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
    accessSecret,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '10m',
    refreshSecret,
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '1d',
    serviceSecret,
    serviceExpiresIn: process.env.JWT_SERVICE_EXPIRES_IN || '5m',
  },

  // Gateway Shared Secret (PEP to internal Resource Services)
  gatewaySecret,

  // Service Client Credentials (for Service Nilai -> Gateway /auth/service)
  serviceAuth: {
    clientId: serviceClientId,
    clientSecret: serviceClientSecret,
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

module.exports = config;

