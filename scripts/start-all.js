const { spawn } = require('child_process');
const path = require('path');

const services = [
  { name: 'GATEWAY', script: 'gateway/server.js', color: '\x1b[36m' },
  { name: 'NILAI  ', script: 'service-nilai/server.js', color: '\x1b[32m' },
  { name: 'TRANSKR', script: 'service-transkrip/server.js', color: '\x1b[35m' },
];

const processes = [];
const resetColor = '\x1b[0m';

console.log('=== Memulai Layanan Zero Trust Sistem Nilai ===');

for (const s of services) {
  const child = spawn('node', [path.resolve(__dirname, '..', s.script)], {
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: true,
  });

  child.stdout.on('data', (data) => {
    const lines = data.toString().trim().split('\n');
    lines.forEach((line) => {
      console.log(`${s.color}[${s.name}]${resetColor} ${line}`);
    });
  });

  child.stderr.on('data', (data) => {
    const lines = data.toString().trim().split('\n');
    lines.forEach((line) => {
      console.error(`${s.color}[${s.name}] [ERR]${resetColor} ${line}`);
    });
  });

  child.on('close', (code) => {
    console.log(`${s.color}[${s.name}]${resetColor} Berhenti dengan kode ${code}`);
  });

  processes.push(child);
}

function shutdown() {
  console.log('\n[RUNNER] Menghentikan semua layanan...');
  processes.forEach((proc) => {
    try {
      proc.kill('SIGTERM');
    } catch (e) {
      // Abaikan jika sudah mati
    }
  });
  setTimeout(() => process.exit(0), 1000);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

