const { getDb } = require('../shared/db');
const { ROLES } = require('../shared/constants');
const { checkAccessHours } = require('../shared/time');

/**
 * Policy Engine / Policy Decision Point (PDP)
 * Memutuskan apakah suatu request diizinkan (ALLOW) atau ditolak (DENY)
 * berdasarkan peran subjek, kepemilikan data aktual di database (ABAC),
 * serta konteks jam akses operasional.
 *
 * @param {Object} context
 * @param {Object} context.user - Payload token pengguna atau service
 * @param {string} context.method - HTTP method (GET, POST, PUT, DELETE)
 * @param {string} context.path - Endpoint path (cth: /nilai, /nilai/1, /kelas/1/finalisasi, /transkrip/220101, /transkrip/sinkron)
 * @param {Object} [context.params] - Route parameters (id, nim)
 * @param {Object} [context.body] - Request body
 * @param {number} [context.simulatedHour] - Jam simulasi untuk pengetesan otomatis
 *
 * @returns {{ allowed: boolean, statusCode: number, reason: string }}
 */
function evaluatePolicy(context) {
  const { user, method, path, params = {}, simulatedHour = null } = context;
  const db = getDb();
  // Normalisasi path: pisahkan query string, lowercase, dan hapus trailing slash (kecuali root '/')
  const cleanPath = (path || '').split('?')[0];
  const normalizedPath = (cleanPath.toLowerCase().replace(/\/+$/, '') || '/');
  const upperMethod = (method || '').toUpperCase();

  // 1. Kebijakan untuk: GET /nilai (Daftar Nilai)
  if (upperMethod === 'GET' && (normalizedPath === '/nilai' || normalizedPath === '/nilai/')) {
    if (user.role === ROLES.MAHASISWA) {
      return {
        allowed: true,
        statusCode: 200,
        reason: 'Mahasiswa diizinkan melihat nilai miliknya sendiri',
      };
    }

    if (user.role === ROLES.DOSEN) {
      return {
        allowed: true,
        statusCode: 200,
        reason: 'Dosen diizinkan melihat nilai pada kelas yang diampunya',
      };
    }

    return {
      allowed: false,
      statusCode: 403,
      reason: `Role '${user.role}' tidak memiliki izin melihat daftar nilai`,
    };
  }

  // 2. Kebijakan untuk: GET /nilai/:id (Detail Nilai Tunggal)
  const getNilaiMatch = normalizedPath.match(/^\/nilai\/(\d+)$/);
  if (upperMethod === 'GET' && getNilaiMatch) {
    const gradeId = parseInt(params.id || getNilaiMatch[1], 10);

    const grade = db.prepare(`
      SELECT g.*, c.dosen_id
      FROM grades g
      JOIN classes c ON g.kelas_id = c.id
      WHERE g.id = ?
    `).get(gradeId);

    if (!grade) {
      return {
        allowed: false,
        statusCode: 404,
        reason: `Data nilai dengan ID ${gradeId} tidak ditemukan`,
      };
    }

    if (user.role === ROLES.MAHASISWA) {
      if (Number(grade.mahasiswa_id) === Number(user.sub)) {
        return {
          allowed: true,
          statusCode: 200,
          reason: 'Mahasiswa diizinkan melihat detail nilai miliknya sendiri',
        };
      }
      return {
        allowed: false,
        statusCode: 403,
        reason: `Akses ditolak: Mahasiswa dilarang mengakses nilai milik mahasiswa lain`,
      };
    }

    if (user.role === ROLES.DOSEN) {
      if (Number(grade.dosen_id) === Number(user.sub)) {
        return {
          allowed: true,
          statusCode: 200,
          reason: 'Dosen diizinkan melihat detail nilai kelas yang diampunya',
        };
      }
      return {
        allowed: false,
        statusCode: 403,
        reason: `Akses ditolak: Dosen bukan pengampu kelas untuk nilai ID ${gradeId}`,
      };
    }

    return {
      allowed: false,
      statusCode: 403,
      reason: `Role '${user.role}' tidak memiliki izin mengakses data nilai`,
    };
  }

  // 3. Kebijakan untuk: PUT /nilai/:id
  const putNilaiMatch = normalizedPath.match(/^\/nilai\/(\d+)$/);
  if (upperMethod === 'PUT' && putNilaiMatch) {
    const gradeId = parseInt(params.id || putNilaiMatch[1], 10);

    // Hanya Dosen yang diizinkan
    if (user.role !== ROLES.DOSEN) {
      return {
        allowed: false,
        statusCode: 403,
        reason: `Hanya dosen yang diizinkan mengubah nilai. Role pengirim: '${user.role}'`,
      };
    }

    // Cek Jam Akses (07.00 - 21.00 Asia/Jakarta)
    const hourCheck = checkAccessHours({ simulatedHour });
    if (!hourCheck.allowed) {
      return {
        allowed: false,
        statusCode: 403,
        reason: hourCheck.message,
      };
    }

    // Cek kepemilikan data di database (ABAC)
    const grade = db.prepare(`
      SELECT g.*, c.dosen_id, c.nama_kelas, c.mata_kuliah
      FROM grades g
      JOIN classes c ON g.kelas_id = c.id
      WHERE g.id = ?
    `).get(gradeId);

    if (!grade) {
      return {
        allowed: false,
        statusCode: 404,
        reason: `Data nilai dengan ID ${gradeId} tidak ditemukan`,
      };
    }

    // Verifikasi apakah dosen adalah pengampu kelas bersangkutan
    if (Number(grade.dosen_id) !== Number(user.sub)) {
      return {
        allowed: false,
        statusCode: 403,
        reason: `Akses ditolak: Dosen bukan pengampu kelas untuk nilai ID ${gradeId}`,
      };
    }

    // Verifikasi apakah nilai sudah difinalisasi
    if (grade.status_final === 1) {
      return {
        allowed: false,
        statusCode: 403,
        reason: `Nilai ID ${gradeId} sudah berstatus FINAL dan tidak dapat diubah`,
      };
    }

    return {
      allowed: true,
      statusCode: 200,
      reason: 'Dosen pengampu terverifikasi, nilai belum final, dan dalam jam akses operasional',
    };
  }

  // 4. Kebijakan untuk: POST /kelas/:id/finalisasi
  const postFinalisasiMatch = normalizedPath.match(/^\/kelas\/(\d+)\/finalisasi$/);
  if (upperMethod === 'POST' && postFinalisasiMatch) {
    const classId = parseInt(params.id || postFinalisasiMatch[1], 10);

    // Hanya Dosen yang diizinkan
    if (user.role !== ROLES.DOSEN) {
      return {
        allowed: false,
        statusCode: 403,
        reason: `Hanya dosen pengampu yang diizinkan memfinalisasi kelas. Role pengirim: '${user.role}'`,
      };
    }

    // Cek Jam Akses (07.00 - 21.00 Asia/Jakarta)
    const hourCheck = checkAccessHours({ simulatedHour });
    if (!hourCheck.allowed) {
      return {
        allowed: false,
        statusCode: 403,
        reason: hourCheck.message,
      };
    }

    // Cek kepemilikan kelas di database
    const classRow = db.prepare('SELECT * FROM classes WHERE id = ?').get(classId);
    if (!classRow) {
      return {
        allowed: false,
        statusCode: 404,
        reason: `Kelas dengan ID ${classId} tidak ditemukan`,
      };
    }

    if (Number(classRow.dosen_id) !== Number(user.sub)) {
      return {
        allowed: false,
        statusCode: 403,
        reason: `Akses ditolak: Dosen bukan pengampu kelas ID ${classId}`,
      };
    }

    return {
      allowed: true,
      statusCode: 200,
      reason: 'Dosen pengampu kelas terverifikasi dan dalam jam akses operasional',
    };
  }

  // 5. Kebijakan untuk: GET /transkrip/:nim
  const getTranskripMatch = normalizedPath.match(/^\/transkrip\/([a-zA-Z0-9_-]+)$/);
  if (upperMethod === 'GET' && getTranskripMatch) {
    const targetNim = params.nim || getTranskripMatch[1];

    if (user.role === ROLES.ADMIN) {
      return {
        allowed: true,
        statusCode: 200,
        reason: 'Admin diizinkan melihat transkrip seluruh mahasiswa',
      };
    }

    if (user.role === ROLES.MAHASISWA) {
      if (String(user.nim) === String(targetNim)) {
        return {
          allowed: true,
          statusCode: 200,
          reason: 'Mahasiswa diizinkan melihat transkrip miliknya sendiri',
        };
      }
      return {
        allowed: false,
        statusCode: 403,
        reason: `Mahasiswa (NIM: ${user.nim}) dilarang melihat transkrip milik mahasiswa lain (NIM: ${targetNim})`,
      };
    }

    return {
      allowed: false,
      statusCode: 403,
      reason: `Role '${user.role}' tidak memiliki izin melihat transkrip akademik`,
    };
  }

  // 6. Kebijakan untuk: POST /transkrip/sinkron
  if (upperMethod === 'POST' && (normalizedPath === '/transkrip/sinkron' || normalizedPath === '/transkrip/sinkron/')) {
    if (user.role === ROLES.SERVICE) {
      return {
        allowed: true,
        statusCode: 200,
        reason: 'Token service terverifikasi untuk operasi sinkronisasi transkrip',
      };
    }

    return {
      allowed: false,
      statusCode: 403,
      reason: `Endpoint sinkronisasi transkrip hanya dapat diakses menggunakan token service. Token pengguna dengan role '${user.role}' ditolak.`,
    };
  }

  // Endpoint lain yang tidak dikenal atau tidak tercakup
  return {
    allowed: false,
    statusCode: 404,
    reason: `Rute '${upperMethod} ${path}' tidak dikenali oleh kebijakan akses gateway`,
  };
}

module.exports = {
  evaluatePolicy,
};
