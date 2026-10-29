const config = require('./config');

/**
 * Mendapatkan jam saat ini (0-23) pada timezone yang ditentukan (default Asia/Jakarta)
 */
function getCurrentHourInTimezone(timezone = config.accessHours.timezone, date = new Date()) {
  const options = {
    timeZone: timezone,
    hour: 'numeric',
    hour12: false,
  };
  const formatter = new Intl.DateTimeFormat('en-US', options);
  return parseInt(formatter.format(date), 10);
}

/**
 * Mengecek apakah waktu saat ini berada dalam rentang jam operasional akses
 * (07.00 - 21.00 Asia/Jakarta)
 *
 * Mendukung simulasi jam (simulatedHour) untuk kemudahan pengujian otomatis.
 */
function checkAccessHours(options = {}) {
  const timezone = options.timezone || config.accessHours.timezone;
  const startHour = options.startHour !== undefined ? options.startHour : config.accessHours.start;
  const endHour = options.endHour !== undefined ? options.endHour : config.accessHours.end;

  let currentHour;
  if (options.simulatedHour !== undefined && options.simulatedHour !== null) {
    currentHour = parseInt(options.simulatedHour, 10);
  } else {
    currentHour = getCurrentHourInTimezone(timezone, options.date || new Date());
  }

  // Jam 07.00 s/d 20.59 (inklusif 7 hingga kurang dari 21)
  const isAllowed = currentHour >= startHour && currentHour < endHour;

  return {
    allowed: isAllowed,
    currentHour,
    startHour,
    endHour,
    timezone,
    message: isAllowed
      ? `Akses diperbolehkan pada jam operasional (${startHour}.00 - ${endHour}.00 ${timezone})`
      : `Operasi ditolak di luar jam akses operasional (${startHour}.00 - ${endHour}.00 ${timezone}). Jam sistem terdeteksi: ${currentHour}.00`,
  };
}

/**
 * Menghasilkan string waktu lokal Asia/Jakarta berformat ISO-like
 */
function getWIBTimestamp(date = new Date()) {
  return new Intl.DateTimeFormat('sv-SE', {
    timeZone: config.accessHours.timezone,
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(date);
}

module.exports = {
  getCurrentHourInTimezone,
  checkAccessHours,
  getWIBTimestamp,
};

