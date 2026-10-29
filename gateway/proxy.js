const config = require('../shared/config');

/**
 * Mekanisme Forwarding Proxy API Gateway ke Resource Services
 * Menyisipkan header internal X-Gateway-Secret dan meneruskan token autentikasi.
 *
 * @param {string} targetBaseUrl - Base URL service tujuan (cth: http://localhost:3001)
 */
function createServiceProxy(targetBaseUrl) {
  return async function serviceProxyMiddleware(req, res) {
    try {
      const targetUrl = new URL(req.originalUrl || req.url, targetBaseUrl).toString();

      const forwardHeaders = {};
      // Salin seluruh header yang relevan
      for (const [key, value] of Object.entries(req.headers)) {
        if (!['host', 'content-length', 'connection'].includes(key.toLowerCase())) {
          forwardHeaders[key] = value;
        }
      }

      // Sisipkan Gateway Secret wajib sesuai spesifikasi Zero Trust (NIST SP 800-207)
      forwardHeaders['x-gateway-secret'] = config.gatewaySecret;

      const fetchOptions = {
        method: req.method,
        headers: forwardHeaders,
      };

      if (
        ['POST', 'PUT', 'PATCH'].includes(req.method.toUpperCase()) &&
        req.body &&
        Object.keys(req.body).length > 0
      ) {
        fetchOptions.headers['content-type'] = 'application/json';
        fetchOptions.body = JSON.stringify(req.body);
      }

      const response = await fetch(targetUrl, fetchOptions);

      res.status(response.status);

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const json = await response.json();
        return res.json(json);
      } else {
        const text = await response.text();
        return res.send(text);
      }
    } catch (error) {
      console.error(`[PROXY ERROR] Gagal menghubungi layanan di ${targetBaseUrl}:`, error.message);
      return res.status(502).json({
        error: 'Bad Gateway',
        reason: `Layanan backend internal tidak dapat dihubungi: ${error.message}`,
      });
    }
  };
}

module.exports = {
  createServiceProxy,
};
