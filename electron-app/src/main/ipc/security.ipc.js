'use strict';

const fingerprintEnforcer = require('../fingerprint-enforcer');

module.exports = function registerSecurityHandlers(ipcMain, services) {
  const { pqcHandshakeService, pqcCertValidator, pqcEngine, verifiedCertificatesGetter } = services;

  // Certificate info
  ipcMain.handle('get-certificate-info', async (e, url) => {
    try {
      const { net } = require('electron');
      const dns = require('dns');

      if (typeof url !== 'string' || url.length === 0) return { error: 'Invalid URL' };

      const parsedUrl = new URL(url);
      if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
        return { error: 'Invalid protocol for certificate info' };
      }

      // SSRF Prevention: Block requests to local/private networks
      const hostname = parsedUrl.hostname.toLowerCase();

      try {
        const addresses = await dns.promises.lookup(hostname, { all: true });
        for (const addr of addresses) {
          const ip = addr.address;
          if (
            ip === '127.0.0.1' ||
            ip === '0.0.0.0' ||
            ip === '::1' ||
            ip.startsWith('192.168.') ||
            ip.startsWith('10.') ||
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
            ip.startsWith('169.254.') ||
            ip.startsWith('fc00:') ||
            ip.startsWith('fe80:')
          ) {
            return { error: 'Private IP resolution not allowed for certificate info' };
          }
        }
      } catch (err) {
        return { error: `DNS lookup failed: ${err.message}` };
      }

      return await new Promise((resolve) => {
        const req = net.request(url);
        req.on('response', (res) => {
          resolve({ statusCode: res.statusCode, url });
          req.abort();
        });
        req.on('error', (err) => resolve({ error: err.message, url }));
        req.end();
      });
    } catch (err) {
      return { error: err.message };
    }
  });

  ipcMain.handle('get-security-info', async (e, urlStr) => {
    try {
      if (!urlStr) {
        return {
          secure: false,
          domain: '—',
          status: 'Not connected',
          protocol: '—',
          kem: '—',
          cipher: '—',
          sig: '—',
          ca: '—',
          pki: '—',
          ms: null,
        };
      }
      const url = new URL(urlStr);
      if (url.protocol !== 'https:') {
        return {
          secure: false,
          domain: url.hostname,
          status: 'Insecure',
          protocol: 'HTTP',
          kem: '—',
          cipher: '—',
          sig: '—',
          ca: '—',
          pki: '—',
          ms: null,
        };
      }

      const hostname = url.hostname.toLowerCase();
      const session = pqcEngine.getSessionByDomain(hostname);
      const certMap = verifiedCertificatesGetter ? verifiedCertificatesGetter() : null;
      const certInfo = certMap
        ? certMap.get(hostname) ||
          certMap.get(hostname.replace(/^www\./, '')) ||
          certMap.get('www.' + hostname)
        : null;

      if (session && session.status === 'COMPLETED') {
        const ca = session.ca || session.issuingCa || (certInfo ? certInfo.issuer : null) || '—';
        return {
          secure: true,
          pqcActive: true,
          protocol: session.tlsVersion || 'TLS 1.3',
          kem: session.kem || '—',
          cipher: session.cipherSuite || '—',
          sig: session.sig || '—',
          ca,
          pki: session.indigenousVerified ? 'Verified' : 'Standard',
          ms: session.ms != null ? session.ms : null,
          domain: url.hostname,
          status: 'SECURE_TUNNEL',
        };
      }

      const ca = certInfo && certInfo.issuer ? certInfo.issuer : '—';
      return {
        secure: true,
        pqcActive: false,
        protocol: 'TLS 1.3',
        kem: '—',
        cipher: '—',
        sig: '—',
        ca,
        pki: 'Standard',
        ms: null,
        domain: url.hostname,
        status: 'Connected',
      };
    } catch (err) {
      return { error: err.message };
    }
  });

  /**
   * set-fingerprint-policy — change the active fingerprint mitigation level.
   * Renderer → preload → IPC → here → FingerprintEnforcer.setPolicy()
   *
   * Accepted levels: 'off' | 'standard' | 'strict'
   * Returns: { ok: true, level } on success, { ok: false, error } on unknown level.
   *
   * Security note: only the policy string crosses IPC — no key material.
   */
  ipcMain.handle('set-fingerprint-policy', async (e, level) => {
    if (typeof level !== 'string') return false;
    const ok = fingerprintEnforcer.setPolicy(level);
    return Boolean(ok);
  });

  /**
   * get-fingerprint-policy — returns the active fingerprint mitigation level.
   */
  ipcMain.handle('get-fingerprint-policy', async () => {
    return fingerprintEnforcer.getPolicy();
  });
};
