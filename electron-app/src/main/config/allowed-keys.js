'use strict';
const fs = require('fs');

const ALLOWED_CONFIG_KEYS = new Set([
  // Existing keys (copy from ALLOWED_CONFIG_KEYS in main.js)
  'krypton_ad_block',
  'krypton_https_upgrade',
  'krypton_send_dnt',
  'krypton_block_cookies',
  'krypton_ask_download_loc',
  'krypton_panic_shortcut',
  // Phase 2 additions (new):
  'krypton_fp_level',
  'krypton_cookie_level',
  'krypton_block_scripts',
  // Phase 3 additions (new):
  'krypton_kem_algorithm',
  'krypton_sig_algorithm',
  'krypton_hybrid_mode',
  'krypton_indigenous_pki',
  'krypton_fail_closed',
]);

let _configCache = {};
let _configPath = null;

function initConfig(configFilePath) {
  _configPath = configFilePath;
  try {
    _configCache = JSON.parse(fs.readFileSync(configFilePath, 'utf8'));
  } catch {
    _configCache = {};
  }
}

function getConfigSync(key, defaultValue = null) {
  return _configCache[key] !== undefined ? _configCache[key] : defaultValue;
}

function setConfigSync(key, value) {
  if (!ALLOWED_CONFIG_KEYS.has(key)) return false;
  _configCache[key] = value;
  if (_configPath) {
    try {
      fs.writeFileSync(_configPath, JSON.stringify(_configCache, null, 2));
    } catch (e) {
      /* ignore write errors */
    }
  }
  return true;
}

module.exports = { ALLOWED_CONFIG_KEYS, initConfig, getConfigSync, setConfigSync };
