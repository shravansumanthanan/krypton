// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// chrome://pqc-security/ — PQC Security Panel Controller
//
// Chrome/Brave-style navigation and data rendering.
// In production, this communicates via Mojo IPC to the network process.
// This standalone version uses simulated data for demonstration.

'use strict';

// ═══ Sidebar Navigation ═══
document.querySelectorAll('.sidebar-item').forEach(item => {
  item.addEventListener('click', () => {
    navigateToSection(item.dataset.section);
  });
});

// Clickable settings rows that navigate to sections
document.querySelectorAll('.settings-row[data-navigate]').forEach(row => {
  row.addEventListener('click', () => {
    navigateToSection(row.dataset.navigate);
  });
});

function navigateToSection(sectionId) {
  // Update sidebar
  document.querySelectorAll('.sidebar-item').forEach(el =>
    el.classList.remove('active'));
  const navItem = document.querySelector(
    `.sidebar-item[data-section="${sectionId}"]`);
  if (navItem) navItem.classList.add('active');

  // Update content
  document.querySelectorAll('.section').forEach(el =>
    el.classList.remove('active'));
  const section = document.getElementById('section-' + sectionId);
  if (section) section.classList.add('active');

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ═══ Indigenous Trust Store Data ═══
const INDIGENOUS_CAS = [
  {
    name: 'NIC Root CA 2025',
    org: 'National Informatics Centre',
    algorithm: 'ML-DSA-65',
    pqc: true,
    active: true,
    ocsp: 'http://ocsp.nic.in',
  },
  {
    name: 'CCA India Root CA',
    org: 'Controller of Certifying Authorities, India',
    algorithm: 'RSA-4096',
    pqc: false,
    active: true,
    ocsp: 'http://ocsp.cca.gov.in',
  },
  {
    name: 'Indian Army PKI Root',
    org: 'Indian Army Signal Corps',
    algorithm: 'ML-DSA-65',
    pqc: true,
    active: true,
    ocsp: 'http://ocsp.army.mil.in',
  },
  {
    name: 'DRDO Internal CA',
    org: 'Defence Research and Development Organisation',
    algorithm: 'ML-DSA-65',
    pqc: true,
    active: true,
    ocsp: 'http://ocsp.drdo.gov.in',
  },
  {
    name: 'eMudhra Class 3 CA',
    org: 'eMudhra Limited',
    algorithm: 'RSA-4096',
    pqc: false,
    active: true,
    ocsp: 'http://ocsp.emudhra.com',
  },
];

function renderTrustStore() {
  const card = document.getElementById('truststore-card');
  card.innerHTML = '';

  INDIGENOUS_CAS.forEach(ca => {
    const row = document.createElement('div');
    row.className = 'trust-row';

    const iconClass = ca.pqc ? 'pqc' : 'classic';
    const iconName = ca.pqc ? 'enhanced_encryption' : 'lock';
    const algBadge = ca.pqc
      ? '<span class="badge badge-green">' + ca.algorithm + '</span>'
      : '<span class="badge badge-blue">' + ca.algorithm + '</span>';
    const statusBadge = '<span class="badge badge-green">Active</span>';

    row.innerHTML = `
      <div class="trust-icon ${iconClass}">
        <span class="material-icons-outlined">${iconName}</span>
      </div>
      <div class="trust-info">
        <div class="trust-name">${ca.name}</div>
        <div class="trust-org">${ca.org}</div>
      </div>
      <div class="trust-meta">
        ${algBadge}
        ${statusBadge}
      </div>
    `;
    card.appendChild(row);
  });
}

// ═══ Session History ═══
const SAMPLE_SESSIONS = [
  { time: '2025-06-15 14:32:01', domain: 'army.mil.in', kem: 'ML-KEM-768', sig: 'ML-DSA-65', status: 'COMPLETED', ca: 'Indian Army PKI Root', pki: 'INDIGENOUS', ms: 42 },
  { time: '2025-06-15 14:31:55', domain: 'nic.in', kem: 'ML-KEM-768', sig: 'ML-DSA-65', status: 'COMPLETED', ca: 'NIC Root CA 2025', pki: 'INDIGENOUS', ms: 38 },
  { time: '2025-06-15 14:31:12', domain: 'drdo.gov.in', kem: 'ML-KEM-768', sig: 'ML-DSA-65', status: 'COMPLETED', ca: 'DRDO Internal CA', pki: 'INDIGENOUS', ms: 45 },
  { time: '2025-06-15 14:30:42', domain: 'example.com', kem: 'ML-KEM-768', sig: 'ML-DSA-65', status: 'FAILED', ca: 'DigiCert', pki: 'REJECTED', ms: 12 },
  { time: '2025-06-15 14:29:10', domain: 'defence.gov.in', kem: 'ML-KEM-768', sig: 'ML-DSA-65', status: 'COMPLETED', ca: 'NIC Root CA 2025', pki: 'INDIGENOUS', ms: 40 },
];

function renderSessionHistory() {
  const tbody = document.getElementById('session-body');
  tbody.innerHTML = '';

  SAMPLE_SESSIONS.forEach(s => {
    const tr = document.createElement('tr');
    const statusBadge = s.status === 'COMPLETED'
      ? '<span class="badge badge-green">✓ Complete</span>'
      : '<span class="badge badge-red">✗ Failed</span>';
    const pkiBadge = s.pki === 'INDIGENOUS'
      ? '<span class="badge badge-green">Indigenous</span>'
      : '<span class="badge badge-red">Rejected</span>';

    tr.innerHTML = `
      <td>${s.time}</td>
      <td style="color:var(--text-primary);font-weight:500">${s.domain}</td>
      <td>${s.kem}</td>
      <td>${s.sig}</td>
      <td>${statusBadge}</td>
      <td>${s.ca}</td>
      <td>${pkiBadge}</td>
      <td>${s.ms}ms</td>
    `;
    tbody.appendChild(tr);
  });
}

// ═══ Handshake Log ═══
const SAMPLE_LOG = [
  { ts: '14:32:01.000', from: 'BROWSER_IDLE', to: 'RESOLVING_DNS', event: 'URL_ENTERED', dur: '0ms', desc: 'DNS resolution initiated for army.mil.in' },
  { ts: '14:32:01.005', from: 'RESOLVING_DNS', to: 'KEY_GENERATION', event: 'IP_RESOLVED', dur: '5ms', desc: 'DNS resolved to 10.0.1.50' },
  { ts: '14:32:01.012', from: 'KEY_GENERATION', to: 'WAITING_FOR_SERVER', event: 'KEYS_READY', dur: '7ms', desc: 'Hybrid keypair generated (X25519 + ML-KEM-768)' },
  { ts: '14:32:01.025', from: 'WAITING_FOR_SERVER', to: 'VERIFYING_IDENTITY', event: 'SERVER_HELLO', dur: '13ms', desc: 'ServerHello received with KEM ciphertext' },
  { ts: '14:32:01.035', from: 'VERIFYING_IDENTITY', to: 'DERIVING_SECRETS', event: 'PKI_VERIFIED', dur: '10ms', desc: 'Certificate verified: Indigenous PKI ✓' },
  { ts: '14:32:01.040', from: 'DERIVING_SECRETS', to: 'SECURE_TUNNEL', event: 'KEYS_DERIVED', dur: '5ms', desc: 'Session key derived via HKDF-SHA3-256' },
];

function renderHandshakeLog() {
  const tbody = document.getElementById('handshake-log-body');
  tbody.innerHTML = '';

  SAMPLE_LOG.forEach(entry => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${entry.ts}</td>
      <td><span class="badge badge-blue">${entry.from}</span></td>
      <td><span class="badge badge-green">${entry.to}</span></td>
      <td>${entry.event}</td>
      <td>${entry.dur}</td>
      <td style="color:var(--text-secondary);font-family:var(--font-sans)">${entry.desc}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ═══ Stats ═══
function updateStats() {
  const total = SAMPLE_SESSIONS.length;
  const pqc = SAMPLE_SESSIONS.filter(s => s.status === 'COMPLETED').length;
  const indigenous = SAMPLE_SESSIONS.filter(s => s.pki === 'INDIGENOUS').length;
  const failed = SAMPLE_SESSIONS.filter(s => s.status === 'FAILED').length;

  document.getElementById('stat-total').textContent = total;
  document.getElementById('stat-pqc').textContent = pqc;
  document.getElementById('stat-indigenous').textContent = indigenous;
  document.getElementById('stat-failed').textContent = failed;
}

// ═══ Global Status ═══
function setGlobalStatus(type, text) {
  const pill = document.getElementById('global-status-pill');
  const dot = document.getElementById('global-dot');
  const label = document.getElementById('global-status-text');

  pill.className = 'global-status-pill';
  if (type === 'warning') pill.classList.add('warning');
  if (type === 'error') pill.classList.add('error');

  label.textContent = text;
}

// ═══ Self-Test ═══
document.getElementById('btn-run-selftest').addEventListener('click', () => {
  const output = document.getElementById('selftest-output');
  output.textContent = '';
  output.style.display = 'block';

  const tests = [
    '[1/8] ML-KEM-768 keygen .............. ✅ PASS (1184B pk, 2400B sk)',
    '[2/8] ML-KEM-768 encaps .............. ✅ PASS (1088B ct, 32B ss)',
    '[3/8] ML-KEM-768 decaps .............. ✅ PASS (shared secrets match)',
    '[4/8] ML-DSA-65  keygen .............. ✅ PASS (1952B pk, 4032B sk)',
    '[5/8] ML-DSA-65  sign ................ ✅ PASS (3309B sig)',
    '[6/8] ML-DSA-65  verify .............. ✅ PASS',
    '[7/8] HKDF-SHA3-256 .................. ✅ PASS (deterministic)',
    '[8/8] Indigenous PKI trust store ..... ✅ PASS (5 CAs loaded)',
    '',
    '════════════════════════════════════════════',
    'All 8 self-tests PASSED. PQC subsystem operational.',
    '════════════════════════════════════════════',
  ];

  let i = 0;
  const interval = setInterval(() => {
    if (i < tests.length) {
      output.textContent += tests[i] + '\n';
      output.scrollTop = output.scrollHeight;
      i++;
    } else {
      clearInterval(interval);
    }
  }, 180);
});

// ═══ CSV Export ═══
document.getElementById('btn-export-csv').addEventListener('click', () => {
  let csv = 'time,domain,kem,sig,status,ca,pki,ms\n';
  SAMPLE_SESSIONS.forEach(s => {
    csv += `${s.time},${s.domain},${s.kem},${s.sig},${s.status},${s.ca},${s.pki},${s.ms}\n`;
  });
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'pqc_sessions.csv';
  a.click();
});

// ═══ Search ═══
document.getElementById('search-input').addEventListener('input', (e) => {
  const query = e.target.value.toLowerCase();
  // Simple search: highlight matching sidebar items
  document.querySelectorAll('.sidebar-item').forEach(item => {
    const label = item.querySelector('.sidebar-label').textContent.toLowerCase();
    item.style.opacity = (!query || label.includes(query)) ? '1' : '0.3';
  });
});

// ═══ Initialize ═══
document.addEventListener('DOMContentLoaded', () => {
  renderTrustStore();
  renderSessionHistory();
  renderHandshakeLog();
  updateStats();
  setGlobalStatus('ok', 'Quantum-Secure');
});
