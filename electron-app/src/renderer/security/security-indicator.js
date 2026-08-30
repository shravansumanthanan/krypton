import { getActiveTab } from '../tabs/tab-manager.js';
import { $securityIndicator, $pqcBadge, $lockIcon } from '../state/store.js';

// ═══ Security Indicator ═══
export function updateSecurityIndicator(url) {
  $securityIndicator.className = 'security-indicator';
  $pqcBadge.classList.remove('visible');

  if (!url || url.startsWith('krypton://')) {
    $lockIcon.textContent = 'shield';
    $securityIndicator.classList.add('secure');
    if (url === 'krypton://pqc-security') $pqcBadge.classList.add('visible');
    return;
  }
  if (url.startsWith('https://')) {
    $lockIcon.textContent = 'lock';
    $securityIndicator.classList.add('secure');
    $pqcBadge.classList.add('visible');
  } else if (url.startsWith('http://')) {
    $lockIcon.textContent = 'lock_open';
    $securityIndicator.classList.add('insecure');
  } else {
    $lockIcon.textContent = 'language';
  }
}

// ═══ Security Popup ═══
export async function updateSecurityPopup() {
  const tab = getActiveTab();
  if (!tab) return;
  const $title = document.getElementById('popup-title');
  const $subtitle = document.getElementById('popup-subtitle');
  const $popupLock = document.getElementById('popup-lock-icon');
  const $protocol = document.getElementById('popup-protocol');
  const $kem = document.getElementById('popup-kem');
  const $cipher = document.getElementById('popup-cipher');
  const $pqc = document.getElementById('popup-pqc');

  if (tab.url && tab.url.startsWith('https://')) {
    const secInfo = await window.kryptonBrowser.getSecurityInfo(tab.url);
    if (secInfo && secInfo.secure) {
      $title.textContent = 'Connection is secure';
      $subtitle.textContent = secInfo.pqcActive
        ? 'Post-quantum encryption active'
        : 'Standard encryption active';
      $popupLock.textContent = 'lock';
      $popupLock.style.color = 'var(--accent-green)';
      $protocol.textContent = secInfo.protocol || 'TLS 1.3';
      $kem.textContent = secInfo.kem || 'Standard';
      $cipher.textContent = secInfo.cipher || 'Standard';
      if (secInfo.pqcActive) {
        $pqc.textContent = '✓ Active';
        $pqc.className = 'popup-value pqc-active';
      } else {
        $pqc.textContent = '⚠ Inactive';
        $pqc.className = 'popup-value';
        $pqc.style.color = 'var(--text-muted)';
      }
    } else {
      $title.textContent = 'Connection is secure';
      $subtitle.textContent = 'Standard encryption active';
      $popupLock.textContent = 'lock';
      $popupLock.style.color = 'var(--accent-green)';
      $protocol.textContent = 'TLS 1.2/1.3';
      $kem.textContent = 'Standard';
      $cipher.textContent = 'Standard';
      $pqc.textContent = '⚠ Inactive';
      $pqc.className = 'popup-value';
      $pqc.style.color = 'var(--text-muted)';
    }
  } else if (tab.url && tab.url.startsWith('http://')) {
    $title.textContent = 'Connection is NOT secure';
    $subtitle.textContent = 'No encryption — data may be intercepted';
    $popupLock.textContent = 'lock_open';
    $popupLock.style.color = 'var(--accent-red)';
    $protocol.textContent = 'None';
    $kem.textContent = 'None';
    $cipher.textContent = 'None';
    $pqc.textContent = '✗ Inactive';
    $pqc.className = 'popup-value';
    $pqc.style.color = 'var(--accent-red)';
  } else {
    $title.textContent = 'Internal page';
    $subtitle.textContent = 'KryptonBrowser internal resources';
    $popupLock.textContent = 'shield';
    $popupLock.style.color = 'var(--accent-green)';
    $protocol.textContent = 'Local';
    $kem.textContent = 'N/A';
    $cipher.textContent = 'N/A';
    $pqc.textContent = 'N/A';
    $pqc.className = 'popup-value';
    $pqc.style.color = 'var(--text-muted)';
  }
}
