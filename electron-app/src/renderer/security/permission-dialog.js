import { $permOverlay } from '../state/store.js';
import { showSettingsToast } from '../pages/settings-page.js';

// ═══ Permission Dialog ═══
const PERM_INFO = {
  camera: { icon: 'videocam', label: 'Camera Access', desc: 'wants to access your camera.' },
  microphone: { icon: 'mic', label: 'Microphone Access', desc: 'wants to access your microphone.' },
  geolocation: {
    icon: 'location_on',
    label: 'Location Access',
    desc: 'wants to know your location.',
  },
  notifications: {
    icon: 'notifications',
    label: 'Notifications',
    desc: 'wants to send you notifications.',
  },
  midi: { icon: 'piano', label: 'MIDI Device', desc: 'wants to access MIDI devices.' },
};

export function showPermissionDialog(details) {
  const info = PERM_INFO[details.permission] || {
    icon: 'security',
    label: 'Permission Request',
    desc: 'is requesting a permission.',
  };
  let origin = details.origin || 'A website';
  try {
    origin = new URL(details.origin).hostname;
  } catch (e) {}

  $permOverlay.querySelector('#perm-icon').innerHTML =
    `<span class="material-icons-outlined">${info.icon}</span>`;
  $permOverlay.querySelector('#perm-title').textContent = info.label;
  $permOverlay.querySelector('#perm-origin').textContent = origin;
  $permOverlay.querySelector('#perm-desc').textContent =
    `${origin} ${info.desc} KryptonBrowser has blocked this request for security.`;
  $permOverlay.style.display = 'flex';

  document.getElementById('perm-deny').onclick = () => {
    $permOverlay.style.display = 'none';
  };
  document.getElementById('perm-allow').onclick = () => {
    $permOverlay.style.display = 'none';
    showSettingsToast('Note: permission enforcement is managed by the system');
  };
}
