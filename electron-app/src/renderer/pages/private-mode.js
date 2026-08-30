import { isPrivateMode, setIsPrivateMode } from '../state/store.js';
import { showSettingsToast } from './settings-page.js';

// ═══ Private Window Mode ═══
export function togglePrivateMode() {
  setIsPrivateMode(!isPrivateMode);
  document.body.classList.toggle('private-mode', isPrivateMode);
  const banner = document.getElementById('private-mode-banner');
  if (banner) banner.style.display = isPrivateMode ? 'flex' : 'none';
  showSettingsToast(
    isPrivateMode ? 'Private browsing: no history will be saved' : 'Exited private mode',
  );
}
