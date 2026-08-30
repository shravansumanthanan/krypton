import { isPrivateMode } from '../state/store.js';

// ═══ History ═══
// Clean up stale entries on startup (entries where title is just the URL)
export function cleanStaleHistory() {
  try {
    let hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    // Remove entries where title is the same as the URL (never got a real title)
    hist = hist.filter((entry) => entry.title && entry.title !== entry.url);
    localStorage.setItem('krypton_history', JSON.stringify(hist));
  } catch (e) {
    /* ignore */
  }
}

cleanStaleHistory();

export function recordHistory(url, title, favicon, timestamp) {
  if (isPrivateMode) return; // Don't record history in private mode
  if (!url || url.startsWith('krypton://') || url.startsWith('file://')) return;
  try {
    let hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    hist.unshift({
      url,
      title: title || url,
      favicon: favicon || null,
      timestamp: timestamp || Date.now(),
    });
    // Keep last 500 entries
    if (hist.length > 500) hist = hist.slice(0, 500);
    localStorage.setItem('krypton_history', JSON.stringify(hist));
  } catch (e) {
    /* storage full or unavailable */
  }
}

export function updateHistoryEntry(timestamp, updates) {
  if (!timestamp) return;
  try {
    let hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    const entry = hist.find((h) => h.timestamp === timestamp);
    if (entry) {
      if (updates.title) entry.title = updates.title;
      if (updates.favicon) entry.favicon = updates.favicon;
      localStorage.setItem('krypton_history', JSON.stringify(hist));
    }
  } catch (e) {
    /* ignore */
  }
}
