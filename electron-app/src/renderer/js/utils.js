import DOMPurify from 'dompurify';

export function sanitizeHTML(html) {
  return DOMPurify.sanitize(html);
}

export function getGreeting() {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
}

export function getTimeString() {
  return new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
}

export function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function formatSpeed(bytesPerSec) {
  return formatBytes(bytesPerSec) + '/s';
}

export function getFileIcon(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const icons = {
    pdf: 'picture_as_pdf',
    zip: 'folder_zip',
    exe: 'settings_applications',
    dmg: 'settings_applications',
    jpg: 'image',
    png: 'image',
    mp4: 'movie',
    mp3: 'audio_file',
  };
  return icons[ext] || 'insert_drive_file';
}
