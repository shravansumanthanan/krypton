import { $downloadsPanel, $dlList, downloadItems } from '../state/store.js';
import { closeAllPanels } from '../shields/shields-controller.js';
import { formatBytes, formatSpeed, getFileIcon, sanitizeHTML } from '../js/utils.js';

// ═══ Downloads Panel ═══
export function toggleDownloadsPanel() {
  if ($downloadsPanel.style.display === 'none' || !$downloadsPanel.style.display) {
    closeAllPanels();
    $downloadsPanel.style.display = 'flex';
  } else {
    $downloadsPanel.style.display = 'none';
  }
}

export function renderDownloadItem(info) {
  const pct = info.totalBytes > 0 ? Math.round((info.receivedBytes / info.totalBytes) * 100) : 0;
  const isDone = info.state === 'completed';
  const isErr = info.state === 'interrupted' || info.state === 'cancelled';
  const metaText = isDone
    ? `${formatBytes(info.totalBytes)} — Done`
    : isErr
      ? `${info.state}`
      : `${formatBytes(info.receivedBytes)} / ${formatBytes(info.totalBytes)} — ${formatSpeed(info.speed)}`;

  let el = document.getElementById('dl-item-' + info.id);
  if (!el) {
    el = document.createElement('div');
    el.className = 'dl-item';
    el.id = 'dl-item-' + info.id;
    // Remove empty placeholder
    const empty = $dlList.querySelector('.dl-empty');
    if (empty) empty.remove();
    $dlList.insertBefore(el, $dlList.firstChild);
  }

  el.innerHTML = sanitizeHTML(
    `<div class="dl-file-icon"><span class="material-icons-outlined">${getFileIcon(info.filename)}</span></div>` +
      `<div class="dl-info">` +
      `<div class="dl-filename" title="${info.filename}">${info.filename}</div>` +
      `<div class="dl-meta">${metaText}</div>` +
      `<div class="dl-progress-bar-wrap"><div class="dl-progress-bar${isDone ? ' complete' : isErr ? ' error' : ''}" style="width:${isDone ? 100 : isErr ? 100 : pct}%"></div></div>` +
      (isDone
        ? `<div class="dl-actions"><button class="dl-action-btn primary dl-btn-open">Open</button><button class="dl-action-btn dl-btn-folder">Show in Folder</button></div>`
        : isErr
          ? `<div class="dl-actions"><span style="font-size:11px;color:var(--accent-red)">${info.state}</span></div>`
          : `<div class="dl-actions"><span style="font-size:11px;color:var(--text-muted)">${pct}%</span></div>`) +
      `</div>`,
  );

  if (isDone) {
    const btnOpen = el.querySelector('.dl-btn-open');
    const btnFolder = el.querySelector('.dl-btn-folder');
    if (btnOpen)
      btnOpen.addEventListener('click', () => window.kryptonBrowser.openDownload(info.savePath));
    if (btnFolder)
      btnFolder.addEventListener('click', () =>
        window.kryptonBrowser.showDownloadInFolder(info.savePath),
      );
  }
}
