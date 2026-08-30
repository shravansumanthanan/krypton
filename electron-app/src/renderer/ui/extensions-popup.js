import { $extensionsPanel, extensions } from '../state/store.js';
import { closeAllPanels } from '../shields/shields-controller.js';

// Extensions panel
export function toggleExtensionsPanel() {
  if ($extensionsPanel.style.display === 'none' || !$extensionsPanel.style.display) {
    closeAllPanels();
    renderExtensionsList();
    $extensionsPanel.style.display = 'block';
  } else {
    $extensionsPanel.style.display = 'none';
  }
}

export function renderExtensionsList() {
  const $list = document.getElementById('ext-list');
  $list.innerHTML = '';
  extensions.forEach((ext) => {
    const item = document.createElement('div');
    item.className = 'ext-item';
    item.innerHTML = `
      <div class="ext-icon" style="background:${ext.color}">${ext.icon}</div>
      <div class="ext-info">
        <div class="ext-name">${ext.name}</div>
        <div class="ext-desc">${ext.desc}</div>
      </div>
      <div class="ext-toggle ${ext.enabled ? 'active' : ''}" data-ext-id="${ext.id}"></div>
    `;
    item.querySelector('.ext-toggle').addEventListener('click', (e) => {
      ext.enabled = !ext.enabled;
      e.target.classList.toggle('active');
    });
    $list.appendChild(item);
  });
}
