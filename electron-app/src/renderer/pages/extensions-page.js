import { extensions } from '../state/store.js';

export function createExtensionsInAppPage(tabId) {
  const div = document.createElement('div');
  div.className = 'new-tab-page hist-page';
  div.dataset.tabId = tabId;

  function renderExtList() {
    let html =
      '<div class="hist-sidebar">' +
      '<a class="hist-nav-item active"><span class="material-icons-outlined">extension</span>All Extensions</a>' +
      '<a class="hist-nav-item"><span class="material-icons-outlined">check_circle</span>Enabled</a>' +
      '<a class="hist-nav-item"><span class="material-icons-outlined">block</span>Disabled</a>' +
      '</div>' +
      '<div class="hist-main">' +
      '<h2 style="font-size:20px;font-weight:600;margin-bottom:20px;color:var(--text-primary)">Extensions</h2>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">';

    extensions.forEach((ext, i) => {
      html +=
        '<div style="background:var(--bg-tab);border-radius:12px;padding:16px;display:flex;align-items:flex-start;gap:12px">' +
        '<div style="width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;background:' +
        ext.color +
        ';flex-shrink:0">' +
        ext.icon +
        '</div>' +
        '<div style="flex:1;min-width:0">' +
        '<div style="font-size:14px;font-weight:500;color:var(--text-primary)">' +
        ext.name +
        '</div>' +
        '<div style="font-size:12px;color:var(--text-muted);margin-top:2px">' +
        ext.desc +
        '</div>' +
        '</div>' +
        '<div class="ext-page-toggle" data-ext-index="' +
        i +
        '" style="width:40px;height:22px;border-radius:11px;position:relative;cursor:pointer;flex-shrink:0;background:' +
        (ext.enabled ? 'var(--accent)' : 'var(--border)') +
        '">' +
        '<div style="position:absolute;' +
        (ext.enabled ? 'right:2px' : 'left:2px') +
        ';top:2px;width:18px;height:18px;border-radius:50%;background:#fff;transition:all 0.2s"></div>' +
        '</div>' +
        '</div>';
    });

    html += '</div></div>';
    div.innerHTML = html;

    // Bind toggle clicks
    div.querySelectorAll('.ext-page-toggle').forEach((toggle) => {
      toggle.addEventListener('click', () => {
        const idx = Number(toggle.dataset.extIndex);
        extensions[idx].enabled = !extensions[idx].enabled;
        renderExtList();
      });
    });
  }

  renderExtList();
  return div;
}
