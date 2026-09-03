import { sidebarOpen, setSidebarOpen } from '../state/store.js';

// ═══ Sidebar Selector ═══
// Always target the main browser sidebar panel
export function getSidebar() {
  return (
    document.getElementById('sidebar-panel') ||
    document.querySelector('.sidebar-panel') ||
    document.querySelector('body > #sidebar') ||
    document.getElementById('sidebar')
  );
}

export function openSidebar() {
  const sidebar = getSidebar();
  setSidebarOpen(true);
  if (sidebar) {
    sidebar.style.display = 'flex';
    sidebar.classList.add('open', 'active');
  }
  document.body.classList.add('sidebar-open');
}

export function closeSidebar() {
  const sidebar = getSidebar();
  setSidebarOpen(false);
  if (sidebar) {
    sidebar.style.display = 'none';
    sidebar.classList.remove('open', 'active');
  }
  document.body.classList.remove('sidebar-open');
}

export function toggleSidebar() {
  const sidebar = getSidebar();
  const isOpen = sidebar
    ? (sidebar.style.display !== 'none' && sidebar.style.display !== '') ||
      sidebar.classList.contains('open') ||
      sidebar.classList.contains('active')
    : sidebarOpen;

  if (isOpen) {
    closeSidebar();
  } else {
    openSidebar();
  }
}

// ═══ Document-Level Event Delegation for Sidebar ═══
document.addEventListener('click', (e) => {
  // Close button click
  const closeBtn = e.target.closest(
    '#sidebar-close, .sidebar-close, [data-action="close-sidebar"]',
  );
  if (closeBtn) {
    e.preventDefault();
    e.stopPropagation();
    closeSidebar();
    return;
  }

  // Sidebar tab switching
  const tabBtn = e.target.closest('.sidebar-tab');
  if (tabBtn) {
    document.querySelectorAll('.sidebar-tab').forEach((t) => t.classList.remove('active'));
    tabBtn.classList.add('active');
    document.querySelectorAll('.sidebar-pane').forEach((p) => p.classList.remove('active'));
    const pane = document.querySelector(`[data-sidebar-pane="${tabBtn.dataset.sidebarTab}"]`);
    if (pane) pane.classList.add('active');
    return;
  }

  // Close sidebar on outside click
  const sidebar = getSidebar();
  if (
    sidebar &&
    (sidebar.style.display === 'flex' ||
      sidebar.classList.contains('open') ||
      sidebar.classList.contains('active')) &&
    !sidebar.contains(e.target) &&
    !e.target.closest('#btn-sidebar')
  ) {
    closeSidebar();
  }
});
