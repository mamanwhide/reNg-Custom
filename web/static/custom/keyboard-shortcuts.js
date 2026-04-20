/**
 * paraKang Global Keyboard Shortcuts
 * Provides SOC-style keyboard navigation for power users.
 *
 * Key Map:
 *   /         → Focus search box
 *   ?         → Open shortcuts help dialog
 *   g then d  → Go to Dashboard
 *   g then t  → Go to Targets
 *   g then s  → Go to Scan History
 *   g then v  → Go to Vulnerabilities
 *   g then e  → Go to Scan Engines
 *   g then n  → Go to Recon Notes
 *   n then s  → New Scan (triggers add-scan button)
 *   n then t  → New Target (triggers add-target button)
 *   Esc       → Close modal / blur active input
 *   [         → Toggle sidebar collapse
 */
(function () {
  'use strict';

  // ── Guard: Only run once ──────────────────────────────────────────────────
  if (window.__rnKeyboardShortcuts) return;
  window.__rnKeyboardShortcuts = true;

  // ── State ─────────────────────────────────────────────────────────────────
  var pendingPrefix = null;   // 'g' or 'n' prefix for two-key combos
  var prefixTimer = null;     // timeout to discard stale prefix
  var COMBO_TIMEOUT = 800;    // ms to wait for second key

  // ── Helpers ───────────────────────────────────────────────────────────────

  /** True when an editable element has focus. */
  function isTyping() {
    var el = document.activeElement;
    if (!el) return false;
    var tag = el.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (el.isContentEditable) return true;
    // Select2 search focus
    if (el.classList.contains('select2-search__field')) return true;
    return false;
  }

  /** Navigate to a sidebar link by partial URL keyword. */
  function gotoSidebarLink(keyword) {
    var links = document.querySelectorAll('.rn-sidebar a[href]');
    for (var i = 0; i < links.length; i++) {
      if (links[i].getAttribute('href').indexOf(keyword) !== -1) {
        window.location.href = links[i].href;
        return true;
      }
    }
    return false;
  }

  /** Clear pending prefix state. */
  function clearPrefix() {
    pendingPrefix = null;
    if (prefixTimer) { clearTimeout(prefixTimer); prefixTimer = null; }
  }

  // ── Help Dialog ───────────────────────────────────────────────────────────

  var shortcuts = [
    { keys: '/', desc: 'Focus search' },
    { keys: '?', desc: 'Show this help' },
    { keys: 'g → d', desc: 'Go to Dashboard' },
    { keys: 'g → t', desc: 'Go to Targets' },
    { keys: 'g → s', desc: 'Go to Scan History' },
    { keys: 'g → v', desc: 'Go to Vulnerabilities' },
    { keys: 'g → e', desc: 'Go to Scan Engines' },
    { keys: 'g → n', desc: 'Go to Recon Notes' },
    { keys: 'n → s', desc: 'New Scan' },
    { keys: 'n → t', desc: 'New Target' },
    { keys: '[', desc: 'Toggle sidebar' },
    { keys: 'Esc', desc: 'Close modal / blur' }
  ];

  function buildHelpHTML() {
    var rows = shortcuts.map(function (s) {
      var badges = s.keys.split(' → ').map(function (k) {
        return '<kbd style="display:inline-block;min-width:24px;padding:3px 8px;' +
          'font-size:12px;font-family:inherit;font-weight:600;text-align:center;' +
          'background:var(--rn-bg-elevated,#f0f3f8);border:1px solid var(--rn-border,#e2e6ed);' +
          'border-radius:4px;color:var(--rn-text-primary,#1a2332);">' + k + '</kbd>';
      }).join(' <span style="color:var(--rn-text-muted);margin:0 2px;">→</span> ');
      return '<tr>' +
        '<td style="padding:6px 12px;white-space:nowrap;">' + badges + '</td>' +
        '<td style="padding:6px 12px;color:var(--rn-text-secondary,#546e7a);">' + s.desc + '</td>' +
        '</tr>';
    }).join('');

    return '<div style="max-width:400px;">' +
      '<table style="width:100%;border-collapse:collapse;">' +
      '<tbody>' + rows + '</tbody></table></div>';
  }

  function showHelpDialog() {
    if (typeof Swal !== 'undefined') {
      Swal.fire({
        title: 'Keyboard Shortcuts',
        html: buildHelpHTML(),
        showConfirmButton: false,
        showCloseButton: true,
        width: 460,
        customClass: { popup: 'rn-shortcuts-popup' }
      });
    }
  }

  // ── Main Keydown Handler ──────────────────────────────────────────────────

  document.addEventListener('keydown', function (e) {
    // Never intercept inside modals with inputs or while typing
    if (isTyping()) {
      // Only Esc is active while typing — to blur out
      if (e.key === 'Escape') {
        document.activeElement.blur();
        clearPrefix();
      }
      return;
    }

    // Don't intercept if Ctrl/Cmd/Alt is held (browser shortcuts)
    if (e.ctrlKey || e.metaKey || e.altKey) return;

    var key = e.key;

    // ── Two-key combos (g → x, n → x) ──────────────────────────────────
    if (pendingPrefix) {
      var prefix = pendingPrefix;
      clearPrefix();
      e.preventDefault();

      if (prefix === 'g') {
        switch (key) {
          case 'd': gotoSidebarLink('dashboard'); return;
          case 't': gotoSidebarLink('target'); return;
          case 's': gotoSidebarLink('scan_history'); return;
          case 'v': gotoSidebarLink('vulnerabilities'); return;
          case 'e': gotoSidebarLink('scan_engine'); return;
          case 'n': gotoSidebarLink('note'); return;
        }
      }

      if (prefix === 'n') {
        switch (key) {
          case 's':
            // Trigger sidebar "Scan History" → user starts scan from there
            gotoSidebarLink('scan_history');
            return;
          case 't':
            gotoSidebarLink('target');
            return;
        }
      }
      return; // consumed the combo
    }

    // ── Single-key shortcuts ────────────────────────────────────────────
    switch (key) {
      case '/':
        e.preventDefault();
        var searchInput = document.getElementById('top-search');
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
        return;

      case '?':
        e.preventDefault();
        showHelpDialog();
        return;

      case 'Escape':
        // Close any open Bootstrap modal
        var openModal = document.querySelector('.modal.show');
        if (openModal && typeof bootstrap !== 'undefined') {
          var bsModal = bootstrap.Modal.getInstance(openModal);
          if (bsModal) bsModal.hide();
        }
        // Close Swal dialog
        if (typeof Swal !== 'undefined' && Swal.isVisible()) {
          Swal.close();
        }
        clearPrefix();
        return;

      case '[':
        e.preventDefault();
        var toggleBtn = document.getElementById('sidebar-toggle');
        if (toggleBtn) toggleBtn.click();
        return;

      case 'g':
      case 'n':
        pendingPrefix = key;
        prefixTimer = setTimeout(clearPrefix, COMBO_TIMEOUT);
        return;
    }
  });

})();
