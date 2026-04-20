/**
 * paraKang Sidebar Navigation v1.0
 *
 * Manages sidebar collapse/expand, submenu toggling, active state
 * highlighting, mobile overlay, and localStorage persistence.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'parakang-sidebar-collapsed';
  var sidebar = document.getElementById('rn-sidebar');
  var toggleBtn = document.getElementById('sidebar-toggle');
  var overlay = document.getElementById('rn-sidebar-overlay');
  var body = document.body;

  if (!sidebar) return;

  // -------------------------------------------------------
  // 1. Collapse / Expand
  // -------------------------------------------------------
  function isCollapsed() {
    return sidebar.classList.contains('collapsed');
  }

  function collapseSidebar() {
    sidebar.classList.add('collapsed');
    body.classList.add('sidebar-collapsed');
    try { localStorage.setItem(STORAGE_KEY, '1'); } catch (e) {}
  }

  function expandSidebar() {
    sidebar.classList.remove('collapsed');
    body.classList.remove('sidebar-collapsed');
    try { localStorage.setItem(STORAGE_KEY, '0'); } catch (e) {}
  }

  function toggleSidebar() {
    if (window.innerWidth < 768) {
      toggleMobileSidebar();
    } else {
      isCollapsed() ? expandSidebar() : collapseSidebar();
    }
  }

  // Restore saved state (desktop only)
  function restoreSavedState() {
    if (window.innerWidth >= 768) {
      try {
        if (localStorage.getItem(STORAGE_KEY) === '1') {
          collapseSidebar();
        }
      } catch (e) {}
    }
  }

  if (toggleBtn) {
    toggleBtn.addEventListener('click', toggleSidebar);
  }

  restoreSavedState();

  // -------------------------------------------------------
  // 2. Mobile Overlay
  // -------------------------------------------------------
  function toggleMobileSidebar() {
    var isOpen = sidebar.classList.contains('mobile-open');
    if (isOpen) {
      closeMobileSidebar();
    } else {
      sidebar.classList.add('mobile-open');
      if (overlay) overlay.classList.add('active');
    }
  }

  function closeMobileSidebar() {
    sidebar.classList.remove('mobile-open');
    if (overlay) overlay.classList.remove('active');
  }

  if (overlay) {
    overlay.addEventListener('click', closeMobileSidebar);
  }

  // Mobile hamburger in header
  var hamburger = document.getElementById('rn-header-hamburger');
  if (hamburger) {
    hamburger.addEventListener('click', function () {
      toggleMobileSidebar();
    });
  }

  // -------------------------------------------------------
  // 3. Submenu Toggle
  // -------------------------------------------------------
  var subMenuItems = sidebar.querySelectorAll('.rn-sidebar__item--has-sub > .rn-sidebar__link');
  subMenuItems.forEach(function (link) {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      var parent = this.parentElement;

      // If sidebar is collapsed on desktop, don't toggle submenu
      if (isCollapsed() && window.innerWidth >= 768) return;

      // Close other open submenus at the same level
      var siblings = parent.parentElement.querySelectorAll(':scope > .rn-sidebar__item--has-sub.open');
      siblings.forEach(function (sib) {
        if (sib !== parent) sib.classList.remove('open');
      });

      parent.classList.toggle('open');
    });
  });

  // -------------------------------------------------------
  // 4. Active State Detection
  // -------------------------------------------------------
  function setActiveLink() {
    var currentPath = window.location.pathname;
    var allLinks = sidebar.querySelectorAll('.rn-sidebar__link, .rn-sidebar__sublink');

    allLinks.forEach(function (link) {
      link.classList.remove('active');
    });

    var bestMatch = null;
    var bestLen = 0;

    allLinks.forEach(function (link) {
      var href = link.getAttribute('href');
      if (!href || href === '#' || href.startsWith('javascript:')) return;

      // Match current path: exact match or prefix match
      if (currentPath === href || (currentPath.startsWith(href) && href.length > bestLen && href !== '/')) {
        bestMatch = link;
        bestLen = href.length;
      }
    });

    if (bestMatch) {
      bestMatch.classList.add('active');

      // Expand parent submenu if sublink is active
      var parentItem = bestMatch.closest('.rn-sidebar__item--has-sub');
      if (parentItem) {
        parentItem.classList.add('open');
      }
    }
  }

  setActiveLink();

  // -------------------------------------------------------
  // 5. Tippy tooltips for collapsed mode
  // -------------------------------------------------------
  function initSidebarTooltips() {
    if (typeof tippy === 'undefined') return;

    var links = sidebar.querySelectorAll('[data-tippy-content]');
    links.forEach(function (link) {
      if (link._sidebarTippy) return; // already initialized

      link._sidebarTippy = tippy(link, {
        placement: 'right',
        arrow: true,
        delay: [200, 0],
        offset: [0, 12],
        onShow: function (instance) {
          // Only show tooltip when sidebar is collapsed
          if (!isCollapsed() && window.innerWidth >= 1200) {
            return false;
          }
        }
      });
    });
  }

  // Defer tippy init until tippy is available
  if (typeof tippy !== 'undefined') {
    initSidebarTooltips();
  } else {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(initSidebarTooltips, 500);
    });
  }

})();
