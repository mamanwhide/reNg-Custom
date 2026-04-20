/**
 * scan-live-poller.js
 * Lightweight polling-based real-time update system for scan status.
 * Polls the API at intervals and dispatches custom DOM events.
 *
 * Usage:
 *   ScanPoller.start({ projectSlug: 'demo', interval: 10000 });
 *   document.addEventListener('rn:scan-update', function(e) { ... });
 *   ScanPoller.stop();
 *
 * When Django Channels / WebSocket is available, replace the polling
 * internals with a WebSocket connection — the event-based API stays the same.
 */
var ScanPoller = (function () {
  'use strict';

  var timer = null;
  var config = { projectSlug: '', interval: 15000 };
  var lastData = null;

  /** Start polling for scan status updates. */
  function start(options) {
    if (timer) stop();
    if (options) {
      config.projectSlug = options.projectSlug || config.projectSlug;
      config.interval = options.interval || config.interval;
    }
    if (!config.projectSlug) {
      var el = document.querySelector('[data-current-project]');
      if (el) config.projectSlug = el.getAttribute('data-current-project');
    }
    if (!config.projectSlug) return;
    poll();
    timer = setInterval(poll, config.interval);
  }

  /** Stop polling. */
  function stop() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  /** Single poll cycle. */
  function poll() {
    var url = '/api/queryAllScanResultVisualise/?project=' +
      encodeURIComponent(config.projectSlug) + '&format=json';

    fetch(url, {
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function (data) {
        var scans = Array.isArray(data) ? data : (data.results || []);
        var running = scans.filter(function (s) {
          // status 1 = running/pending
          return s.scan_status === 1 || s.scan_status === 0;
        });

        var payload = {
          allScans: scans,
          runningScans: running,
          runningCount: running.length,
          changed: JSON.stringify(running) !== JSON.stringify(lastData)
        };

        lastData = running;

        // Dispatch custom event
        document.dispatchEvent(new CustomEvent('rn:scan-update', { detail: payload }));

        // If running scans detected, poll faster
        if (running.length > 0 && config.interval > 5000) {
          stop();
          config.interval = 5000;
          timer = setInterval(poll, config.interval);
        } else if (running.length === 0 && config.interval < 15000) {
          stop();
          config.interval = 15000;
          timer = setInterval(poll, config.interval);
        }
      })
      .catch(function () {
        // Silently fail — next poll will retry
      });
  }

  return {
    start: start,
    stop: stop
  };

})();

// Auto-start when DOM is ready (if on an authenticated page)
document.addEventListener('DOMContentLoaded', function () {
  // Only start if user is logged in (sidebar exists)
  if (document.getElementById('rn-sidebar')) {
    ScanPoller.start({});

    // Update the header scan counter badge
    document.addEventListener('rn:scan-update', function (e) {
      var badge = document.getElementById('current_scan_counter');
      if (!badge) return;
      var count = e.detail.runningCount || 0;
      badge.textContent = count > 0 ? count : '';
      badge.style.display = count > 0 ? '' : 'none';
    });
  }
});
