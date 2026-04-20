/**
 * vuln-view-switcher.js
 * Handles switching between Table / Summary views on vulnerability pages.
 * Depends on: ApexCharts, DataTables, design-tokens.css (rn-view-switcher, rn-severity-strip)
 */
(function () {
  'use strict';

  if (window.__rnVulnViewSwitcher) return;
  window.__rnVulnViewSwitcher = true;

  var switcher = document.getElementById('vuln-view-switcher');
  if (!switcher) return;

  var tableView = document.getElementById('vuln-table-view');
  var summaryView = document.getElementById('vuln-summary-view');
  if (!tableView || !summaryView) return;

  var donutChart = null;
  var barChart = null;
  var summaryRendered = false;

  // ── View Toggle ──────────────────────────────────────────────────────────

  switcher.addEventListener('click', function (e) {
    var btn = e.target.closest('.rn-view-switcher__btn');
    if (!btn) return;

    var view = btn.getAttribute('data-view');
    switcher.querySelectorAll('.rn-view-switcher__btn').forEach(function (b) {
      b.classList.remove('active');
    });
    btn.classList.add('active');

    if (view === 'summary') {
      tableView.style.display = 'none';
      summaryView.style.display = '';
      renderSummary();
    } else {
      tableView.style.display = '';
      summaryView.style.display = 'none';
    }
  });


  // ── Collect Data from the Page ───────────────────────────────────────────

  function getVulnData() {
    // Try reading from the DataTable first
    var table = null;
    try {
      table = $.fn.DataTable.isDataTable('#vulnerability_results')
        ? $('#vulnerability_results').DataTable()
        : null;
    } catch (e) { /* not initialized yet */ }

    var data = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0, total: 0, names: {} };

    if (table) {
      var rows = table.rows({ search: 'applied' }).data();
      for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var sev = parseInt(row.severity, 10);
        switch (sev) {
          case 4: data.critical++; break;
          case 3: data.high++; break;
          case 2: data.medium++; break;
          case 1: data.low++; break;
          case 0: data.info++; break;
          default: data.unknown++; break;
        }
        var name = row.name || 'Unknown';
        data.names[name] = (data.names[name] || 0) + 1;
        data.total++;
      }
    }
    return data;
  }


  // ── Render Summary ───────────────────────────────────────────────────────

  function renderSummary() {
    var d = getVulnData();

    // Severity strip
    renderSeverityStrip(d);

    // Donut chart
    renderDonut(d);

    // Top names bar chart
    renderTopNames(d);

    summaryRendered = true;
  }

  function renderSeverityStrip(d) {
    var strip = document.getElementById('vuln-summary-strip');
    var labels = document.getElementById('vuln-summary-labels');
    if (!strip) return;

    var total = d.total || 1;
    var segments = [
      { key: 'critical', color: 'var(--rn-critical)', count: d.critical },
      { key: 'high', color: 'var(--rn-high)', count: d.high },
      { key: 'medium', color: 'var(--rn-medium)', count: d.medium },
      { key: 'low', color: 'var(--rn-low)', count: d.low },
      { key: 'info', color: 'var(--rn-info-sev)', count: d.info },
      { key: 'unknown', color: 'var(--rn-unknown)', count: d.unknown }
    ];

    strip.innerHTML = '';
    segments.forEach(function (s) {
      if (s.count === 0) return;
      var seg = document.createElement('div');
      seg.className = 'rn-severity-strip__segment rn-severity-strip__segment--' + s.key;
      seg.style.width = ((s.count / total) * 100).toFixed(1) + '%';
      strip.appendChild(seg);
    });

    if (labels) {
      labels.innerHTML = '';
      segments.forEach(function (s) {
        var lbl = document.createElement('span');
        lbl.className = 'rn-severity-strip__label';
        lbl.innerHTML = '<span class="rn-severity-strip__dot" style="background:' + s.color + ';"></span>' +
          s.key.charAt(0).toUpperCase() + s.key.slice(1) + ': ' + s.count;
        labels.appendChild(lbl);
      });
    }
  }

  function renderDonut(d) {
    var el = document.getElementById('vuln-summary-donut');
    if (!el) return;

    if (donutChart) {
      donutChart.updateSeries([d.critical, d.high, d.medium, d.low, d.info, d.unknown]);
      return;
    }

    if (typeof ApexCharts === 'undefined') {
      el.innerHTML = '<p style="text-align:center;color:var(--rn-text-muted);padding:40px;">ApexCharts not loaded</p>';
      return;
    }

    var cs = getComputedStyle(document.documentElement);
    var bgCard = cs.getPropertyValue('--rn-bg-card').trim() || '#ffffff';
    var textPrimary = cs.getPropertyValue('--rn-text-primary').trim() || '#1a2332';
    var textMuted = cs.getPropertyValue('--rn-text-muted').trim() || '#90a4ae';

    var opts = {
      chart: { type: 'donut', height: 280, animations: { enabled: true, speed: 600 } },
      series: [d.critical, d.high, d.medium, d.low, d.info, d.unknown],
      labels: ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'],
      colors: ['#d32f2f', '#e53935', '#f9a825', '#2e7d32', '#1565c0', '#78909c'],
      plotOptions: {
        pie: {
          donut: {
            size: '70%',
            labels: {
              show: true,
              name: { fontSize: '13px', color: textPrimary },
              value: { fontSize: '20px', fontWeight: 700, color: textPrimary },
              total: {
                show: true, label: 'Total', fontSize: '12px', color: textMuted,
                formatter: function () { return d.total.toLocaleString(); }
              }
            }
          }
        }
      },
      stroke: { width: 2, colors: [bgCard] },
      legend: {
        position: 'bottom', fontSize: '12px',
        labels: { colors: textMuted },
        markers: { width: 10, height: 10, radius: 3 }
      },
      dataLabels: { enabled: false }
    };

    donutChart = new ApexCharts(el, opts);
    donutChart.render();
  }

  function renderTopNames(d) {
    var el = document.getElementById('vuln-summary-top-names');
    if (!el) return;

    // Sort names by count descending, take top 10
    var entries = Object.keys(d.names).map(function (k) { return { name: k, count: d.names[k] }; });
    entries.sort(function (a, b) { return b.count - a.count; });
    entries = entries.slice(0, 10);

    if (entries.length === 0) {
      el.innerHTML = '<p style="text-align:center;color:var(--rn-text-muted);padding:20px;">No vulnerability data</p>';
      return;
    }

    var cats = entries.map(function (e) {
      return e.name.length > 40 ? e.name.substring(0, 37) + '...' : e.name;
    });
    var vals = entries.map(function (e) { return e.count; });

    if (barChart) {
      barChart.updateOptions({
        xaxis: { categories: cats },
        series: [{ data: vals }]
      });
      return;
    }

    if (typeof ApexCharts === 'undefined') {
      el.innerHTML = '<p style="text-align:center;color:var(--rn-text-muted);padding:20px;">ApexCharts not loaded</p>';
      return;
    }

    var cs = getComputedStyle(document.documentElement);
    var textMuted = cs.getPropertyValue('--rn-text-muted').trim() || '#90a4ae';
    var border = cs.getPropertyValue('--rn-border').trim() || '#e2e6ed';

    var opts = {
      chart: { type: 'bar', height: 180, toolbar: { show: false }, animations: { speed: 600 } },
      series: [{ name: 'Count', data: vals }],
      plotOptions: { bar: { horizontal: true, borderRadius: 4, barHeight: '60%' } },
      colors: ['#3283f6'],
      xaxis: {
        categories: cats,
        labels: { style: { colors: textMuted, fontSize: '11px' } },
        axisBorder: { show: false }, axisTicks: { show: false }
      },
      yaxis: {
        labels: { style: { colors: textMuted, fontSize: '11px' }, maxWidth: 200 }
      },
      grid: { borderColor: border, strokeDashArray: 4, xaxis: { lines: { show: true } }, yaxis: { lines: { show: false } } },
      tooltip: { y: { formatter: function (v) { return v.toLocaleString(); } } },
      dataLabels: { enabled: true, style: { fontSize: '11px', fontWeight: 600 } }
    };

    barChart = new ApexCharts(el, opts);
    barChart.render();
  }

})();
