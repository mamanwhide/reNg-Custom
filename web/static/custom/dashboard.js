/**
 * dashboard.js — SOC Dashboard JavaScript
 * Provides chart rendering (ApexCharts), counter animations, and sparklines.
 * Loaded via {% static 'custom/dashboard.js' %} on the dashboard page.
 */
var SOCDashboard = (function () {
  'use strict';

  // ── ApexCharts Theme Defaults ─────────────────────────────────────────────

  function getThemeColors() {
    var cs = getComputedStyle(document.documentElement);
    return {
      textPrimary: cs.getPropertyValue('--rn-text-primary').trim() || '#1a2332',
      textMuted: cs.getPropertyValue('--rn-text-muted').trim() || '#90a4ae',
      border: cs.getPropertyValue('--rn-border').trim() || '#e2e6ed',
      bgCard: cs.getPropertyValue('--rn-bg-card').trim() || '#ffffff'
    };
  }

  // ── Counter Animation ─────────────────────────────────────────────────────

  /**
   * Animate a number from 0 to targetValue with easing.
   * @param {HTMLElement} el - The element to update
   * @param {number|string} targetValue - Target number
   */
  function animateCounter(el, targetValue) {
    var target = parseInt(targetValue, 10) || 0;
    if (target === 0) { el.textContent = '0'; return; }

    var duration = Math.min(1500, 300 + target * 2);
    var start = performance.now();

    function step(now) {
      var elapsed = now - start;
      var progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      var eased = 1 - Math.pow(1 - progress, 3);
      var current = Math.round(eased * target);
      el.textContent = current.toLocaleString();
      if (progress < 1) {
        requestAnimationFrame(step);
      }
    }

    requestAnimationFrame(step);
  }


  // ── Sparkline Chart ───────────────────────────────────────────────────────

  /**
   * Render a mini area-sparkline chart.
   * @param {string} selector - CSS selector for the container
   * @param {number[]} data - Array of 7 data points
   * @param {string[]} labels - Array of 7 date labels
   * @param {string} color - Hex color for the line
   */
  function createSparkline(selector, data, labels, color) {
    var el = document.querySelector(selector);
    if (!el) return;

    var theme = getThemeColors();

    var options = {
      chart: {
        type: 'area',
        height: 40,
        sparkline: { enabled: true },
        animations: {
          enabled: true,
          easing: 'easeinout',
          speed: 800
        }
      },
      series: [{ data: data }],
      labels: labels,
      stroke: {
        curve: 'smooth',
        width: 2,
        colors: [color]
      },
      fill: {
        type: 'gradient',
        gradient: {
          shadeIntensity: 1,
          opacityFrom: 0.4,
          opacityTo: 0.05,
          stops: [0, 100],
          colorStops: [{
            offset: 0,
            color: color,
            opacity: 0.4
          }, {
            offset: 100,
            color: color,
            opacity: 0.05
          }]
        }
      },
      tooltip: {
        theme: 'dark',
        fixed: { enabled: false },
        x: { show: true },
        y: {
          formatter: function (val) {
            return val != null ? val.toLocaleString() : '0';
          }
        }
      },
      colors: [color]
    };

    var chart = new ApexCharts(el, options);
    chart.render();
    return chart;
  }


  // ── Donut Chart ───────────────────────────────────────────────────────────

  /**
   * Render a vulnerability severity donut chart.
   * @param {string} selector
   * @param {number[]} series - [critical, high, medium, low, info, unknown]
   * @param {string[]} labels
   * @param {string[]} colors
   */
  function createDonutChart(selector, series, labels, colors) {
    var el = document.querySelector(selector);
    if (!el) return;

    var theme = getThemeColors();

    var total = series.reduce(function (a, b) { return a + b; }, 0);

    var options = {
      chart: {
        type: 'donut',
        height: 260,
        animations: {
          enabled: true,
          easing: 'easeinout',
          speed: 800
        }
      },
      series: series,
      labels: labels,
      colors: colors,
      plotOptions: {
        pie: {
          donut: {
            size: '70%',
            labels: {
              show: true,
              name: { fontSize: '13px', color: theme.textPrimary },
              value: {
                fontSize: '20px',
                fontWeight: 700,
                color: theme.textPrimary,
                formatter: function (val) { return parseInt(val, 10).toLocaleString(); }
              },
              total: {
                show: true,
                label: 'Total',
                fontSize: '12px',
                color: theme.textMuted,
                formatter: function () { return total.toLocaleString(); }
              }
            }
          }
        }
      },
      stroke: { width: 2, colors: [theme.bgCard] },
      legend: {
        position: 'bottom',
        fontSize: '12px',
        labels: { colors: theme.textMuted },
        markers: { width: 10, height: 10, radius: 3 }
      },
      tooltip: {
        y: {
          formatter: function (val) {
            return val.toLocaleString() + ' (' + (total > 0 ? ((val / total) * 100).toFixed(1) : 0) + '%)';
          }
        }
      },
      dataLabels: { enabled: false },
      responsive: [{
        breakpoint: 480,
        options: {
          chart: { height: 220 },
          legend: { position: 'bottom' }
        }
      }]
    };

    var chart = new ApexCharts(el, options);
    chart.render();
    return chart;
  }


  // ── Horizontal Bar Chart ──────────────────────────────────────────────────

  /**
   * Render a horizontal bar chart (IP addresses, ports, technologies).
   * @param {string} selector
   * @param {string} title - Series name
   * @param {number[]} data
   * @param {string[]} categories
   * @param {string} color
   */
  function createBarChart(selector, title, data, categories, color) {
    var el = document.querySelector(selector);
    if (!el) return;

    var theme = getThemeColors();

    // Filter out empty entries
    var filtered = [];
    var filteredCats = [];
    for (var i = 0; i < data.length; i++) {
      if (data[i] > 0 && categories[i]) {
        filtered.push(data[i]);
        filteredCats.push(categories[i]);
      }
    }

    if (filtered.length === 0) {
      el.innerHTML = '<div style="text-align:center;padding:40px;color:' + theme.textMuted + ';">No data available</div>';
      return;
    }

    var options = {
      chart: {
        type: 'bar',
        height: 240,
        toolbar: { show: false },
        animations: {
          enabled: true,
          easing: 'easeinout',
          speed: 600
        }
      },
      series: [{ name: title, data: filtered }],
      plotOptions: {
        bar: {
          horizontal: true,
          borderRadius: 4,
          barHeight: '60%'
        }
      },
      colors: [color],
      xaxis: {
        categories: filteredCats,
        labels: {
          style: { colors: theme.textMuted, fontSize: '11px' }
        },
        axisBorder: { show: false },
        axisTicks: { show: false }
      },
      yaxis: {
        labels: {
          style: { colors: theme.textMuted, fontSize: '11px' },
          maxWidth: 120
        }
      },
      grid: {
        borderColor: theme.border,
        strokeDashArray: 4,
        xaxis: { lines: { show: true } },
        yaxis: { lines: { show: false } }
      },
      tooltip: {
        y: {
          formatter: function (val) { return val.toLocaleString(); }
        }
      },
      dataLabels: {
        enabled: true,
        style: { fontSize: '11px', fontWeight: 600 },
        formatter: function (val) { return val.toLocaleString(); }
      }
    };

    var chart = new ApexCharts(el, options);
    chart.render();
    return chart;
  }


  // ── Public API ────────────────────────────────────────────────────────────

  return {
    animateCounter: animateCounter,
    createSparkline: createSparkline,
    createDonutChart: createDonutChart,
    createBarChart: createBarChart
  };

})();
