/* =============================================================================
   paraKang Constants — JavaScript
   Mirrors Python definitions from paraKang/definitions.py.
   Loaded globally in base.html so all scripts can reference these.
   ============================================================================= */

'use strict';

/**
 * Celery Task / Scan Status codes
 * Python source: paraKang/definitions.py  INITIATED_TASK..ABORTED_TASK
 */
const SCAN_STATUS = Object.freeze({
  INITIATED: -1,
  FAILED:     0,
  RUNNING:    1,
  SUCCESS:    2,
  ABORTED:    3,
});

/**
 * Human-readable labels for scan statuses
 */
const SCAN_STATUS_LABEL = Object.freeze({
  [SCAN_STATUS.INITIATED]: 'Initiated',
  [SCAN_STATUS.FAILED]:    'Failed',
  [SCAN_STATUS.RUNNING]:   'Running',
  [SCAN_STATUS.SUCCESS]:   'Completed',
  [SCAN_STATUS.ABORTED]:   'Aborted',
});

/**
 * CSS class suffix for each scan status (maps to .rn-badge--*)
 */
const SCAN_STATUS_BADGE = Object.freeze({
  [SCAN_STATUS.INITIATED]: 'pending',
  [SCAN_STATUS.FAILED]:    'error',
  [SCAN_STATUS.RUNNING]:   'running',
  [SCAN_STATUS.SUCCESS]:   'success',
  [SCAN_STATUS.ABORTED]:   'warning',
});

/**
 * Vulnerability Severity codes
 * Python source: paraKang/definitions.py  NUCLEI_SEVERITY_MAP
 */
const SEVERITY = Object.freeze({
  UNKNOWN:  -1,
  INFO:      0,
  LOW:       1,
  MEDIUM:    2,
  HIGH:      3,
  CRITICAL:  4,
});

/**
 * Human-readable labels for severities
 */
const SEVERITY_LABEL = Object.freeze({
  [SEVERITY.UNKNOWN]:  'Unknown',
  [SEVERITY.INFO]:     'Info',
  [SEVERITY.LOW]:      'Low',
  [SEVERITY.MEDIUM]:   'Medium',
  [SEVERITY.HIGH]:     'High',
  [SEVERITY.CRITICAL]: 'Critical',
});

/**
 * CSS class suffix for each severity (maps to .rn-badge--*)
 */
const SEVERITY_BADGE = Object.freeze({
  [SEVERITY.UNKNOWN]:  'unknown',
  [SEVERITY.INFO]:     'info',
  [SEVERITY.LOW]:      'low',
  [SEVERITY.MEDIUM]:   'medium',
  [SEVERITY.HIGH]:     'high',
  [SEVERITY.CRITICAL]: 'critical',
});

/**
 * Helper: return an HTML badge for a given severity integer.
 * @param {number} sev - Severity code from SEVERITY enum
 * @returns {string} HTML string for badge
 */
function severityBadge(sev) {
  var cls = SEVERITY_BADGE[sev] || 'unknown';
  var label = SEVERITY_LABEL[sev] || 'Unknown';
  return '<span class="rn-badge rn-badge--' + cls + '">' + label + '</span>';
}

/**
 * Helper: return an HTML badge for a given scan status integer.
 * @param {number} status - Status code from SCAN_STATUS enum
 * @returns {string} HTML string for badge
 */
function scanStatusBadge(status) {
  var cls = SCAN_STATUS_BADGE[status] || 'pending';
  var label = SCAN_STATUS_LABEL[status] || 'Unknown';
  return '<span class="rn-badge rn-badge--' + cls + '">' + label + '</span>';
}
