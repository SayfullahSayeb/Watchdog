/**
 * Watchdog dashboard scan progress poller.
 *
 * While a scan is active the progress panel is refreshed from the
 * server every few seconds without reloading the page, so the current
 * stage (files processed / total, running or paused) stays visible.
 * When the run completes the page is reloaded once to show results.
 */
(function () {
    'use strict';

    var el = document.getElementById('watchdog-scan-progress');
    if (!el || !window.WatchdogScanProgress) {
        return;
    }

    var endpoint = window.WatchdogScanProgress.endpoint;
    var nonce = window.WatchdogScanProgress.nonce || '';
    var reloading = false;
    var finishedPolls = 0;
    var inFlight = false;

    function isVisible(node) {
        return node.offsetParent !== null;
    }

    function apply(progress) {
        var total = parseInt(progress.total, 10) || 0;
        var scanned = Math.min(parseInt(progress.scanned, 10) || 0, total);
        var percent = total > 0 ? Math.round((scanned / total) * 100) : 0;
        var fill = el.querySelector('.watchdog-progress-fill');
        var status = el.querySelector('.watchdog-progress-status');
        var scope = el.querySelector('.watchdog-progress-scope');
        var meta = el.querySelector('.watchdog-progress-meta');
        var pct = el.querySelector('.watchdog-progress-pct');
        var current = el.querySelector('.watchdog-progress-current');
        var segment = el.querySelector('.watchdog-progress-segment');
        var eta = el.querySelector('.watchdog-progress-eta');
        var log = el.querySelector('.watchdog-progress-log');

        if (fill) {
            fill.style.width = percent + '%';
        }
        if (status) {
            status.textContent = progress.running ? 'Scanning' : 'Scan queued';
        }
        if (scope) {
            scope.textContent = progress.scope_label || 'Everything';
        }
        if (meta) {
            meta.innerHTML = '';
            var strong = document.createElement('strong');
            strong.textContent = scanned.toLocaleString() + ' ';
            meta.appendChild(strong);
            meta.appendChild(document.createTextNode(
                'of ' + total.toLocaleString() + ' files processed'));
        }
        if (pct) {
            pct.textContent = percent + '%';
        }
        if (current) {
            current.innerHTML = '';
            if (progress.current_path) {
                var fresh = progress.current_updated &&
                    ((Date.now() / 1000) - progress.current_updated) < 75;
                current.appendChild(document.createTextNode(
                    (fresh ? 'Scanning: ' : 'Last file: ')));
                var code = document.createElement('code');
                code.textContent = progress.current_path;
                current.appendChild(code);
            }
        }
        if (segment) {
            segment.textContent = String(parseInt(progress.segments, 10) || 1);
        }
        if (eta) {
            eta.textContent = progress.running ? 'Running' : 'Queued — next segment';
        }
        if (log && Array.isArray(progress.current_files) && progress.current_files.length) {
            log.innerHTML = '';
            progress.current_files.forEach(function (file) {
                var item = document.createElement('li');
                var stamp = document.createElement('span');
                stamp.className = 'wd-file-stamp';
                stamp.textContent = (file && file.ts ? new Date(file.ts * 1000) : new Date(0))
                    .toISOString().slice(11, 19);
                var code = document.createElement('code');
                code.textContent = file ? (file.path || '') : '';
                item.appendChild(stamp);
                item.appendChild(code);
                log.appendChild(item);
            });
        }

        updateStages(percent);
    }

    var STAGE_THRESHOLDS = [0, 20, 45, 75, 95];

    function updateStages(percent) {
        var stages = el.querySelectorAll('.wd-stage');
        if (!stages.length) {
            return;
        }
        Array.prototype.forEach.call(stages, function (stage, i) {
            var done = percent >= (STAGE_THRESHOLDS[i] || 101);
            stage.classList.toggle('wd-stage-done', done);
            stage.classList.toggle('wd-stage-active',
                !done && i === firstPending(stages, percent));
            stage.classList.toggle('wd-stage-pending',
                !done && i !== firstPending(stages, percent));
        });
    }

    function firstPending(stages, percent) {
        for (var i = 0; i < stages.length; i++) {
            if (percent < (STAGE_THRESHOLDS[i] || 101)) {
                return i;
            }
        }
        return stages.length;
    }

    function poll() {
        if (reloading || inFlight || typeof window.fetch !== 'function') {
            return;
        }
        // Each poll may run the next scan segment server-side (up to the
        // segment budget), so requests can take much longer than 5s.
        // Never let two run at once.
        inFlight = true;
        var body = new URLSearchParams();
        body.set('action', 'watchdog_scan_progress');
        body.set('nonce', nonce);

        window.fetch(endpoint, {
            method: 'POST',
            credentials: 'same-origin',
            body: body
        }).then(function (response) {
            return response.json();
        }).then(function (data) {
            inFlight = false;
            if (!data || !data.success) {
                return;
            }
            if (data.data === null || data.data === undefined) {
                // Run finished (the poll that ran the last segment returns
                // no payload). Reload to show the results — immediately
                // when the Scan tab is visible, or as soon as the user
                // opens it (a few more polls are kept for that).
                finishedPolls++;
                if (isVisible(el)) {
                    reloading = true;
                    window.location.reload();
                    return;
                }
                if (finishedPolls > 24) {
                    window.clearInterval(timer);
                }
                return;
            }
            finishedPolls = 0;
            try {
                apply(data.data);
            } catch (e) {
                // malformed payload; the next poll retries
            }
        }).catch(function () {
            // transient failure; the next poll retries
            inFlight = false;
        });
    }

    var timer = window.setInterval(poll, 5000);
    poll();
})();
