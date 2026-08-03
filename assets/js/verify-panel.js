/**
 * Watchdog verification panel poller.
 *
 * Refreshes the Verification tab cards in place every few seconds so the
 * user always sees the current state: queued → working on package X →
 * result. No page reload needed and repeated clicking is unnecessary.
 */
(function () {
    'use strict';

    var el = document.getElementById('watchdog-verify-status');
    if (!el || !window.WatchdogVerifyStatus) {
        return;
    }

    var endpoint = window.WatchdogVerifyStatus.endpoint;
    var nonce = window.WatchdogVerifyStatus.nonce || '';

    var CORE_STATE = el.querySelector('.watchdog-core-state');
    var CORE_LIST = el.querySelector('.watchdog-core-list');
    var PKG_STATE = el.querySelector('.watchdog-pkg-state');
    var PKG_SUMMARY = el.querySelector('.watchdog-pkg-summary');
    var PKG_LIST = el.querySelector('.watchdog-pkg-list');

    function fmtTime(ts) {
        var d = new Date((parseInt(ts, 10) || 0) * 1000);
        if (isNaN(d.getTime())) {
            return '';
        }
        function pad(n) { return (n < 10 ? '0' : '') + n; }
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
            ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }

    function clear(node) {
        if (node) {
            node.innerHTML = '';
        }
    }

    function span(text, color) {
        var node = document.createElement('strong');
        node.textContent = text;
        if (color) {
            node.style.color = color;
        }
        return node;
    }

    function code(text) {
        var node = document.createElement('code');
        node.textContent = text;
        return node;
    }

    function fillList(node, items, max) {
        if (!node || !items || !items.length) {
            return;
        }
        var ul = document.createElement('ul');
        ul.style.maxHeight = '180px';
        ul.style.overflow = 'auto';
        items.slice(0, max || 50).forEach(function (item) {
            var li = document.createElement('li');
            li.appendChild(code(String(item)));
            ul.appendChild(li);
        });
        node.appendChild(ul);
    }

    function apply(data) {
        if (!data || !data.success || !data.data) {
            return;
        }
        var s = data.data;
        var active = s.active || '';
        var core = s.core || {};
        var pkgs = s.packages || {};
        var by = pkgs.byStatus || {};

        // Core card
        if (CORE_STATE) {
            clear(CORE_STATE);
            if (active === 'core') {
                CORE_STATE.appendChild(span('Verifying core files now…', '#46b450'));
            } else if (core.pending) {
                CORE_STATE.appendChild(span('Queued — starts within ~2 minutes.', '#f56e28'));
            } else if (core.result && core.result.time) {
                var r = core.result;
                var timeNote = ' (checked ' + fmtTime(r.time) + ')';
                if (r.status === 'clean') {
                    CORE_STATE.appendChild(span('Clean', '#46b450'));
                    CORE_STATE.appendChild(document.createTextNode(' — all ' + (r.verified || 0) + ' checked file(s) match official checksums' + timeNote + '.'));
                } else if (r.status === 'modified') {
                    CORE_STATE.appendChild(span('Modified', '#dc3232'));
                    CORE_STATE.appendChild(document.createTextNode(' — ' + ((r.mismatches || []).length) + ' file(s) differ from the official package' + timeNote + '.'));
                } else if (r.status === 'unavailable') {
                    CORE_STATE.appendChild(span('Unavailable', '#f56e28'));
                    CORE_STATE.appendChild(document.createTextNode(' — no official checksums published for this WordPress version/locale' + timeNote + '.'));
                } else {
                    CORE_STATE.appendChild(span('Error', '#f56e28'));
                    CORE_STATE.appendChild(document.createTextNode(' — could not verify against the checksums API' + timeNote + '.'));
                }
            } else {
                CORE_STATE.appendChild(document.createTextNode('Not verified yet. Click Verify Core Checksums — the result appears here automatically.'));
            }
        }
        clear(CORE_LIST);
        fillList(CORE_LIST, core.result && core.result.mismatches ? core.result.mismatches : [], 50);

        // Packages card
        if (PKG_STATE) {
            clear(PKG_STATE);
            if (active !== '' && active !== 'core') {
                PKG_STATE.appendChild(span('Working on: ', '#46b450'));
                PKG_STATE.appendChild(code(String(active)));
            } else if (parseInt(pkgs.queued, 10) > 0) {
                PKG_STATE.appendChild(span(pkgs.queued + ' package(s) queued — starts within ~2 minutes.', '#f56e28'));
            } else {
                PKG_STATE.appendChild(document.createTextNode('No verification running.'));
            }
        }

        if (PKG_SUMMARY) {
            clear(PKG_SUMMARY);
            var total = 0;
            var parts = [];
            var labels = {
                'clean': 'Clean', 'modified': 'Modified', 'not-on-wordpress': 'Not on WP.org',
                'version-mismatch': 'Version differs', 'download-error': 'Download failed',
                'error': 'Error', 'other': 'Other'
            };
            Object.keys(by).forEach(function (key) {
                var n = parseInt(by[key], 10) || 0;
                total += n;
                parts.push((labels[key] || 'Other') + ' ' + n);
            });
            if (total === 0) {
                PKG_SUMMARY.appendChild(document.createTextNode('No packages verified yet. Click Verify All WP.org Plugins & Themes — results appear here automatically.'));
            } else {
                var strong = document.createElement('strong');
                strong.textContent = 'Verified ' + total + ' package' + (total === 1 ? '' : 's');
                PKG_SUMMARY.appendChild(strong);
                if (parseInt(pkgs.installed, 10) > 0) {
                    PKG_SUMMARY.appendChild(document.createTextNode(' of ' + pkgs.installed));
                }
                PKG_SUMMARY.appendChild(document.createTextNode(' — ' + parts.join(' · ') + '.'));
                if (pkgs.last) {
                    var br = document.createElement('br');
                    var note = document.createElement('span');
                    note.className = 'description';
                    note.textContent = 'Last verification activity: ' + fmtTime(pkgs.last) + '.';
                    PKG_SUMMARY.appendChild(br);
                    PKG_SUMMARY.appendChild(note);
                }
            }
        }

        if (PKG_LIST) {
            var modified = Array.isArray(pkgs.modified) ? pkgs.modified : [];
            clear(PKG_LIST);
            if (modified.length) {
                var h4 = document.createElement('h4');
                h4.style.color = '#dc3232';
                h4.style.margin = '8px 0 4px';
                h4.textContent = 'Modified packages';
                PKG_LIST.appendChild(h4);
                fillList(PKG_LIST, modified, 30);
            }
        }
    }

    function poll() {
        if (typeof window.fetch !== 'function') {
            return;
        }
        var body = new URLSearchParams();
        body.set('action', 'watchdog_verify_status');
        body.set('nonce', nonce);

        window.fetch(endpoint, {
            method: 'POST',
            credentials: 'same-origin',
            body: body
        }).then(function (response) {
            return response.json();
        }).then(function (data) {
            apply(data);
        }).catch(function () {
            // transient failure; the next poll retries
        });
    }

    window.setInterval(poll, 5000);
})();
