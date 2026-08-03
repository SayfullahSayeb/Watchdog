/**
 * Watchdog dashboard UI layer (progressive enhancement only).
 *
 * Handles the visual shell: light/dark theme, page labels, searchable /
 * sortable tables, copy-to-clipboard and toasts. It never talks to the
 * server and never changes behaviour of the forms; without it the page
 * is fully functional.
 */
(function () {
    'use strict';

    var shell = document.getElementById('watchdog-shell');
    if (!shell) {
        return;
    }

    /* -------------------------------------------------------------- theme */
    var THEME_KEY = 'watchdog-theme';
    var themeToggle = document.getElementById('wd-theme-toggle');

    function systemPrefersDark() {
        return window.matchMedia &&
            window.matchMedia('(prefers-color-scheme: dark)').matches;
    }

    function readTheme() {
        try {
            var saved = window.localStorage.getItem(THEME_KEY);
            if (saved === 'dark' || saved === 'light') {
                return saved;
            }
        } catch (err) { /* storage unavailable */ }
        return systemPrefersDark() ? 'dark' : 'light';
    }

    function applyTheme(theme) {
        shell.setAttribute('data-wd-theme', theme);
        if (themeToggle) {
            var sun = themeToggle.querySelector('.wd-ic-sun');
            var moon = themeToggle.querySelector('.wd-ic-moon');
            if (sun) { sun.hidden = theme !== 'dark'; }
            if (moon) { moon.hidden = theme === 'dark'; }
            themeToggle.setAttribute('aria-label',
                theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
        }
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', function () {
            var next = shell.getAttribute('data-wd-theme') === 'dark' ? 'light' : 'dark';
            try {
                window.localStorage.setItem(THEME_KEY, next);
            } catch (err) { /* ignore */ }
            applyTheme(next);
        });
    }

    applyTheme(readTheme());

    /* --------------------------------------------------------- page title */
    var docTitleSite = (window.WatchdogUi && window.WatchdogUi.siteName) || '';

    function syncTitle() {
        var active = shell.querySelector('.nav-tab-active[data-wd-label]');
        if (active && docTitleSite) {
            document.title = docTitleSite + ' ‹ ' + active.getAttribute('data-wd-label') + ' — WordPress';
        }
    }

    shell.addEventListener('click', syncTitle);
    window.addEventListener('hashchange', syncTitle);
    syncTitle();

    /* ------------------------------------------------------- table filters */
    function applyTableFilter(table) {
        var body = table.tBodies[0];
        if (!body) {
            return;
        }
        var tab = table.getAttribute('data-wd-tab') || '';
        var needle = (table.getAttribute('data-wd-needle') || '').toLowerCase();
        var visible = 0;
        Array.prototype.forEach.call(body.rows, function (row) {
            var okTab = !tab || (row.getAttribute('data-sev') || '') === tab;
            var okNeedle = !needle || row.textContent.toLowerCase().indexOf(needle) !== -1;
            row.style.display = okTab && okNeedle ? '' : 'none';
            if (okTab && okNeedle) {
                visible++;
            }
        });
        var empty = table.querySelector('.wd-table-empty');
        if (empty) {
            empty.style.display = visible === 0 ? '' : 'none';
        }
    }

    document.querySelectorAll('[data-wd-search]').forEach(function (input) {
        var targetId = input.getAttribute('data-wd-search');
        var table = targetId && document.querySelector(targetId);
        if (!table) {
            return;
        }
        input.addEventListener('input', function () {
            table.setAttribute('data-wd-needle', input.value);
            applyTableFilter(table);
        });
    });

    /* ------------------------------------------------- sub-tabs (severity) */
    document.querySelectorAll('.wd-tabs[data-wd-tabgroup]').forEach(function (bar) {
        var group = bar.getAttribute('data-wd-tabgroup');
        var tableSel = bar.getAttribute('data-wd-table');
        var table = tableSel && document.querySelector(tableSel);
        var buttons = Array.prototype.slice.call(bar.querySelectorAll('.wd-tab[data-wd-tab]'));

        function show(key) {
            buttons.forEach(function (btn) {
                var on = btn.getAttribute('data-wd-tab') === key;
                btn.classList.toggle('wd-tab-active', on);
                btn.setAttribute('aria-selected', on ? 'true' : 'false');
            });
            if (table) {
                table.setAttribute('data-wd-tab', key);
                applyTableFilter(table);
            } else {
                document.querySelectorAll('[data-wd-panel-group="' + group + '"]').forEach(function (panel) {
                    panel.style.display = panel.getAttribute('data-wd-panel') === key ? '' : 'none';
                });
            }
        }

        buttons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                show(btn.getAttribute('data-wd-tab'));
            });
        });

        var def = bar.getAttribute('data-wd-default');
        show(def || (buttons[0] ? buttons[0].getAttribute('data-wd-tab') : ''));
    });

    /* ------------------------------------------------------------ sorting */
    document.querySelectorAll('.wd-table').forEach(function (table) {
        Array.prototype.forEach.call(table.querySelectorAll('th.wd-sort'), function (th) {
            th.addEventListener('click', function () {
                var current = th.getAttribute('aria-sort');
                var dir = current === 'ascending' ? 'descending' : 'ascending';
                Array.prototype.forEach.call(table.querySelectorAll('th.wd-sort'), function (other) {
                    other.removeAttribute('aria-sort');
                });
                th.setAttribute('aria-sort', dir);

                var tbody = table.tBodies[0];
                var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
                var rows = Array.prototype.slice.call(tbody.rows);
                rows.sort(function (a, b) {
                    var av = a.cells[idx].textContent.trim();
                    var bv = b.cells[idx].textContent.trim();
                    var an = parseFloat(av.replace(/[^0-9.-]/g, ''));
                    var bn = parseFloat(bv.replace(/[^0-9.-]/g, ''));
                    var cmp;
                    if (!isNaN(an) && !isNaN(bn)) {
                        cmp = an - bn;
                    } else {
                        cmp = av.localeCompare(bv);
                    }
                    return dir === 'ascending' ? cmp : -cmp;
                });
                rows.forEach(function (row) { tbody.appendChild(row); });
            });
        });
    });

    /* --------------------------------------------------------------- copy */
    document.addEventListener('click', function (event) {
        var button = event.target.closest('[data-wd-copy]');
        if (!button) {
            return;
        }
        var selector = button.getAttribute('data-wd-copy');
        var node = document.querySelector(selector);
        if (!node) {
            return;
        }
        var text = node.classList.contains('wd-log-pre') || node.tagName === 'PRE'
            ? node.textContent : node.textContent.trim();
        function done(ok) {
            var label = button.querySelector('.wd-copy-label') || button;
            label.textContent = ok ? 'Copied ✓' : 'Copy failed';
            if (ok) {
                setTimeout(function () { label.textContent = 'Copy'; }, 1800);
            }
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
        } else {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            try {
                document.execCommand('copy');
                done(true);
            } catch (err) {
                done(false);
            }
            document.body.removeChild(ta);
        }
    });

    /* ---------------------------------------------- finding list pagination */
    document.querySelectorAll('[data-wd-paginate]').forEach(function (list) {
        var perPage = parseInt(list.getAttribute('data-wd-paginate'), 10) || 20;
        var items = Array.prototype.slice.call(list.children);
        if (items.length <= perPage) {
            return;
        }
        var page = 1;
        var pages = Math.ceil(items.length / perPage);

        var bar = document.createElement('div');
        bar.className = 'wd-pager';
        var prev = document.createElement('button');
        prev.type = 'button';
        prev.className = 'button button-small';
        prev.textContent = '‹ Prev';
        var label = document.createElement('span');
        label.className = 'wd-pager-label';
        var next = document.createElement('button');
        next.type = 'button';
        next.className = 'button button-small';
        next.textContent = 'Next ›';
        bar.appendChild(prev);
        bar.appendChild(label);
        bar.appendChild(next);
        list.parentNode.insertBefore(bar, list.nextSibling);

        function render() {
            var from = (page - 1) * perPage;
            items.forEach(function (item, i) {
                item.style.display = (i >= from && i < from + perPage) ? '' : 'none';
            });
            label.textContent = 'Page ' + page + ' of ' + pages + ' — ' + items.length + ' items';
            prev.disabled = page === 1;
            next.disabled = page === pages;
        }

        prev.addEventListener('click', function () {
            if (page > 1) {
                page--;
                render();
            }
        });
        next.addEventListener('click', function () {
            if (page < pages) {
                page++;
                render();
            }
        });

        render();
    });

    /* ------------------------------------------------------------ notifications */
    var notice = document.querySelector('.wd-notice > .wd-notice-close');
    if (notice) {
        notice.addEventListener('click', function () {
            var node = notice.closest('.wd-notice');
            if (node) {
                node.style.transition = 'opacity .25s ease, transform .25s ease';
                node.style.opacity = '0';
                node.style.transform = 'translateY(-6px)';
                setTimeout(function () { node.remove(); }, 260);
            }
        });
    }
})();