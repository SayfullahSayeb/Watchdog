/**
 * Watchdog dashboard tab switcher.
 *
 * Splits the dashboard into hash-addressable tabs (#watchdog-tab-scan,
 * #watchdog-tab-settings, ...) so the active tab survives refresh and
 * browser navigation. Without JavaScript every panel renders stacked,
 * like the classic one-page layout. The active tab id is also posted
 * with every form so admin-post redirects return to the same tab.
 */
(function () {
    'use strict';

    var wrapper = document.querySelector('.nav-tab-wrapper');
    if (!wrapper) {
        return;
    }

    var links = Array.prototype.slice.call(wrapper.querySelectorAll('.nav-tab'));
    var panels = Array.prototype.slice.call(document.querySelectorAll('.watchdog-tab'));
    var DEFAULT_TAB = 'watchdog-tab-overview';

    function currentId() {
        var id = window.location.hash.replace(/^#/, '');
        if (id && document.getElementById(id)) {
            return id;
        }
        return DEFAULT_TAB;
    }

    function show(id) {
        links.forEach(function (link) {
            if (link.getAttribute('data-tab') === id) {
                link.classList.add('nav-tab-active');
            } else {
                link.classList.remove('nav-tab-active');
            }
        });
        panels.forEach(function (panel) {
            panel.style.display = panel.id === id ? '' : 'none';
        });
    }

    links.forEach(function (link) {
        link.addEventListener('click', function (event) {
            var id = link.getAttribute('data-tab');
            if (window.history && window.history.replaceState) {
                window.history.replaceState(null, '', '#' + id);
            }
            show(id);
            event.preventDefault();
        });
    });

    window.addEventListener('hashchange', function () {
        show(currentId());
    });

    // Keep the active tab when a form posts to admin-post.php: the
    // server reads the hidden field and redirects back to this tab.
    Array.prototype.forEach.call(document.querySelectorAll('form[method="post"]'), function (form) {
        form.addEventListener('submit', function (event) {
            var scopes = form.querySelectorAll('input[name="watchdog_scope[]"]');
            if (scopes.length > 0) {
                var anyChecked = Array.prototype.some.call(scopes, function (input) {
                    return input.checked;
                });
                if (!anyChecked) {
                    event.preventDefault();
                    window.alert('Select at least one scan scope, then start the scan.');
                    return;
                }
            }
            var input = form.querySelector('input[name="watchdog_tab"]');
            if (!input) {
                input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'watchdog_tab';
                form.appendChild(input);
            }
            input.value = currentId();
        });
    });

    show(currentId());
})();
