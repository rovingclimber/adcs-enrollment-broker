/* CSP-safe classic script. Load from the application's own origin in the head. */
(function () {
  'use strict';
  var key = 'rc-ui-theme';
  var choices = ['light', 'dark', 'system'];
  var media = window.matchMedia('(prefers-color-scheme: dark)');
  var preference = 'light';
  try { var saved = window.localStorage.getItem(key); if (choices.includes(saved)) preference = saved; } catch (_) {}
  function resolved() { return preference === 'system' ? (media.matches ? 'dark' : 'light') : preference; }
  function apply() {
    var theme = resolved();
    document.documentElement.setAttribute('data-rc-theme', theme);
    document.querySelectorAll('[data-rc-theme-picker]').forEach(function (picker) { picker.value = preference; });
    window.dispatchEvent(new CustomEvent('rc-theme-change', { detail: { preference: preference, theme: theme } }));
  }
  function setTheme(value) {
    if (!choices.includes(value)) throw new TypeError('Theme must be light, dark or system');
    preference = value;
    try { window.localStorage.setItem(key, value); } catch (_) {}
    apply();
  }
  function bind() {
    document.querySelectorAll('[data-rc-theme-picker]').forEach(function (picker) {
      if (picker.dataset.rcThemeBound) return;
      picker.dataset.rcThemeBound = 'true';
      picker.addEventListener('change', function () { setTheme(picker.value); });
    });
    apply();
  }
  media.addEventListener('change', function () { if (preference === 'system') apply(); });
  window.addEventListener('storage', function (event) {
    if (event.key !== key && event.key !== null) return;
    preference = choices.includes(event.newValue) ? event.newValue : 'light';
    apply();
  });
  window.SharedUI = Object.freeze({ setTheme: setTheme, getTheme: function () { return preference; }, getResolvedTheme: resolved, bindThemePickers: bind });
  apply();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind, { once: true });
  else bind();
})();
