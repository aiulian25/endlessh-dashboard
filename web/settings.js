/* Settings page: everything you manage rather than watch — password, theme,
   backups, and the read-only view of the geography sources and effective
   configuration the container actually loaded. */

import {
  api, esc, toast, renderError, fmtShortDuration, fmtDuration, fmtNumber,
  getSession, getThemePref, setThemePref,
  THEME_DARK, THEME_LIGHT, THEME_SYSTEM,
  signOutAfterPasswordChange,
} from './app.js';
import { renderBackups } from './backups.js';

const THEME_OPTIONS = [
  { value: THEME_SYSTEM, label: 'System' },
  { value: THEME_LIGHT, label: 'Light' },
  { value: THEME_DARK, label: 'Dark' },
];

const DAY_LABEL = (days) => `${fmtNumber(days)} day${Number(days) === 1 ? '' : 's'}`;

const ONLINE_PROVIDER = 'ip-api.com';

function configRows(settings) {
  return [
    ['Scrape interval', `every ${fmtShortDuration(settings.scrape_interval_seconds)}`],
    ['Signed out after', fmtDuration(settings.session_lifetime_seconds)],
    ['History retention', DAY_LABEL(settings.retention_days)],
    ['Backups kept', fmtNumber(settings.backup_keep_last)],
    ['Daily backup', settings.backup_daily_enabled ? 'On' : 'Off'],
    ['Private ranges blocked', settings.block_private ? 'Yes' : 'No'],
    ['Version', settings.version || '—'],
  ];
}

// The three geography sources are tried in this order, so the section lists them
// in it. The online one is the only thing on this page that leaves the host,
// which is why it says so in full rather than reading "enabled".
function geographyRows(settings) {
  const local = settings.geoip_enabled
    ? `Active — ${settings.geoip_source}`
    : 'Not configured — no database mounted';

  const online = settings.geoip_online_enabled
    ? `On — up to ${fmtNumber(settings.geoip_online_rate_per_minute)} lookups a minute`
    : 'Off — no attacker address leaves this host';

  return [
    ['Tarpit labels', 'Always tried first — country and location as the tarpit itself reports them'],
    ['Local database', local],
    [`Online lookups (${ONLINE_PROVIDER})`, online],
  ];
}

function geographyCard(settings) {
  const warning = settings.geoip_online_enabled
    ? `Online lookups are on: the address of each attacker the first two sources could not place is sent to ${ONLINE_PROVIDER}, a third party, over an unencrypted connection. Results are cached and rate-limited.`
    : `Online lookups are off. Switched on, they would send the address of each attacker the first two sources could not place to ${ONLINE_PROVIDER}, a third party.`;

  return `
    <div class="card">
      <div class="card-head">
        <h2 class="card-title">Geography</h2>
        <span class="page-sub">Read-only — set on the server</span>
      </div>
      <div class="table-wrap">
        <table class="kv">
          <tbody>${geographyRows(settings).map(([key, value]) => `
            <tr><th scope="row">${esc(key)}</th><td>${esc(value)}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>
      <div class="card-foot"><span class="filters-note">${esc(warning)}</span></div>
    </div>`;
}

function passwordCard() {
  return `
    <div class="card">
      <div class="card-head"><h2 class="card-title">Change password</h2></div>
      <form class="card-pad stack narrow" id="pw-form" novalidate>
        <div class="field">
          <label for="pw-current">Current password</label>
          <input class="input" id="pw-current" type="password" autocomplete="current-password" required>
        </div>
        <div class="field">
          <label for="pw-new">New password</label>
          <input class="input" id="pw-new" type="password" autocomplete="new-password" required>
        </div>
        <div class="field">
          <label for="pw-confirm">Repeat new password</label>
          <input class="input" id="pw-confirm" type="password" autocomplete="new-password" required>
        </div>
        <p class="form-error" id="pw-error" role="alert" hidden></p>
        <div><button type="submit" class="btn btn-primary">Update password</button></div>
      </form>
    </div>`;
}

function themeCard() {
  const current = getThemePref();
  return `
    <div class="card">
      <div class="card-head"><h2 class="card-title">Appearance</h2></div>
      <div class="card-pad stack">
        <div class="seg" id="theme-seg" role="group" aria-label="Theme preference">
          ${THEME_OPTIONS.map((option) => `
            <button type="button" data-theme-option="${option.value}" aria-pressed="${option.value === current}">${esc(option.label)}</button>`).join('')}
        </div>
        <p class="field-hint">“System” follows your operating system setting and falls back to the dark theme.</p>
      </div>
    </div>`;
}

export async function render(mount) {
  const session = getSession();

  mount.innerHTML = `
    <div class="page-head">
      <h1 class="page-title">Settings</h1>
      ${session ? `<span class="page-sub">Signed in as <strong>${esc(session.username)}</strong></span>` : ''}
    </div>
    ${passwordCard()}
    ${themeCard()}
    <div id="backups-host"></div>
    <div id="geo-card">
      <div class="card"><div class="card-pad"><div class="skeleton w60"></div></div></div>
    </div>
    <div class="card" id="config-card">
      <div class="card-head">
        <h2 class="card-title">Effective configuration</h2>
        <span class="page-sub">Read-only — set on the server</span>
      </div>
      <div class="card-pad"><div class="skeleton w60"></div></div>
    </div>`;

  const themeSeg = mount.querySelector('#theme-seg');
  themeSeg.querySelectorAll('[data-theme-option]').forEach((button) => {
    button.addEventListener('click', () => {
      setThemePref(button.dataset.themeOption);
      themeSeg.querySelectorAll('[data-theme-option]').forEach((other) => {
        other.setAttribute('aria-pressed', String(other.dataset.themeOption === button.dataset.themeOption));
      });
    });
  });

  const form = mount.querySelector('#pw-form');
  const formError = mount.querySelector('#pw-error');

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    formError.hidden = true;

    const current = mount.querySelector('#pw-current').value;
    const next = mount.querySelector('#pw-new').value;
    const confirmValue = mount.querySelector('#pw-confirm').value;

    if (next !== confirmValue) {
      formError.textContent = 'The two new passwords do not match.';
      formError.hidden = false;
      return;
    }

    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await api('/password', { method: 'POST', body: { current_password: current, new_password: next } });
      form.reset();
      // The server drops every session on a password change, so this page is
      // already signed out. Say so and hand over to the login screen rather
      // than letting the next click fail with a bare 401.
      toast('Password updated. Sign in again with your new password.', 'success');
      signOutAfterPasswordChange();
    } catch (error) {
      if (error.status === 401) return;
      formError.textContent = error.message;
      formError.hidden = false;
    } finally {
      button.disabled = false;
    }
  });

  // Backups own their loading and error handling, so this is fired off rather
  // than awaited: a slow listing must not hold up the rest of the page.
  renderBackups(mount.querySelector('#backups-host'));

  const configCard = mount.querySelector('#config-card');
  const geoCard = mount.querySelector('#geo-card');
  const loadConfig = async () => {
    try {
      const settings = await api('/settings');
      geoCard.innerHTML = geographyCard(settings);
      configCard.innerHTML = `
        <div class="card-head">
          <h2 class="card-title">Effective configuration</h2>
          <span class="page-sub">Read-only — set on the server</span>
        </div>
        <div class="table-wrap">
          <table class="kv">
            <tbody>${configRows(settings).map(([key, value]) => `
              <tr><th scope="row">${esc(key)}</th><td>${esc(value)}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>`;
    } catch (error) {
      if (error.status === 401) return;
      geoCard.innerHTML = '';
      configCard.innerHTML = '';
      renderError(configCard, error, loadConfig);
    }
  };

  await loadConfig();
}
