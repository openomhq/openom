/**
 * Account & sync presentation. Two hooks the plumbing calls:
 *   accountStatusChip(app) — the title-bar status pill (main.js renders it in .titlebar-actions).
 *   accountOverlayView(app) — the independently-mounted account "page" (#account-overlay), shown when
 *     accountUiState().screen !== null, including before a tree exists / while the gate owns the DOM.
 *
 * Design rules (from the plumbing contract):
 *  - auth (signedOut|signedIn|expired) and custody (none|locked|unlocked) are ORTHOGONAL — rendered apart.
 *  - `pending` is a ReadonlySet; never claim "synced"/"done" while its action is present.
 *  - sign-in/up controls are hidden per app.auth.capabilities() (DevAuth has none).
 *  - errors come only from accountUiState().error (already localized); never re-map or show raw provider text.
 *  - onboarding is app.doEnableSync(); no manual register()/backup() surfaced here.
 *  - close/back are disabled while an operation is busy (else it can complete after close and re-open).
 */
import { h, svg, toast } from '../ui/dom.js';
import { t } from '../core/i18n.js';

/** @typedef {import('../core/types/accountUi.js').AccountViewHost} AccountViewHost */
/** @typedef {import('../core/types/accountUi.js').AccountUiState} AccountUiState */
/** @typedef {import('../core/types/accountSession.js').AccountPendingAction} AccountPendingAction */

// --- form field helpers (mirror gate.js; reuse the lock-* input styling) ---

/** @param {boolean} shown */
const revealIcon = (shown) =>
  shown
    ? svg('svg', { width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': 'true' },
        svg('path', { d: 'M3 3l18 18', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round' }),
        svg('path', { d: 'M10.6 6.2A9 9 0 0121 12c-.5 1-1.2 1.9-2 2.7M6.5 7.5A13 13 0 003 12c1.7 3.3 5 5.5 9 5.5 1.2 0 2.3-.2 3.3-.6', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round' }))
    : svg('svg', { width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': 'true' },
        svg('path', { d: 'M3 12c1.7-3.3 5-5.5 9-5.5s7.3 2.2 9 5.5c-1.7 3.3-5 5.5-9 5.5s-7.3-2.2-9-5.5z', stroke: 'currentColor', 'stroke-width': 1.6 }),
        svg('circle', { cx: 12, cy: 12, r: 2.6, stroke: 'currentColor', 'stroke-width': 1.6 }));

/** @param {string} id */
function emailField(id) {
  const input = h('input', {
    id, type: 'email', 'aria-label': t('auth-email'), placeholder: t('auth-email'), autocomplete: 'email',
    autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', inputmode: 'email', class: 'lock-input',
  });
  return { node: h('div', { class: 'lock-field' }, input), input };
}

/** @param {string} id @param {string} label @param {string} autocomplete */
function passField(id, label, autocomplete) {
  const input = h('input', {
    id, type: 'password', 'aria-label': label, placeholder: label, autocomplete,
    autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', class: 'lock-input',
  });
  const toggle = h('button', {
    type: 'button', class: 'lock-reveal', 'aria-label': t('gate-show-pass'), 'aria-pressed': 'false',
    onClick: () => {
      const shown = input.type === 'text';
      input.type = shown ? 'password' : 'text';
      toggle.setAttribute('aria-pressed', String(!shown));
      toggle.replaceChildren(revealIcon(!shown));
      input.focus();
    },
  }, revealIcon(false));
  return { node: h('div', { class: 'lock-field' }, input, toggle), input };
}

/** @param {() => unknown} onSubmit @param {...(Node|string|null)} kids */
function form(onSubmit, ...kids) {
  return h('form', {
    class: 'lock-form', novalidate: 'true',
    onSubmit: (/** @type {SubmitEvent} */ event) => { event.preventDefault(); onSubmit(); },
  }, ...kids);
}
/** @param {Readonly<AccountUiState>} ui */
const errorLine = (ui) => h('div', { class: 'lock-error', role: 'alert', 'aria-live': 'assertive' }, ui.error || '');
/** @param {string} label @param {Record<string, unknown>} [opts] */
const primary = (label, opts = {}) => h('button', { class: 'button-primary', type: 'submit', ...opts }, label);
/** @param {string} label @param {() => unknown} onClick @param {Record<string, unknown>} [opts] */
const secondary = (label, onClick, opts = {}) => h('button', { class: 'button-secondary', type: 'button', onClick, ...opts }, label);
/** @param {string} label @param {() => unknown} onClick @param {boolean} disabled */
const linkGhost = (label, onClick, disabled) => h('button', { class: 'lock-ghost', type: 'button', onClick, disabled }, label);

// ---------------------------------------------------------------------------
// Title-bar status chip
// ---------------------------------------------------------------------------

// Precedence is explicit (contract): conflict > expired > pending > DevAuth > signedOut > backedUp > bound > else.
// "Synced" ONLY when binding==='backedUp' AND no pending AND no conflict.
/** @param {AccountViewHost} app */
function chipState(app) {
  const s = app.account.state();
  const caps = app.auth.capabilities();
  if (s.conflict) return { key: 'account-chip-attention', tone: 'warn' };
  if (s.auth === 'expired') return { key: 'account-chip-expired', tone: 'warn' };
  if (s.pending.size > 0) return { key: 'account-chip-syncing', tone: 'busy' };
  if (!caps.canLogin) return { key: 'account-chip-local', tone: 'muted' };
  if (s.auth === 'signedOut') return { key: 'account-chip-signin', tone: 'accent' };
  if (s.binding === 'backedUp') return { key: 'account-chip-synced', tone: 'ok' };
  if (s.binding === 'bound') return { key: 'account-chip-backup-needed', tone: 'warn' };
  return { key: 'account-chip-sync-off', tone: 'muted' };
}

/** @param {AccountViewHost} app @returns {Node|null} */
export function accountStatusChip(app) {
  if (!app?.account?.state || !app?.auth?.capabilities) return null;
  const { key, tone } = chipState(app);
  return h('button', {
    class: 'account-chip account-chip-' + tone, type: 'button',
    title: t('account-title'), 'aria-label': t('account-title') + ' — ' + t(key),
    onClick: () => app.showAccountView('overview'),
  }, t(key));
}

// ---------------------------------------------------------------------------
// Account overlay ("page")
// ---------------------------------------------------------------------------

/**
 * @param {KeyboardEvent} event
 * @param {HTMLElement} panel
 * @param {() => void} close
 */
function handleDialogKeydown(event, panel, close) {
  if (event.key === 'Escape') {
    event.preventDefault();
    close();
    return;
  }
  if (event.key !== 'Tab') return;
  const focusable = [...panel.querySelectorAll('input:not([disabled]), button:not([disabled])')]
    .filter((element) => element instanceof HTMLElement && !element.hidden);
  if (focusable.length === 0) {
    event.preventDefault();
    panel.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    if (last instanceof HTMLElement) last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    if (first instanceof HTMLElement) first.focus();
  }
}

/** @param {AccountViewHost} app @returns {Node|null} */
export function accountOverlayView(app) {
  const ui = app.accountUiState();
  if (!ui.screen) return null;
  const busy = ui.busy !== null;
  const close = () => { if (!busy) app.closeAccountView(); };

  /** @type {string} */
  let title;
  /** @type {Node} */
  let body;
  switch (ui.screen) {
    case 'signIn': title = t('auth-signin-title'); body = signInScreen(app, ui); break;
    case 'signUp': title = t('auth-signup-title'); body = signUpScreen(app, ui); break;
    case 'confirmationRequired': title = t('auth-confirm-title'); body = confirmationScreen(app, busy); break;
    case 'restore': title = t('account-restore-title'); body = placeholderScreen('account-restore-body', app, busy); break;
    case 'conflict': title = t('account-conflict-title'); body = conflictScreen(app, busy); break;
    default: title = t('account-title'); body = overviewScreen(app, ui);
  }

  const closeBtn = h('button', {
    class: 'account-close', type: 'button', 'aria-label': t('account-action-close'),
    disabled: busy, onClick: close,
  }, '×');
  const panel = h('div', {
    class: 'account-panel', role: 'dialog', 'aria-modal': 'true', 'aria-label': title, tabindex: '-1',
    onClick: (/** @type {MouseEvent} */ event) => event.stopPropagation(),
  }, h('div', { class: 'account-panel-head' }, h('div', { class: 'account-panel-title' }, title), closeBtn),
     body);
  const overlay = h('div', {
    class: 'account-overlay', onClick: close,
    onKeydown: (/** @type {KeyboardEvent} */ event) => handleDialogKeydown(event, panel, close),
  }, panel);
  queueMicrotask(() => {
    if (!panel.isConnected) return;
    const initial = panel.querySelector('input:not([disabled])')
      ?? panel.querySelector('button:not([disabled])');
    if (initial instanceof HTMLElement) initial.focus();
    else panel.focus();
  });
  // Scrim click closes (unless busy); clicks inside the panel don't bubble out to it.
  return overlay;
}

// ---- Overview: auth + custody rendered independently, then sync/pending/conflict/storage ----

/** @param {AccountViewHost} app @param {Readonly<AccountUiState>} ui */
function overviewScreen(app, ui) {
  const s = app.account.state();
  const caps = app.auth.capabilities();
  const busy = ui.busy !== null;
  const rows = [];

  // Auth block
  const authActions = [];
  if (!caps.canLogin) {
    rows.push(statusRow('account-auth-heading', t('account-auth-local'), 'muted'));
  } else if (s.auth === 'signedIn') {
    rows.push(statusRow('account-auth-heading', t('account-auth-signedin'), 'ok'));
    authActions.push(secondary(t('account-action-signout'), () => app.doSignOut(), { disabled: busy }));
  } else {
    const expired = s.auth === 'expired';
    rows.push(statusRow('account-auth-heading', t(expired ? 'account-auth-expired' : 'account-auth-signedout'), expired ? 'warn' : 'muted'));
    authActions.push(secondary(t('account-action-signin'), () => app.showAccountView('signIn'), { disabled: busy }));
    if (caps.canSignUp) authActions.push(secondary(t('account-action-signup'), () => app.showAccountView('signUp'), { disabled: busy }));
  }

  // Custody block (independent of auth)
  const dataKey = s.account === 'unlocked' ? 'account-data-unlocked' : s.account === 'locked' ? 'account-data-locked' : 'account-data-none';
  rows.push(statusRow('account-data-heading', t(dataKey), s.account === 'unlocked' ? 'ok' : 'muted'));

  // Sync / binding
  if (s.account === 'unlocked') {
    const syncKey = s.binding === 'backedUp' ? 'account-sync-backedup' : s.binding === 'bound' ? 'account-sync-bound' : 'account-sync-off';
    rows.push(statusRow(null, t(syncKey), s.binding === 'backedUp' ? 'ok' : 'muted'));
  }

  // Pending (never claim "done" while present)
  /** @type {Record<AccountPendingAction, string>} */
  const pendingMessages = {
    register: 'account-pending-register',
    restore: 'account-pending-restore',
    backup: 'account-pending-backup',
    revoke: 'account-pending-revoke',
  };
  for (const operation of s.pending) {
    const key = pendingMessages[operation];
    if (key) rows.push(noteRow(t(key), 'busy'));
  }

  // Enable sync: signed in + unlocked + not yet backed up (incl. bound); hidden on conflict/localOnly/busy/pending.
  const canEnableSync = s.auth === 'signedIn' && s.account === 'unlocked' && s.binding !== 'backedUp'
    && !s.conflict && s.syncDisposition !== 'localOnly' && !busy
    && s.pending.size === 0;
  const actions = [...authActions];
  if (canEnableSync) actions.unshift(h('button', { class: 'button-primary', type: 'button', disabled: busy, onClick: () => app.doEnableSync() }, t('account-action-enable-sync')));
  if (s.conflict) actions.push(secondary(t('account-action-resolve'), () => app.showAccountView('conflict'), { disabled: busy }));

  const extras = [];
  if (s.conflict) extras.push(noteRow(t('account-conflict-title'), 'warn'));
  if (s.storagePersistence === 'denied') extras.push(noteRow(t('account-storage-denied'), 'warn'));

  return h('div', { class: 'stack', style: { gap: '16px' } },
    h('div', { class: 'stack', style: { gap: '10px' } }, ...rows),
    ...extras,
    errorLine(ui),
    actions.length ? h('div', { class: 'row', style: { gap: '10px', flexWrap: 'wrap' } }, ...actions) : null,
    h('div', { class: 'muted', style: { fontSize: 'var(--t-small)', textWrap: 'pretty' } }, t('account-two-secrets')));
}

/** @param {string|null} headingKey @param {string} value @param {string} tone */
function statusRow(headingKey, value, tone) {
  return h('div', { class: 'row between', style: { alignItems: 'baseline', gap: '12px' } },
    headingKey ? h('span', { class: 'section-label', style: { margin: 0 } }, t(headingKey)) : h('span', {}),
    h('span', { class: 'account-status account-status-' + (tone || 'muted') }, value));
}
/** @param {string} text @param {string} tone */
function noteRow(text, tone) {
  return h('div', { class: 'account-note account-note-' + (tone || 'muted') }, text);
}

// ---- Sign in ----

/** @param {AccountViewHost} app @param {Readonly<AccountUiState>} ui */
function signInScreen(app, ui) {
  const caps = app.auth.capabilities();
  const email = emailField('account-email');
  const pass = passField('account-pass', t('auth-password'), 'current-password');
  const busy = ui.busy === 'signIn';
  const submit = () => app.doSignIn(email.input.value, pass.input.value);
  return h('div', { class: 'stack', style: { gap: '14px' } },
    h('div', { class: 'muted', style: { fontSize: 'var(--t-small)', textWrap: 'pretty' } }, t('auth-signin-subtitle')),
    form(submit, email.node, pass.node, errorLine(ui),
      primary(busy ? t('auth-signin-busy') : t('auth-signin-submit'), { disabled: ui.busy !== null })),
    caps.canSignUp ? linkGhost(t('auth-to-signup'), () => app.showAccountView('signUp'), ui.busy !== null) : null);
}

// ---- Sign up (Supabase). Router handles signedIn vs confirmationRequired; this view just submits. ----

/** @param {AccountViewHost} app @param {Readonly<AccountUiState>} ui */
function signUpScreen(app, ui) {
  const email = emailField('account-email');
  const p1 = passField('account-pass', t('auth-password'), 'new-password');
  const p2 = passField('account-pass2', t('auth-password-confirm'), 'new-password');
  const busy = ui.busy === 'signUp';
  const submit = () => {
    if (p1.input.value !== p2.input.value) { toast(t('auth-signup-mismatch')); return; }
    app.doSignUp(email.input.value, p1.input.value);
  };
  return h('div', { class: 'stack', style: { gap: '14px' } },
    h('div', { class: 'muted', style: { fontSize: 'var(--t-small)', textWrap: 'pretty' } }, t('auth-signup-subtitle')),
    form(submit, email.node, p1.node, p2.node, errorLine(ui),
      primary(busy ? t('auth-signup-busy') : t('auth-signup-submit'), { disabled: ui.busy !== null })),
    linkGhost(t('auth-to-signin'), () => app.showAccountView('signIn'), ui.busy !== null));
}

// ---- Email confirmation required ----

/** @param {AccountViewHost} app @param {boolean} busy */
function confirmationScreen(app, busy) {
  return h('div', { class: 'stack', style: { gap: '14px' } },
    h('div', { class: 'muted', style: { textWrap: 'pretty' } }, t('auth-confirm-body')),
    h('div', { class: 'row', style: { gap: '10px' } },
      secondary(t('auth-confirm-back'), () => app.showAccountView('signIn'), { disabled: busy })));
}

// ---- Non-destructive placeholders: explain arrival and always offer back/close ----

/** @param {string} bodyKey @param {AccountViewHost} app @param {boolean} busy */
function placeholderScreen(bodyKey, app, busy) {
  return h('div', { class: 'stack', style: { gap: '14px' } },
    h('div', { class: 'muted', style: { textWrap: 'pretty' } }, t(bodyKey)),
    h('div', { class: 'row', style: { gap: '10px' } },
      secondary(t('account-action-back'), () => app.showAccountView('overview'), { disabled: busy })));
}

/** @param {AccountViewHost} app @param {boolean} busy */
function conflictScreen(app, busy) {
  return h('div', { class: 'stack', style: { gap: '14px' } },
    h('div', { class: 'muted', style: { textWrap: 'pretty' } }, t('account-conflict-body')),
    h('div', { class: 'row', style: { gap: '10px' } },
      secondary(t('account-action-back'), () => app.showAccountView('overview'), { disabled: busy })));
}
