/**
 * Stable presentation hooks for account UI. The lifecycle and action state live outside this file so the
 * visual implementation can evolve without moving auth/account decisions into views.
 */

/** @typedef {import('../core/types/accountUi.js').AccountViewHost} AccountViewHost */

/** @param {AccountViewHost} _app @returns {Node|null} */
export function accountOverlayView(_app) {
  return null;
}

/** @param {AccountViewHost} _app @returns {Node|null} */
export function accountStatusChip(_app) {
  return null;
}
