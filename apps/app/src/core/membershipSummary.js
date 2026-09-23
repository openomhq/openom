// Client-side push of the advisory membership summary (OPE-278 / the server-keyring-decoupling decision).
//
// After a locally-VERIFIED keyring change, the client asserts its resolved {memberId, role} view to the
// server (RemoteStore.putAccess → PUT /trees/{id}/access). The server stores it advisorily and NEVER parses
// a keyring — so this is the only thing that tells the managed backend "who is in this tree" (for
// notifications, server-side revocation, proposal routing, a sharing dashboard, member-only-write
// anti-spam). It is NOT the security boundary; the crypto is, client-side.
//
// Two ordering hazards, both handled here:
//  - Concurrent multi-device pushes → the server's CAS `generation` (last-writer-wins). On a 409 we re-GET
//    and retry.
//  - A causally-STALE device overwriting a newer view → before asserting, we check our own trust state
//    COVERS the stored engine-opaque `basis` (the frontier the last push was computed from). If not, we're
//    behind: `refresh()` (pull the keyring + recompute) ONCE, then push regardless — advisory data, and
//    honest re-asserts from up-to-date devices reconverge. The one-pull cap stops a bogus stored basis
//    livelocking every honest device into eternal pulls.
//
// `coversBasis` and `refresh` are engine seams (the coverage check is `check_floor` on the dag, a revision
// compare on the chain); they're injected so this orchestration is engine-agnostic and unit-testable.

/** @typedef {import('./types/domain.js').TreeUuid} TreeUuid */
/** @typedef {import('./types/domain.js').MemberId} MemberId */
/** @typedef {import('./types/appCoreApi.js').MembershipSummaryMember} MembershipSummaryMember */
/** @typedef {import('./types/appCoreApi.js').StoredMembershipSummary} StoredMembershipSummary */
/** @typedef {import('./types/appCoreApi.js').MembershipSummaryPutResult} MembershipSummaryPutResult */

/** @typedef {{view: ReadonlyArray<MembershipSummaryMember>, basis: ReadonlyArray<string>}} MembershipSummary */
/** @typedef {{
 *   getAccess: (treeId: TreeUuid) => import('./types/appCoreApi.js').Awaitable<StoredMembershipSummary|null>,
 *   putAccess: (treeId: TreeUuid, body: {
 *     basis: ReadonlyArray<string>, expectedGeneration: number|null,
 *     members: ReadonlyArray<MembershipSummaryMember>
 *   }) => import('./types/appCoreApi.js').Awaitable<MembershipSummaryPutResult>
 * }} MembershipSummaryTransport */
/** @typedef {{
 *   coversBasis?: (storedBasis: ReadonlyArray<string>) => boolean|Promise<boolean>,
 *   refresh?: () => Promise<MembershipSummary>,
 *   maxAttempts?: number
 * }} MembershipSummaryOptions */

/**
 * Assert `current` = `{ view: [{memberId, role}], basis: string[] }` to `remote` for `treeId`.
 *
 * @param {MembershipSummaryTransport} remote a RemoteStore or a compatible transport
 * @param {TreeUuid} treeId
 * @param {MembershipSummary} current
 * @param {MembershipSummaryOptions} [opts]
 * @returns {Promise<MembershipSummaryPutResult>}
 */
export async function pushMembershipSummary(remote, treeId, current, opts = {}) {
  const { coversBasis, refresh, maxAttempts = 3 } = opts;
  let { view, basis } = current;
  let refreshed = false;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const stored = await remote.getAccess(treeId);
    const expected = stored ? stored.generation : null;

    // Coverage guard (once): if a summary exists and our trust state does not cover its basis, we're
    // causally behind — pull + recompute a single time, then assert regardless (bounded, advisory).
    if (!refreshed && stored && expected != null && coversBasis && refresh) {
      const covered = await coversBasis(stored.basis);
      if (!covered) {
        refreshed = true;
        ({ view, basis } = await refresh());
      }
    }

    try {
      return await remote.putAccess(treeId, { basis, expectedGeneration: expected, members: view });
    } catch (/** @type {unknown} */ e) {
      // A concurrent push advanced the generation — re-GET (next loop) and retry. Any other error propagates.
      if (isConflictError(e) && attempt < maxAttempts - 1) continue;
      throw e;
    }
  }
  // Unreachable: the loop either returns or throws.
  throw new Error('pushMembershipSummary: exhausted retries');
}

/** @param {unknown} error */
function isConflictError(error) {
  return typeof error === 'object' && error !== null && 'name' in error && error.name === 'ConflictError';
}
