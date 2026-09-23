import { test, expect } from '@playwright/test';

// The max-Rust app-core sync path in a real browser: real Web Workers running the wasm engine +
// sealer + docsync loop + local store + replicator, meeting only through an in-page transport (the
// server seam). This is the layer the Node fakes can't reach — wasm-in-a-worker + the async worker
// driver around the core's synchronous steps.
test('app-core: two devices converge through the server', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.converge());

  expect(r.aPush.state).toBe('ok');
  expect(r.bPull.state).toBe('ok');
  expect(r.serverSize).toBe(1); // A's one committed batch reached the server
  expect(r.aPeople.map((p: any) => p.id)).toContain('pA');
  // B, which minted nothing, sees A's person + name after one pull — the loop converged.
  expect(r.bPeople.map((p: any) => p.id)).toContain('pA');
  expect(r.bPeople[0].names?.length ?? 0).toBeGreaterThan(0);
  // Gate-2 liveness (OPE-409): a sync tick reported its PULL frontier to PUT /frontier — a non-empty
  // {replica: counter} map, so the server's log-GC can pin its floor to the slowest member's pull point.
  expect(r.reportedFrontier, 'a tick reported a pull frontier').toBeTruthy();
  expect(
    Object.values(r.reportedFrontier).some((v: any) => v > 0),
    'the reported frontier is a non-empty {replica:counter} map',
  ).toBe(true);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: a device does not re-download log objects it already pulled', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.fetchSkipsAlreadyPulled());

  expect(r.firstPassPeople).toBe(3); // B folded all three of A's mints on the first pull
  expect(r.serverLogSize).toBe(3); // the three log objects are still present on the remote (not reaped)
  // OPE-464: the second tick re-lists the remote but fetches NONE of the already-pulled log objects — the
  // whole point of the optimization. Only mutable heads/snapshot pointers may be re-fetched.
  expect(r.secondLogGets, 'no already-pulled log object is re-downloaded').toEqual([]);
  expect(r.peopleAfterSkip, 'state is intact after the skipping tick').toBe(3);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: the durable invite mint record is DEK-sealed at rest', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.inviteSealsMintRecord());

  expect(r.storedByteLen, 'a mint record was persisted').toBeGreaterThan(0);
  // OPE-453: the at-rest bytes are the sealed envelope, not the plaintext record — they must not parse as the
  // JSON object carrying sMacClaim.
  expect(r.looksPlaintext, 'the at-rest bytes are ciphertext, not the plaintext record').toBe(false);
  // ...yet admit still OPENS the sealed record under the DEK and verifies the claimant's MAC end-to-end.
  expect(r.admitError, 'admit opened the sealed record without error').toBeNull();
  expect(r.admitted, 'the seal → store → open round-trip completed through the real worker').toBe(true);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: compaction publishes a snapshot with the covered header', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.compaction());

  expect(r.push.state).toBe('ok');
  expect(r.hasSnapshot, 'a snapshot object was produced + uploaded').toBe(true);
  expect(r.covered, 'the x-openom-covered header rode the snapshot PUT').toBeTruthy();
  const m = JSON.parse(r.covered);
  expect(Object.values(m).some((v: any) => v > 0), 'covered is a non-empty {replica:counter} map').toBe(true);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: an offline mint is offered outbound once a transport attaches', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.offlineThenSync());

  expect(r.offlineResult.state).toBe('no-transport'); // committed locally, nothing pushed yet
  expect(r.serverSize).toBe(1); // after the transport attached, the mint reached the server
  expect(r.bPeople.map((p: any) => p.id)).toContain('pOff'); // and a peer received it
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: an offline mint survives a reload via IndexedDB', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.reloadSurvives());

  expect(r.beforePeople.map((p: any) => p.id)).toContain('pReload'); // minted + committed
  // A fresh core (a reload) hydrated from IndexedDB alone still has it — the durable-outbox gap, closed.
  expect(r.afterPeople.map((p: any) => p.id)).toContain('pReload');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: real keyring lifecycle — provision, mint, reload, unlock', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.provisionUnlockLifecycle());

  expect(r.recoveryCodeLen).toBeGreaterThan(20); // provision returned a real one-time recovery code
  expect(r.beforePeople.map((p: any) => p.id)).toContain('pLife'); // minted under the provisioned key
  expect(r.sameDid).toBe(true); // unlock re-derived the same author identity
  expect(r.afterPeople.map((p: any) => p.id)).toContain('pLife'); // unlock loaded the keyring + hydrated
  expect(r.wrongRejected).toBe(true); // a wrong passphrase is refused
  expect(r.sameWorkerWrongRejected).toBe(true); // closing the last tree also dropped the account handle
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: account candidates verify before snapshot adoption', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const result = await page.evaluate(() => (window as any).__syncWorker.accountCandidateAdoption());
  expect(new Set(result.memberIds).size).toBe(1);
  expect(result.wrongRejected).toBe(true);
  expect(result.statusAfterWrong).toBe('none');
  expect(result.adoptedGeneration).toBe(result.sourceGeneration);
  expect(result.adoptedHash).toEqual(result.sourceHash);
  expect(result.recoveredGeneration).toBe(result.sourceGeneration + 1);
  expect(result.recoveryHash).not.toEqual(result.sourceHash);
  expect(result.recoveryCodeRotated).toBe(true);
  expect(result.retainedMemberIds).toEqual([result.displacedMemberId]);
  expect(result.usedRecoveryRejected).toBe(true);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: account record changes invalidate stale tabs and tree sessions', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const result = await page.evaluate(() => (window as any).__syncWorker.accountCrossTabInvalidation());
  expect(result.staleTreeDropped).toBe(true);
  expect(result.secondStatus).toBe('locked');
  expect(result.oldPassRejected).toBe(true);
  expect(result.reopenedMemberId).toBeTruthy();
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: account backup intent compare-clears only its exact version', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const result = await page.evaluate(() => (window as any).__syncWorker.accountPendingJournal());
  expect(result.staleCleared).toBe(false);
  expect(result.staleStillPending).toBe(true);
  expect(result.exactCleared).toBe(true);
  expect(result.acknowledgedEtag).toBe('"backup-v1"');
  expect(result.pendingKindAfterPassphraseChange).toBe('backup');
  expect(result.pendingKindAfterDowngrade).toBe('revoke');
  expect(result.downgradeRevision).toBe(result.revokeRevision);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

for (const engine of ['chain', 'dag'] as const) {
  test(`app-core: one durable account owns and joins multiple trees (${engine})`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));

    await page.goto('/e2e/sync-worker-harness.html');
    await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

    const result = await page.evaluate((eng) => (
      window as any
    ).__syncWorker.durableAccountAcrossTrees(eng), engine);

    expect(new Set(result.memberIds).size, 'owned and joined identity stays profile-stable').toBe(1);
    expect(result.registrationProofLength, 'registration proof is signed inside the worker').toBe(64);
    expect(result.rotatedRecoveryCodeLength, 'root rotation returns a replacement recovery code').toBeGreaterThan(20);
    expect(result.accountStatuses, 'custody reports create and lock transitions').toEqual(['none', 'unlocked', 'locked']);
    expect(result.oldPassRejected, 'the old profile passphrase is revoked').toBe(true);
    expect(result.joinedDid, 'the account joined the shared tree').toBeTruthy();
    expect(result.reopenedDids.every((did: string) => did.length > 0), 'all trees reopen').toBe(true);
    expect(result.reopenedDids[2], 'joined-tree reopen keeps the same author identity').toBe(result.joinedDid);
    expect(errors, 'no uncaught page errors').toEqual([]);
  });
}

test('app-core: an owner shares a tree and a member joins + verifies through the worker', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareAndVerify());

  // The member genesis-walked the published keyring and unlocked as a member.
  expect(r.joinedDid.length).toBeGreaterThan(0);
  expect(r.serverKeyringHead).toBe(2); // owner published rev 1 (genesis) + rev 2 (after the add)
  expect(r.sync.state).toBe('ok');
  // Verify-on-ingest ACCEPTED the owner's signed write on the shared tree — the member sees it.
  expect(r.memberPeople).toContain('pShared');
  // MEMBER REOPEN (#2): a FRESH worker reopened the joined tree via account unlock + openTree — same identity,
  // same data. Pre-fix, a member reopen fell through to the owner-unlock path (no member branch) and failed.
  expect(r.reopenedDid).toBe(r.joinedDid);
  expect(r.reopenedPeople).toContain('pShared');
  // OPE-293: addMember asserted the resolved membership to the advisory /access — owner + the new member,
  // each with a role, plus a CAS generation and a non-empty basis frontier.
  expect(r.access, 'membership summary was pushed to /access').not.toBeNull();
  expect(r.access.generation).toBeGreaterThanOrEqual(1);
  expect(r.access.basis.length).toBeGreaterThan(0);
  // OPE-543 self-cert ids: /access carries exactly the DERIVED owner + member ids (never caller labels).
  const ids = r.access.members.map((m: any) => m.memberId).sort();
  expect(ids).toEqual([r.ownerMemberId, r.memberMemberId].sort());
  expect(r.access.members.every((m: any) => typeof m.role === 'number')).toBe(true);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: role routes an editor to a proposal a maintainer approves/rejects, owner commits directly', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.proposeApprove());

  // The write-side role pre-check routes by role: the editor cannot commit → submitEdit produced a PROPOSAL;
  // the owner can → submitEdit committed directly.
  expect(r.editorCanCommit, 'an editor cannot commit directly').toBe(false);
  expect(r.editorRouted, "the editor's submitEdit routed to a proposal").toBe(true);
  expect(r.ownerCanCommit, 'the owner can commit directly').toBe(true);
  expect(r.ownerCommitted, "the owner's submitEdit committed directly").toBe(true);
  // The editor sealed a proposal (not a committed delta) and it reached the proposals channel.
  expect(r.proposedId, 'the editor sealed + uploaded a proposal').toBeTruthy();
  expect(r.pendingCount, 'the owner sees one pending proposal').toBe(1);
  // The owner verified + committed it as an attributed delta.
  expect(r.committed, 'ops were committed').toBeGreaterThanOrEqual(1);
  expect(r.afterApproveCount, 'the approved proposal was deleted from the channel').toBe(0);
  // Attribution preserved: the committed record's createdBy is the EDITOR (the proposer), not the approver.
  expect(r.anchorCreatedBy, 'createdBy is preserved as the proposer').toBe(r.editorDid);
  // A rejected proposal is discarded without committing.
  expect(r.rejectedId, 'a second proposal was created').toBeTruthy();
  expect(r.afterRejectCount, 'the rejected proposal was deleted from the channel').toBe(0);
  // Final owner state: the approved editor claim + the owner's own direct commit are live; the reject is not.
  expect(r.ownerPeopleFinal, "the editor's approved person is live on the owner").toContain('pByEditor');
  expect(r.ownerPeopleFinal, "the owner's directly-committed person is live").toContain('pByOwner');
  expect(r.ownerPeopleFinal, 'the rejected edit was never committed').not.toContain('pRejected');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

for (const engine of ['chain', 'dag'] as const) {
  test(`app-core: a joining member sees the owner's pre-share history via the first-share base seal (${engine})`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));

    await page.goto('/e2e/sync-worker-harness.html');
    await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

    const r = await page.evaluate((eng) => (window as any).__syncWorker.preShareVisibility(eng), engine);

    // The owner keeps their OWN pre-share history through the solo→shared re-fold (it is folded as trusted
    // before the §B3 gate goes live — not dropped as an unsigned forgery).
    expect(r.ownerSeesAfterShare, `owner keeps their pre-share tree on ${engine}`).toContain('pPreShare');
    // The first-share base seal pushed a signed snapshot carrying that state.
    expect(r.snapAfterShare, 'a base snapshot was sealed + pushed at first share').toBe(true);
    // The joining member sees the owner's pre-share history + its name claim — authenticated via the signed
    // base, NOT lost to the shared-tree unsigned-reject rule.
    expect(r.sawPreShare, `member sees the owner's pre-share person on ${engine}`).toBe(true);
    expect(r.preShareNames, 'and its pre-share name claim').toBeGreaterThan(0);
    expect(errors, 'no uncaught page errors').toEqual([]);
  });
}

test('app-core: change-history feed decrypts each delta into renderable records through the worker', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.changeHistory());

  // The feed returned at least the one committed change, fully decrypted (no un-viewable entries on the own path).
  expect(r.count, 'the committed delta appears in the history feed').toBeGreaterThanOrEqual(1);
  expect(r.allViewable, 'the device can decrypt its own history').toBe(true);
  expect(r.author, 'each change carries an author').toBeTruthy();
  // The decrypted op-batch carries the minted records — the anchor pA is among them.
  expect(r.ids, "the decrypted change includes the minted anchor's id").toContain('pA');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: an owner removes a member through the worker — rotate, re-unlock, lock out', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareRemoveLockout());

  expect(r.beforeRemoval).toContain('pShared'); // the member joined and saw the shared write
  expect(r.headBefore).toBe(2); // genesis + the add
  expect(r.headAfter).toBe(3); // the removal rotated the keyring and published rev 3
  expect(r.pushState).toBe('ok'); // the re-unlocked owner sealer signs + syncs under the new epoch
  expect(r.ownerAfter).toContain('pShared'); // pre-removal history intact
  expect(r.ownerAfter).toContain('pAfter'); // the post-removal signed write landed
  expect(r.lockedOut).toBe(true); // the removed member can no longer unlock the rotated tree
  // OPE-293: removeMember asserted the rotated membership to /access — the removed member is dropped from the
  // advisory view (the owner remains), and the generation advanced past the add.
  expect(r.accessAfterRemoval, 'rotated membership was pushed to /access').not.toBeNull();
  const idsAfter = r.accessAfterRemoval.members.map((m: any) => m.memberId);
  expect(idsAfter).toContain(r.ownerMemberId);
  expect(idsAfter).not.toContain(r.memberMemberId);
  expect(r.accessAfterRemoval.generation).toBeGreaterThanOrEqual(2); // add (gen 1) then remove (gen 2+)
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: chain removeMember preserves the removed maintainer\'s history via compact-before-remove', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.chainRemovePreservesHistory());

  // The owner folded the member's delta live at removal time.
  expect(r.ownerLiveSees).toContain('pMemberWrite');
  // OPE-421 Slice 3: after a COLD reload the owner re-judges the whole log under the post-removal head (member
  // absent → the look-behind would Drop the delta), yet still projects it — recovered from the compact-before-
  // remove pin. This is the end-to-end proof that pre-removal history survives a cold re-judgement.
  expect(r.seenAfterReload).toContain('pMemberWrite');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: dag distribution — a member joins by pin, writes, and removeMember authors a cover', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareVerifyDag());

  expect(r.joinedDid.length).toBeGreaterThan(0); // the member verified the anchor against the OOB pin + unlocked
  expect(r.wrongPinRejected).toBe(true); // a tampered pin is refused — the founder/freshness trust gate holds
  expect(r.memberSees).toContain('pShared'); // verify-on-ingest accepted the owner's signed dag write
  expect(r.ownerSees).toContain('pShared');
  expect(r.ownerSees).toContain('pMember'); // the member's own maintainer write verified on the owner's pull
  expect(r.keyringGrew).toBe(true); // removeMember rotated + republished the anchor
  expect(r.coverPushed).toBe(1); // removeMember authored + pushed exactly one self-heal cover to the data channel
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: dag self-heal — a remaining member adopts the rotated epoch and covered-accepts removed history', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.dagSelfHealCoveredAccept());

  expect(r.carolBeforeRemoval).not.toContain('pBob'); // carol hadn't pulled bob's write before the removal
  expect(r.carolSyncState).toBe('ok');
  // After the removal, carol adopted the rotated epoch (so she could open the new-epoch cover) and
  // covered-accepted bob's now-removed history — the full self-heal loop, live in a browser.
  expect(r.carolAfter).toContain('pBob');
  expect(r.carolAnomalies).toBe(0); // the cover is honored — nothing rejected
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: dag co-owner promote/demote through the worker — role round-trips via /access', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareChangeRoleDag());

  // OPE-364: the member is admitted as editor, promoted to co-owner, then demoted back to editor — each role
  // reflected in the advisory /access view the worker pushes. Roles are numeric, lower = stronger.
  expect(r.present).toBe(true);
  expect(typeof r.afterAdd).toBe('number');
  expect(r.afterPromote).toBeLessThan(r.afterAdd); // promote raised authority (co-owner is stronger)
  expect(r.afterDemote).toBe(r.afterAdd); // demote restored the original editor role
  expect(r.afterPromote).not.toBe(r.afterDemote);
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: chain co-owner demote through the worker — hard + preserves pre-demote history', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.shareChangeRoleChain());

  // OPE-421: chain co-owner demote is no longer refused. The member is promoted to co-owner then demoted back
  // to editor, each reflected in the advisory /access view (roles numeric, lower = stronger).
  expect(r.present).toBe(true);
  expect(r.afterPromote).toBeLessThan(r.afterDemote); // co-owner (stronger) → editor (weaker)
  // Slice 3: compact-before-demote preserved the demoted member's pre-demote commit across a cold owner reload,
  // even though the look-behind would Drop it under the post-demote head (Editor < Maintainer for a Delta).
  expect(r.seenAfterReload).toContain('pMemberWrite');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: opt-in soft removal — a demoted member\'s trailing edit is queued, approved, and preserved', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.softRemovalApprove());

  // OPE-426: the demoted member's trailing edit was DROPPED into the pending-review queue (not silently lost,
  // not merged) — attributed to the member.
  expect(r.pendingAuthors).toContain(r.memberMemberId);
  expect(r.liveBeforeApprove).not.toContain('pLate'); // dropped, so not projected before review
  // The admin APPROVED it: it folds live, and survives a cold reload (recovered from the pin).
  expect(r.approvedAny).toBe(true);
  expect(r.liveAfterApprove).toContain('pLate');
  expect(r.seenAfterReload).toContain('pLate');
  expect(errors, 'no uncaught page errors').toEqual([]);
});

test('app-core: reset clears the tree for a clean reseed', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto('/e2e/sync-worker-harness.html');
  await page.waitForFunction(() => (window as any).__ready === true, null, { timeout: 25_000 });

  const r = await page.evaluate(() => (window as any).__syncWorker.reseedClears());

  expect(r.beforeIds).toContain('pOld'); // seeded
  expect(r.clearedIds).toEqual([]); // reset emptied the tree
  expect(r.afterIds).toContain('pNew'); // reseed works
  expect(r.afterIds).not.toContain('pOld'); // the old data did not pile up
  expect(errors, 'no uncaught page errors').toEqual([]);
});
