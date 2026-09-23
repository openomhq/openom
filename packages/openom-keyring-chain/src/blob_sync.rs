//! Fit the linear chain keyring to the `blobstore` seam (OPE-265).
//!
//! The keyring is one small, low-contention register, so **per-object CAS is its sequencer**: the current
//! keyring lives at a single CAS'd `keyring/head`, with an append-only `keyring/rev/{n}` history so a
//! lagging replica can [`verify_walk`](crate::verify_walk) up to the head. This works on a managed
//! backend and a dumb BYO one alike.
//!
//! This is the storage transport only. The crypto that *produces* keyrings —
//! provision / recover / change-passphrase, in openom-sealer's vault — is a pure `bytes -> bytes`
//! lifecycle (it takes the current keyring bytes and returns the next), so every operation publishes its
//! output through here unchanged. Recovery is the one that isn't a plain transition: a reset re-founds
//! the identity, so [`verify_transition`](crate::verify_transition) rejects it — it surfaces on pull as
//! [`PullError::ResetPending`] (the client's out-of-band re-verify ceremony) and is adopted via
//! [`KeyringChainBlobSync::accept_reset`], never silently walked.

use prost::Message;
use store_blob::{BlobError, BlobStore, Etag, Precondition};

use crate::keyring::signing_bytes as keyring_signing_bytes;
use crate::wire::Keyring;
use crate::{
    keyring_hash, sign_keyring, verify_reset, verify_transition, verify_walk, KeyringAnchor,
    KeyringError, SigningKey,
};

const HEAD: &str = "keyring/head";
const DRAFT_PREFIX: &str = "keyring/drafts/";

fn rev_key(n: u32) -> String {
    format!("keyring/rev/{n}")
}

fn draft_key(id: &str) -> String {
    format!("{DRAFT_PREFIX}{id}")
}

/// The outcome of trying to promote a draft candidate to the head.
#[derive(Debug, PartialEq, Eq)]
pub enum Promotion {
    /// The draft met the governance rule and advanced the head.
    Promoted,
    /// A valid candidate, but it doesn't yet carry enough signatures for the rule.
    NotReady,
    /// The head moved out from under it (a competing revision) — the draft no longer chains, so it must
    /// be rebuilt on the new head and re-signed. A *safe* re-propose, never a corruption.
    Stale,
}

/// A transport failure (as opposed to a governance decision — see [`PullError`]).
#[derive(Debug)]
pub enum SyncError {
    Store(BlobError),
    Decode(String),
    Chain(String),
    Malformed(&'static str),
    /// The head advanced under us during a publish — pull, re-produce the keyring, and publish again.
    Conflict,
    /// A countersign was asked to sign a draft whose current content differs from the bytes the caller
    /// reviewed — a store swapped the draft between review and signature. Refused: a signer must never
    /// certify content they did not see. Re-review the current draft, then countersign that.
    DraftContentChanged,
}

impl From<BlobError> for SyncError {
    fn from(e: BlobError) -> Self {
        Self::Store(e)
    }
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "blob store: {e}"),
            Self::Decode(e) => write!(f, "keyring decode: {e}"),
            Self::Chain(e) => write!(f, "chain rejected: {e}"),
            Self::Malformed(m) => write!(f, "malformed keyring transport state: {m}"),
            Self::Conflict => write!(f, "head advanced concurrently; retry"),
            Self::DraftContentChanged => {
                write!(
                    f,
                    "draft content changed since review; re-review before countersigning"
                )
            }
        }
    }
}
impl std::error::Error for SyncError {}

/// Pulling can surface a decision the transport can't make itself.
#[derive(Debug)]
pub enum PullError {
    Sync(SyncError),
    /// The served head is OLDER than what we've accepted — a rollback / stale-serve attack.
    Rollback {
        have: u32,
        served: u32,
    },
    /// The head is a recovery RESET (a new, deliberately-unendorsed founder). The client must confirm it
    /// out of band (surface the hash + revision), then call [`KeyringChainBlobSync::accept_reset`].
    ResetPending,
}

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sync(e) => write!(f, "{e}"),
            Self::Rollback { have, served } => {
                write!(f, "rollback: have revision {have}, store served {served}")
            }
            Self::ResetPending => {
                write!(f, "head is a recovery reset; awaiting out-of-band confirm")
            }
        }
    }
}
impl std::error::Error for PullError {}

/// One replica's Blob transport for a chain keyring: publishes locally-produced keyrings and pulls
/// remote advances, holding the trusted [`KeyringAnchor`] and the head etag for CAS.
pub struct KeyringChainBlobSync<S: BlobStore> {
    store: S,
    anchor: Option<KeyringAnchor>,
    head_etag: Option<Etag>,
}

impl<S: BlobStore> KeyringChainBlobSync<S> {
    pub const fn new(store: S) -> Self {
        Self {
            store,
            anchor: None,
            head_etag: None,
        }
    }

    /// The revision this replica currently trusts (its anti-rollback watermark), if bootstrapped.
    pub fn revision(&self) -> Option<u32> {
        self.anchor.as_ref().map(|a| a.revision)
    }

    /// Publish a locally-produced keyring (the vault's output bytes). Writes its immutable `rev/{n}` blob
    /// and CAS-advances the head; adopts it as the local anchor (own production is trusted). Returns
    /// [`SyncError::Conflict`] if another replica advanced the head first (pull + re-produce + retry).
    ///
    /// # Errors
    /// Returns [`SyncError::Conflict`] on a concurrent head advance, or [`SyncError`] on a store/decode error.
    pub fn publish(&mut self, keyring_bytes: &[u8]) -> Result<(), SyncError> {
        let keyring = decode(keyring_bytes)?;
        match self.store.put(
            &rev_key(keyring.revision),
            keyring_bytes,
            Precondition::IfAbsent,
        ) {
            Ok(_) | Err(BlobError::PreconditionFailed) => {} // immutable + idempotent
            Err(e) => return Err(SyncError::Store(e)),
        }
        // First publish (no head yet): create-only. Otherwise CAS onto the etag we last saw.
        let pre = match &self.head_etag {
            Some(e) => Precondition::IfMatch(e.clone()),
            None => Precondition::IfAbsent,
        };
        let etag = self
            .store
            .put(HEAD, keyring_bytes, pre)
            .map_err(|e| match e {
                BlobError::PreconditionFailed => SyncError::Conflict,
                // A keyring HEAD is a pointer, never GC-reaped below a floor, so a `Gone` on this write is a
                // store-level anomaly, not a bootstrap signal — surface it as a store error (exhaustiveness for
                // the new `BlobError::Gone`, OPE-409 C2).
                err @ (BlobError::Backend(_) | BlobError::Gone) => SyncError::Store(err),
            })?;
        self.head_etag = Some(etag);
        self.anchor = Some(KeyringAnchor::from_keyring(&keyring));
        Ok(())
    }

    /// First-sight trust from the head (genesis, or an out-of-band-pinned head): [`verify_reset`] accepts
    /// it on its own terms. Sets the anchor. Returns the keyring bytes, or `None` if there is no head.
    ///
    /// # Errors
    /// Returns [`SyncError`] on a store error or if the fetched head fails to decode or verify.
    pub fn bootstrap(&mut self) -> Result<Option<Vec<u8>>, SyncError> {
        let Some((bytes, etag)) = self.store.get(HEAD)? else {
            return Ok(None);
        };
        let keyring = decode(&bytes)?;
        // First sight has no prior recovery authority to check continuity against (OOB trust root).
        self.anchor = Some(verify_reset(None, &keyring).map_err(chain_err)?);
        self.head_etag = Some(etag);
        Ok(Some(bytes))
    }

    /// Pull the head and verify it advances the anchor ([`verify_walk`] over any skipped revisions).
    /// Returns the new keyring bytes if it advanced, `None` if unchanged. Rejects a rollback; surfaces a
    /// recovery reset as [`PullError::ResetPending`].
    ///
    /// # Errors
    /// Returns [`PullError::ResetPending`] if a recovery reset is pending, or [`PullError`] on a store,
    /// decode, or verification failure.
    pub fn pull(&mut self) -> Result<Option<Vec<u8>>, PullError> {
        let Some(anchor) = self.anchor.clone() else {
            return self.bootstrap().map_err(PullError::Sync);
        };
        let Some((bytes, etag)) = self
            .store
            .get(HEAD)
            .map_err(|e| PullError::Sync(e.into()))?
        else {
            return Ok(None);
        };
        let head = decode(&bytes).map_err(PullError::Sync)?;
        if head.revision < anchor.revision {
            return Err(PullError::Rollback {
                have: anchor.revision,
                served: head.revision,
            });
        }
        if head.revision == anchor.revision {
            if keyring_hash(&head) != anchor.keyring_hash {
                return Err(PullError::Sync(SyncError::Malformed(
                    "store served a different keyring at the same revision",
                )));
            }
            self.head_etag = Some(etag);
            return Ok(None);
        }
        // Gather the skipped revisions from history, then the head, and walk them.
        let mut hops = Vec::new();
        for n in (anchor.revision + 1)..head.revision {
            let (rb, _) = self
                .store
                .get(&rev_key(n))
                .map_err(|e| PullError::Sync(e.into()))?
                .ok_or(PullError::Sync(SyncError::Malformed(
                    "missing revision in history",
                )))?;
            hops.push(decode(&rb).map_err(PullError::Sync)?);
        }
        hops.push(head);
        match verify_walk(&anchor, &hops) {
            Ok(new_anchor) => {
                self.anchor = Some(new_anchor);
                self.head_etag = Some(etag);
                Ok(Some(bytes))
            }
            // An unendorsed set change on the walk is a recovery reset — needs the OOB ceremony.
            Err(KeyringError::UnendorsedSetChange) => Err(PullError::ResetPending),
            Err(e) => Err(PullError::Sync(SyncError::Chain(format!("{e:?}")))),
        }
    }

    /// Adopt the head as a recovery reset, AFTER the client's out-of-band confirmation: run
    /// [`verify_reset`] and set the anchor. Refuses a reset whose revision is behind the watermark.
    /// Returns the keyring bytes.
    ///
    /// # Errors
    /// Returns [`SyncError`] on a store error or if the reset fails to decode or verify.
    pub fn accept_reset(&mut self) -> Result<Vec<u8>, SyncError> {
        let Some((bytes, etag)) = self.store.get(HEAD)? else {
            return Err(SyncError::Malformed("no head to accept"));
        };
        let keyring = decode(&bytes)?;
        if let Some(a) = &self.anchor {
            if keyring.revision < a.revision {
                return Err(SyncError::Malformed(
                    "reset revision is behind the watermark",
                ));
            }
        }
        // A reset accepted against an existing anchor must be continuous with — and signed by — the
        // prior recovery authority (RVK), so a served reset can't re-found the tree under a forged
        // recovery root. Inactive if the prior pinned no RVK (pre-RVK keyrings).
        let prior_rvk = self
            .anchor
            .as_ref()
            .map(|a| a.recovery_verifying_key.as_slice())
            .filter(|rvk| !rvk.is_empty());
        self.anchor = Some(verify_reset(prior_rvk, &keyring).map_err(chain_err)?);
        self.head_etag = Some(etag);
        Ok(bytes)
    }

    // ---- multi-signer draft exchange (blob-only, cross-backend) ----

    /// Open a draft: publish a candidate keyring (built on the current head, signed by >= 1 signer) under
    /// `proposal_id` for co-owners to countersign. Create-once (a proposal id is claimed once).
    ///
    /// # Errors
    /// Returns [`SyncError`] on a store error or if the `proposal_id` is already claimed.
    pub fn propose(&self, proposal_id: &str, candidate_bytes: &[u8]) -> Result<(), SyncError> {
        decode(candidate_bytes)?; // must be a decodable keyring
        match self.store.put(
            &draft_key(proposal_id),
            candidate_bytes,
            Precondition::IfAbsent,
        ) {
            Ok(_) => Ok(()),
            Err(BlobError::PreconditionFailed) => Err(SyncError::Conflict), // that proposal id is taken
            Err(e) => Err(SyncError::Store(e)),
        }
    }

    /// The candidate bytes of a draft, if it exists.
    ///
    /// # Errors
    /// Returns [`SyncError`] on a store error.
    pub fn get_draft(&self, proposal_id: &str) -> Result<Option<Vec<u8>>, SyncError> {
        Ok(self.store.get(&draft_key(proposal_id))?.map(|(b, _)| b))
    }

    /// Add this signer's approval to the draft the caller **reviewed** — `reviewed_bytes` is the exact
    /// candidate the co-owner approved (in the UI). The signature is bound to that content: before signing,
    /// the store's current draft is fetched and its content (signatures excluded, [`keyring_signing_bytes`])
    /// is compared to the reviewed content; a mismatch is refused with [`SyncError::DraftContentChanged`].
    /// This closes a review/sign TOCTOU — a hostile store cannot swap the draft between the co-owner's
    /// review and their signature (nor during the CAS retry loop, which re-checks each iteration) and so
    /// cannot harvest a countersignature over content the signer never saw.
    ///
    /// The store's copy — not `reviewed_bytes` — is what we re-sign, so co-owners' signatures accumulate
    /// (signatures are excluded from the signed content, so appending ours preserves the others'); we only
    /// require that copy's content still equals what was reviewed. Retried if another co-owner's
    /// countersignature landed first.
    ///
    /// # Errors
    /// Returns [`SyncError`] on a store error, if the draft is missing, if its content changed since
    /// review ([`SyncError::DraftContentChanged`]), or on a decode failure.
    pub fn countersign(
        &self,
        proposal_id: &str,
        reviewed_bytes: &[u8],
        key: &SigningKey,
    ) -> Result<(), SyncError> {
        let reviewed_content = keyring_signing_bytes(&decode(reviewed_bytes)?);
        let dkey = draft_key(proposal_id);
        loop {
            let (bytes, etag) = self
                .store
                .get(&dkey)?
                .ok_or(SyncError::Malformed("no such draft"))?;
            let mut candidate = decode(&bytes)?;
            // Sign ONLY the content the co-owner reviewed. If the store served different content (a swap
            // attack, or a genuinely different draft under this id), refuse rather than certify unseen bytes.
            if keyring_signing_bytes(&candidate) != reviewed_content {
                return Err(SyncError::DraftContentChanged);
            }
            sign_keyring(&mut candidate, key);
            match self.store.put(
                &dkey,
                &candidate.encode_to_vec(),
                Precondition::IfMatch(etag),
            ) {
                Ok(_) => return Ok(()),
                Err(BlobError::PreconditionFailed) => {} // concurrent countersign — refetch + re-check
                Err(e) => return Err(SyncError::Store(e)),
            }
        }
    }

    /// Try to promote a draft to the head: verify it satisfies the governance rule AND chains onto the
    /// head we currently trust (`verify_transition`), then CAS-advance the head. Call [`pull`](Self::pull)
    /// first for freshness. Returns [`Promotion`] — promoted, not-ready (needs more signatures), or stale
    /// (the head moved → rebuild + re-propose; a safe re-propose, never corruption).
    ///
    /// # Errors
    /// Returns [`SyncError`] if not bootstrapped, on a store/decode error, or if the draft fails to verify.
    pub fn promote(&mut self, proposal_id: &str) -> Result<Promotion, SyncError> {
        let Some(anchor) = self.anchor.clone() else {
            return Err(SyncError::Malformed("not bootstrapped"));
        };
        let dkey = draft_key(proposal_id);
        let Some((bytes, _)) = self.store.get(&dkey)? else {
            return Err(SyncError::Malformed("no such draft"));
        };
        let draft = decode(&bytes)?;
        match verify_transition(&anchor, &draft) {
            Ok(new_anchor) => {
                let pre = match &self.head_etag {
                    Some(e) => Precondition::IfMatch(e.clone()),
                    None => Precondition::IfAbsent,
                };
                match self.store.put(HEAD, &bytes, pre) {
                    Ok(etag) => {
                        let _ = self.store.put(
                            &rev_key(draft.revision),
                            &bytes,
                            Precondition::IfAbsent,
                        );
                        let _ = self.store.delete(&dkey, Precondition::Any); // best-effort cleanup
                        self.head_etag = Some(etag);
                        self.anchor = Some(new_anchor);
                        Ok(Promotion::Promoted)
                    }
                    Err(BlobError::PreconditionFailed) => Ok(Promotion::Stale), // head advanced under us
                    Err(e) => Err(SyncError::Store(e)),
                }
            }
            // The draft no longer chains onto the head we trust — it moved; rebuild + re-propose.
            Err(KeyringError::Fork | KeyringError::NonSequential) => Ok(Promotion::Stale),
            // A structurally-valid candidate that just lacks the quorum yet.
            Err(KeyringError::UnendorsedSetChange | KeyringError::UnendorsedOrdinaryChange) => {
                Ok(Promotion::NotReady)
            }
            Err(e) => Err(SyncError::Chain(format!("{e:?}"))),
        }
    }
}

fn decode(bytes: &[u8]) -> Result<Keyring, SyncError> {
    Keyring::decode(bytes).map_err(|e| SyncError::Decode(e.to_string()))
}

// A value->value error conversion used as a `.map_err(fn)` argument; taking `&` would force a closure
// at every call site.
#[allow(clippy::needless_pass_by_value)]
fn chain_err(e: KeyringError) -> SyncError {
    SyncError::Chain(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Member, RecoveryKey, MEMBER_OWNER, WRAP_RRK_HPKE, WRAP_X25519_HPKE};
    use keyeo_crypto::{
        codec, EncappedKey, Epoch as KeyeoEpoch, KeyId, Wrap as KeyeoWrap, WrapMethod, WrappedDek,
        X25519PublicKey,
    };
    use std::sync::Arc;
    use store_blob::MemoryBlob;

    const EDITOR: i32 = 4;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }
    fn pk(seed: u8) -> Vec<u8> {
        sk(seed).verifying_key().to_bytes().to_vec()
    }
    fn wrap(id: &str, method: i32) -> KeyeoWrap<String> {
        let encapped = EncappedKey::from_bytes([0u8; 32]);
        let recipient_key = X25519PublicKey::from_bytes([9u8; 32]);
        let m = if method == WRAP_RRK_HPKE {
            WrapMethod::RrkHpke {
                encapped,
                recipient_key,
            }
        } else {
            WrapMethod::MemberHpke {
                encapped,
                recipient_key,
            }
        };
        KeyeoWrap {
            recipient: id.into(),
            method: m,
            ciphertext: WrappedDek::from_bytes([1u8; 48]),
        }
    }
    fn bytes(k: &Keyring) -> Vec<u8> {
        k.encode_to_vec()
    }

    /// A one-founder genesis (rev 1) re-keyed to `founder_seed`, self-signed.
    fn genesis(founder_seed: u8) -> Keyring {
        let mut g = Keyring {
            tree_id: b"tree-uuid-16byte".to_vec(),
            revision: 1,
            layout_version: 1,
            prev_keyring_hash: vec![],
            members: vec![Member {
                member_id: "owner".into(),
                role: MEMBER_OWNER,
                author_public_key: pk(founder_seed),
                hpke_public_key: vec![9; 32],
            }],
            signatures: vec![],
            recovery_keys: vec![],
            epochs: codec::encode_epochs(&[KeyeoEpoch {
                key_id: KeyId::new(vec![0]),
                ordinal: 0,
                dek_commitment: [0u8; 32],
                wraps: vec![wrap("owner", WRAP_RRK_HPKE)],
            }]),
            ..Default::default()
        };
        sign_keyring(&mut g, &sk(founder_seed));
        g
    }

    /// Like [`genesis`], but pinning `rvk_seed` as the recovery authority and co-signed by it.
    fn genesis_with_rvk(founder_seed: u8, rvk_seed: u8) -> Keyring {
        let mut g = genesis(founder_seed);
        g.recovery_keys = vec![RecoveryKey {
            public_key: vec![5; 32],
            member_id: "owner".into(),
            wraps: codec::encode_wraps::<String>(&[]),
            recovery_verifying_key: pk(rvk_seed),
        }];
        g.signatures.clear();
        sign_keyring(&mut g, &sk(founder_seed));
        sign_keyring(&mut g, &sk(rvk_seed));
        g
    }

    /// A rev+1 ordinary successor of `prior` that adds editor `id`, founder-signed.
    fn next(prior: &Keyring, editor_seed: u8, id: &str, founder_seed: u8) -> Keyring {
        let mut k = prior.clone();
        k.revision = prior.revision + 1;
        k.prev_keyring_hash = keyring_hash(prior).to_vec();
        k.members.push(Member {
            member_id: id.into(),
            role: EDITOR,
            author_public_key: pk(editor_seed),
            hpke_public_key: vec![9; 32],
        });
        let mut eps = k.key_material().unwrap();
        eps[0].wraps.push(wrap(id, WRAP_X25519_HPKE));
        k.epochs = codec::encode_epochs(&eps);
        k.signatures.clear();
        sign_keyring(&mut k, &sk(founder_seed));
        k
    }

    /// A self-signed recovery reset re-founding under `founder_seed` at `rev` (no recovery authority).
    fn reset_at(founder_seed: u8, rev: u32) -> Keyring {
        let mut r = genesis(founder_seed);
        r.revision = rev;
        r.signatures.clear();
        sign_keyring(&mut r, &sk(founder_seed));
        r
    }

    #[test]
    fn pull_bootstraps_then_reports_none_then_walks_a_multi_revision_advance() {
        let store = Arc::new(MemoryBlob::new());
        let mut producer = KeyringChainBlobSync::new(Arc::clone(&store));
        let g = genesis(1);
        producer.publish(&bytes(&g)).unwrap();

        let mut consumer = KeyringChainBlobSync::new(Arc::clone(&store));
        // First pull with no anchor bootstraps off the head and returns its bytes.
        assert_eq!(consumer.pull().unwrap(), Some(bytes(&g)));
        assert_eq!(consumer.revision(), Some(1));
        // Pulling again with the head unchanged (same revision, same hash) reports no advance.
        assert_eq!(consumer.pull().unwrap(), None);

        // The producer advances the head two revisions, leaving rev/2 in history.
        let r2 = next(&g, 2, "e2", 1);
        let r3 = next(&r2, 3, "e3", 1);
        producer.publish(&bytes(&r2)).unwrap();
        producer.publish(&bytes(&r3)).unwrap();
        // The consumer walks rev/2 then the head rev/3 and adopts the new bytes.
        assert_eq!(consumer.pull().unwrap(), Some(bytes(&r3)));
        assert_eq!(consumer.revision(), Some(3));

        // A head served BELOW our watermark is a rollback, not an advance.
        store.put(HEAD, &bytes(&g), Precondition::Any).unwrap();
        assert!(matches!(
            consumer.pull(),
            Err(PullError::Rollback { have: 3, served: 1 })
        ));
    }

    #[test]
    fn pull_surfaces_a_recovery_reset_as_reset_pending() {
        let store = Arc::new(MemoryBlob::new());
        let mut producer = KeyringChainBlobSync::new(Arc::clone(&store));
        let g = genesis(1);
        producer.publish(&bytes(&g)).unwrap();
        let mut consumer = KeyringChainBlobSync::new(Arc::clone(&store));
        consumer.pull().unwrap();

        // A rev-2 head that re-founds under a fresh identity (an unendorsed set change on the walk) is a
        // recovery reset — surfaced for the out-of-band ceremony, never silently walked.
        let mut reset = reset_at(9, 2);
        reset.prev_keyring_hash = keyring_hash(&g).to_vec();
        reset.signatures.clear();
        sign_keyring(&mut reset, &sk(9));
        store.put(HEAD, &bytes(&reset), Precondition::Any).unwrap();
        assert!(matches!(consumer.pull(), Err(PullError::ResetPending)));
    }

    #[test]
    fn accept_reset_enforces_the_revision_watermark() {
        let store = Arc::new(MemoryBlob::new());
        let mut producer = KeyringChainBlobSync::new(Arc::clone(&store));
        let g = genesis(1);
        producer.publish(&bytes(&g)).unwrap();
        producer.publish(&bytes(&next(&g, 2, "e2", 1))).unwrap();

        let mut consumer = KeyringChainBlobSync::new(Arc::clone(&store));
        consumer.pull().unwrap(); // bootstrap rev 1
        consumer.pull().unwrap(); // walk to rev 2
        assert_eq!(consumer.revision(), Some(2));

        // Behind the watermark → refused.
        store
            .put(HEAD, &bytes(&reset_at(9, 1)), Precondition::Any)
            .unwrap();
        assert!(
            consumer.accept_reset().is_err(),
            "a reset behind the watermark is refused"
        );
        // At the watermark → accepted (no prior RVK to gate).
        store
            .put(HEAD, &bytes(&reset_at(9, 2)), Precondition::Any)
            .unwrap();
        assert!(
            consumer.accept_reset().is_ok(),
            "a reset at the watermark is accepted"
        );
        // Ahead of the watermark → accepted.
        store
            .put(HEAD, &bytes(&reset_at(8, 3)), Precondition::Any)
            .unwrap();
        assert!(
            consumer.accept_reset().is_ok(),
            "a reset ahead of the watermark is accepted"
        );
    }

    #[test]
    fn accept_reset_enforces_the_prior_recovery_authority() {
        let store = Arc::new(MemoryBlob::new());
        let mut producer = KeyringChainBlobSync::new(Arc::clone(&store));
        // The head pins a recovery authority (rvk seed 42), so the bootstrapped anchor carries it.
        producer.publish(&bytes(&genesis_with_rvk(7, 42))).unwrap();
        let mut consumer = KeyringChainBlobSync::new(Arc::clone(&store));
        consumer.pull().unwrap();

        // A forged reset that re-founds under NO recovery authority must be refused: the prior anchor
        // pinned an RVK this reset neither carries nor is signed by. (If the RVK filter were inverted the
        // gate would go inactive and this forged reset would be accepted.)
        store
            .put(HEAD, &bytes(&reset_at(9, 1)), Precondition::Any)
            .unwrap();
        assert!(
            consumer.accept_reset().is_err(),
            "an RVK-pinned anchor must reject a reset lacking the recovery authority"
        );

        // The legitimate reset — carrying the same RVK and co-signed by it — is accepted.
        store
            .put(HEAD, &bytes(&genesis_with_rvk(9, 42)), Precondition::Any)
            .unwrap();
        assert!(
            consumer.accept_reset().is_ok(),
            "a reset carrying and signed by the pinned RVK is accepted"
        );
    }

    #[test]
    fn drafts_are_keyed_per_proposal_id() {
        let store = Arc::new(MemoryBlob::new());
        let sync = KeyringChainBlobSync::new(Arc::clone(&store));
        let (a, b) = (bytes(&genesis(1)), bytes(&genesis(2)));
        sync.propose("p1", &a).unwrap();
        // A distinct proposal id must claim a distinct key; a constant key would collide here (Conflict).
        sync.propose("p2", &b).unwrap();
        assert_eq!(sync.get_draft("p1").unwrap(), Some(a));
        assert_eq!(sync.get_draft("p2").unwrap(), Some(b));
    }

    #[test]
    fn sync_and_pull_errors_render_human_readable_messages() {
        assert!(format!("{}", SyncError::Malformed("boom")).contains("boom"));
        assert!(format!("{}", SyncError::Conflict).contains("concurrent"));
        assert!(format!("{}", PullError::Rollback { have: 3, served: 1 }).contains('3'));
        assert!(format!("{}", PullError::ResetPending).contains("reset"));
    }
}
