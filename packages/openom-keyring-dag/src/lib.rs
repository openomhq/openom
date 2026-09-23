#![doc = include_str!("../README.md")]

use keyeo_dag::{AccessControl, GroupState, MembershipAction, QuorumPolicy, Requirement, Role};
use std::collections::HashSet;

pub mod anchor_verifier;
pub mod blob_sync;
pub mod checkpoint;
pub mod client;
pub mod recovery;
pub mod verifier;

// The signature scheme is keyeo's unified [`Ed25519`] (verify = edsign's `verify_strict`, rejecting
// small-order / torsion keys and non-canonical signatures) — re-exported so `openom_keyring_dag::Ed25519` names
// the scheme the keyring types are instantiated with. It replaces the old crate-local `OpenomSign`, a
// byte-identical duplicate of the same edsign verify that was deduplicated into keyeo-core (OPE-306).
pub use keyeo_dag::Ed25519;

/// OPE-543: the self-certifying member-id derivation (`uuid8(SHA-256(author_pubkey))`), re-exported from
/// [`openom_keyring_api`] so callers (and the crate's own integration tests) can compute the binding the
/// admission gate enforces without depending on the api crate directly.
pub use openom_keyring_api::derive_member_id;

/// A keyring role, power-descending (**lower is stronger**).
///
/// `ROLE_OWNER = 1` … `ROLE_VIEWER = 5`,
/// bound to openom-keyring-api's engine-neutral role convention ([`openom_keyring_api::ROLE_OWNER`] …) — which openom's
/// `openom-keyring::roles` drift-guard pins to the proto `MemberRole` values, so the engine never has to
/// depend on openom-roles (and stays openom-free).
///
/// Wraps the `i16` so a role can be a signed,
/// content-addressed op field (keyeo requires `Role: Serialize`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct KeyringRole(pub i16);

impl KeyringRole {
    pub const OWNER: Self = Self(openom_keyring_api::ROLE_OWNER);
    pub const CO_OWNER: Self = Self(openom_keyring_api::ROLE_CO_OWNER);
    pub const MAINTAINER: Self = Self(openom_keyring_api::ROLE_MAINTAINER);
    pub const EDITOR: Self = Self(openom_keyring_api::ROLE_EDITOR);
    pub const VIEWER: Self = Self(openom_keyring_api::ROLE_VIEWER);

    /// A signer (keyring administrative authority) is a `CoOwner` or stronger (`Owner`).
    const fn is_signer(self) -> bool {
        self.0 <= openom_keyring_api::ROLE_CO_OWNER
    }

    /// The Owner (founder) — the unique keyring root.
    const fn is_owner(self) -> bool {
        self.0 == openom_keyring_api::ROLE_OWNER
    }
}

impl Role for KeyringRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        // Power-descending: a stronger (lower-valued) role grants everything a weaker one does.
        self.0 <= other.0
    }
}

/// The concrete keyeo instantiation for the openom keyring.
///
/// Op ids are 32-byte content hashes, member ids are openom member-id strings, roles are
/// [`KeyringRole`], signatures are keyeo's unified [`Ed25519`].
pub type KeyringAction = MembershipAction<String, KeyringRole, Ed25519>;
pub type KeyringOp = keyeo_dag::Op<[u8; 32], String, KeyringRole, Ed25519>;
pub type KeyringState = GroupState<String, KeyringRole, Ed25519>;
pub type KeyringMemberInit = keyeo_dag::MemberInit<String, KeyringRole, Ed25519>;

/// OPE-543 self-cert admission gate: a `member_id` MUST be the `uuid8` of its own author key
/// (`openom_keyring_api::derive_member_id`). Enforced inside [`AccessControl::is_authorized`], which runs at
/// every op's causal position on every replica — so a forged `(member_id, author_key)` binding is unauthorized
/// (hence ineffective) everywhere, not just rejected by the minting client. Checks the ACTION's carried key
/// (the binding being installed), not the admitting op's signer key.
pub(crate) fn member_id_binds_key(member_id: &str, author_public_key: &[u8]) -> bool {
    member_id == openom_keyring_api::derive_member_id(author_public_key)
}
pub type KeyringEngine = keyeo_dag::Keyeo<KeyringOp, KeyringAccess, keyeo_dag::StrongRemove>;
/// The v2 keyring engine — same authority + strong-remove, plus a [`KeyringQuorum`] multi-signer policy
/// for privileged changes.
///
/// Construct with `Keyeo::with_quorum(state, KeyringAccess, StrongRemove,
/// KeyringQuorum::founder_or_unanimity())` (or any other [`QuorumRule`]).
pub type KeyringQuorumEngine =
    keyeo_dag::Keyeo<KeyringOp, KeyringAccess, keyeo_dag::StrongRemove, KeyringQuorum>;

/// Sign a membership op with an edsign key. keyeo's `Op::sign` is dalek-specific; this signs over
/// keyeo's canonical encoding with the edsign seam instead, so the adapter never touches dalek.
pub fn sign_op(
    id: [u8; 32],
    parents: Vec<[u8; 32]>,
    author: impl Into<String>,
    action: KeyringAction,
    key: &edsign::SigningKey,
) -> KeyringOp {
    let author = author.into();
    // No sealing on these ops — sign_op is the id-supplied constructor used across tests + the keyless
    // paths; the sealing-carrying, content-addressed minting lives in the DagKeyring client facade (OPE-273).
    // Group id is UNSCOPED here: sign_op is single-group (tests / keyless fixtures); the production minting
    // path (`client::mint`) binds the real group id (openom: the tree id).
    let group_id = keyeo_dag::GroupId::unscoped();
    let canonical = keyeo_dag::canonical_encode(&group_id, &parents, &author, &action, &[]);
    let signature = key.sign(&canonical).to_bytes();
    let author_public_key = key.verifying_key().to_bytes();
    keyeo_dag::Op::new(
        id,
        group_id,
        parents,
        author,
        action,
        signature,
        author_public_key,
    )
}

/// openom keyring authority — v1, founder-signed governance (multi-signer quorum is v2).
///
/// Keyring-write authority is **signer-gated**, not role-threshold-based: only a **signer** (Owner or
/// `CoOwner`) may author a keyring change. A `MemberRole` below `CoOwner` (Maintainer / Editor / Viewer)
/// carries content/moderation authority elsewhere in openom, but grants **no keyring-write authority**
/// here. Within that gate:
/// - touching a **signer** (adding/removing/retargeting an Owner or `CoOwner`) requires the **Owner**;
/// - touching an **ordinary member** requires any **signer** (`CoOwner` or Owner);
/// - the **Owner is unique and immutable** in v1 — no second Owner may be created, and the Owner may not
///   be removed or demoted (not even by themselves): "the founder can't leave" (transfer is a v2 op);
/// - any **non-Owner** member may **remove themselves** (a deliberate BYO-offline widening).
///
/// This mirrors openom's two-axis model as a single-axis re-model under a declared lockstep invariant
/// (Owner↔Founder-signer, CoOwner-member↔CoOwner-signer). Authorization is evaluated by the resolver at
/// each op's causal position — see keyeo's authority-aware `StrongRemove` (OPE-258).
pub struct KeyringAccess;

impl KeyringAccess {
    /// The weakest role permitted to author a change **touching** a member whose role is `target`:
    /// touching a signer needs the Owner; touching an ordinary member needs any signer (`CoOwner`+).
    const fn required_for(target: KeyringRole) -> KeyringRole {
        if target.is_signer() {
            KeyringRole::OWNER
        } else {
            KeyringRole::CO_OWNER
        }
    }

    /// The role a member currently holds at this causal position (Viewer if absent — a target that
    /// isn't a member is "ordinary", never a signer).
    fn role_of(state: &KeyringState, member: &str) -> KeyringRole {
        state
            .members
            .get(member)
            .map_or(KeyringRole::VIEWER, |m| m.role)
    }
}

impl AccessControl<String, KeyringRole, Ed25519> for KeyringAccess {
    // The `ReFound` / `RotateRecoveryAuthority` / `Retarget` arms deliberately share the `false` body with
    // the (handled-above) `Create` arm, but are kept SEPARATE from each other and from `Create` because each
    // carries its own security rationale (OPE-543: why on-tree re-founding/rotation/rekey is unauthorized).
    // Collapsing them would erase that per-op documentation, so the identical-body lint is allowed here.
    #[allow(clippy::match_same_arms)]
    fn is_authorized(&self, state: &KeyringState, author: &String, action: &KeyringAction) -> bool {
        // Genesis Create: authorized ONLY at an unestablished causal position (no members yet), with the
        // author a listed initial member and EXACTLY ONE Owner (the founder). The empty-state gate is the
        // OPE-271 hardening: keyeo's `apply_action` applies a `Create` by *replacing* the whole
        // `GroupState`, and a `Create` is self-certifying (the engine authenticates it against its OWN
        // `initial_members`, not the resolved state), so absent this gate a second, attacker-signed
        // `Create{owner: self}` folded at any populated position would WIPE the resolved roster and
        // re-found the group under the attacker. Gating on `is_empty()` means a `Create` can only ever
        // seed an unestablished group and can never re-found an established one. In openom's
        // out-of-band-seeded construction the genesis membership is the engine's trusted base, so every
        // in-DAG `Create` is a no-op and no `Create` can reset the roster.
        if let MembershipAction::Create { initial_members } = action {
            let owners = initial_members.iter().filter(|m| m.role.is_owner()).count();
            return state.members.is_empty()
                && owners == 1
                && initial_members.iter().any(|m| &m.id == author)
                // OPE-543: every seeded member's id must be self-certifying against its carried key.
                && initial_members
                    .iter()
                    .all(|m| member_id_binds_key(&m.id, m.author_public_key.as_ref()));
        }
        // Every other change requires an active member author.
        let author_role = match state.members.get(author) {
            Some(m) if m.is_active() => m.role,
            _ => return false,
        };
        match action {
            MembershipAction::Create { .. } => false, // handled above
            MembershipAction::Add {
                member,
                role,
                author_public_key,
                ..
            } => {
                // No second Owner, ever; the author must out-rank what the target role needs; AND (OPE-543)
                // the member id must be self-certifying against the carried key. Covers reactivation too (a
                // re-add of a removed member flows through this same arm).
                !role.is_owner()
                    && author_role.grants_at_least(&Self::required_for(*role))
                    && member_id_binds_key(member, author_public_key.as_ref())
            }
            MembershipAction::ChangeRole { member, new_role } => {
                let current = Self::role_of(state, member);
                // The Owner can't be demoted, and no one may be promoted INTO Owner (uniqueness). The
                // author must out-rank both the current standing and the target role.
                !current.is_owner()
                    && !new_role.is_owner()
                    && author_role.grants_at_least(&Self::required_for(current))
                    && author_role.grants_at_least(&Self::required_for(*new_role))
            }
            MembershipAction::Remove { member } => {
                let current = Self::role_of(state, member);
                // The Owner can never be removed — not even by themselves (the founder can't leave).
                if current.is_owner() {
                    return false;
                }
                // Widen: any non-Owner member may remove THEMSELVES.
                if author == member {
                    return true;
                }
                author_role.grants_at_least(&Self::required_for(current))
            }
            // Quorum-protocol ops (v2): the author must be a signer to participate; the wrapped target's
            // authority is decided by the quorum resolver (founder-or-unanimity), not here.
            MembershipAction::Propose { .. }
            | MembershipAction::Approve { .. }
            | MembershipAction::Commit { .. } => author_role.is_signer(),
            // OPE-543: durable identity has NO on-tree re-founding — recovery restores the SAME account
            // identity via a keystore re-wrap, so there is nothing to re-found on-tree. `ReFound` is
            // UNAUTHORIZED here (not merely uncalled): if it stayed authorizable, a Rotate→re-pin→ReFound
            // ladder could re-arm `reset_authority` (which `apply_action` sets unconditionally) and retarget
            // the owner's key. Killing it in the domain gate makes the whole recovery-rotation subsystem
            // provably dormant on an openom tree (the generic machinery stays in keyeo-dag for other uses).
            MembershipAction::ReFound { .. } => false,
            // OPE-543: killed alongside ReFound (see above) — it is the op that would re-arm `reset_authority`.
            MembershipAction::RotateRecoveryAuthority { .. } => false,
            // OPE-543: voluntary self-rekey removed — under durable identity a member's key never changes
            // on-tree (a compromised key is an account-level succession, not a per-tree retarget).
            MembershipAction::Retarget { .. } => false,
            // A forward-secrecy reseal (OPE-282): any active member may author one — minting a fresh DEK
            // needs only public keys, so a member locked out of the current write epoch can still repair it.
            // The engine's D3 check binds it to the author's current key; the sealer's coverage check binds
            // WHAT it may contain, so no role gate is needed here.
            MembershipAction::Reseal => true,
        }
    }

    fn is_privileged(&self, state: &KeyringState, action: &KeyringAction) -> bool {
        // The authority-structure-changing ops — everything the reset-merge carve-out voids when it is
        // concurrent with a surviving recovery. Ordinary member changes (adding/removing/re-roling a
        // non-signer) are NOT privileged, so they auto-merge across a recovery (compass: never lose an
        // innocent edit). Signer-set changes, governance (quorum), and recovery are.
        match action {
            // Adding a signer is privileged; adding an ordinary member is not.
            MembershipAction::Add { role, .. } => role.is_signer(),
            // Touching a signer in either direction (promoting into, or demoting/removing out of).
            MembershipAction::ChangeRole { member, new_role } => {
                new_role.is_signer() || Self::role_of(state, member).is_signer()
            }
            // Removing OR retargeting the key of a signer touches the authority structure (privileged);
            // doing either to an ordinary member (incl. an ordinary member's self-rekey) does not.
            MembershipAction::Remove { member } | MembershipAction::Retarget { member, .. } => {
                Self::role_of(state, member).is_signer()
            }
            // Governance and recovery are always authority-structure changes.
            MembershipAction::Propose { .. }
            | MembershipAction::Approve { .. }
            | MembershipAction::Commit { .. }
            | MembershipAction::ReFound { .. }
            | MembershipAction::RotateRecoveryAuthority { .. } => true,
            // A reseal (a routine forward-secrecy repair) and a Create change no signer/governance/recovery
            // structure, so they auto-merge (never carve-out-voided by a concurrent recovery).
            MembershipAction::Reseal | MembershipAction::Create { .. } => false,
        }
    }
}

/// The member a change *acts on* — the one whose consent shouldn't gate their own removal/demotion.
/// Excluded from both the eligible set and the unanimity denominator (you don't need a member's
/// approval to remove or demote them).
const fn target_member(action: &KeyringAction) -> Option<&String> {
    match action {
        MembershipAction::Remove { member } | MembershipAction::ChangeRole { member, .. } => {
            Some(member)
        }
        _ => None,
    }
}

/// The active Owner (founder), if any. The Owner is unique and immutable in openom, so this is `Some`
/// for any well-formed keyring; the `None` arm is defensive (fail-closed).
fn active_owner(state: &KeyringState) -> Option<String> {
    state
        .members
        .iter()
        .find(|(_, m)| m.is_active() && m.role.is_owner())
        .map(|(id, _)| id.clone())
}

/// The per-keyring governance rule — so one family tree can be founder-only, another 3-of-4, another
/// founder-or-unanimity, all from the same [`KeyringQuorum`] policy.
///
/// The founder (Owner) is always
/// eligible to propose/approve; the co-owners are the collective body. Every rule is still bounded by
/// founder-equivalent authority (see [`KeyringQuorum::requirement`]).
///
/// Note (not yet wired): the chosen rule must be **authenticated and pinned** per keyring — set at
/// genesis and replicated — so every replica evaluates the same denominator and an attacker can't
/// weaken it (e.g. 3-of-4 → 1-of-4). Today it's a construction-time parameter the client is responsible
/// for keeping consistent across a family's replicas; pinning it into the signed root is a follow-up
/// (OPE-260 hardening / the unified-substrate governance-config question).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumRule {
    /// The founder alone — co-owners have no governance vote (a single-admin family).
    FounderOnly,
    /// The founder alone, OR unanimity of the co-owners.
    FounderOrUnanimity,
    /// The founder alone, OR at least `m` of the co-owners.
    FounderOrThreshold(usize),
    /// At least `m` of the signers (Owner + co-owners), with no special founder path — a flat M-of-N.
    Threshold(usize),
}

/// openom's v2 multi-signer quorum, parameterised by a per-keyring [`QuorumRule`].
///
/// A privileged change
/// takes effect when the rule's requirement is met by the distinct eligible approvers — e.g. the founder
/// alone, or unanimity of co-owners, or M of N.
///
/// The quorum grants **founder-equivalent** authority and no more: [`Self::requirement`] asks
/// [`KeyringAccess`] whether the *founder* could authorize this target directly, and returns a
/// fail-closed (empty-`All`) requirement if not. This binds owner-immutability (no removing/demoting the
/// Owner, no second Owner) to the quorum path too — closing the hole that a Commit applies its target
/// via `apply_action` without re-checking target-level access. The member being removed/demoted is
/// excluded from the denominator (their consent isn't needed to evict them).
#[derive(Clone, Copy, Debug)]
pub struct KeyringQuorum {
    rule: QuorumRule,
}

impl KeyringQuorum {
    #[must_use]
    pub const fn new(rule: QuorumRule) -> Self {
        Self { rule }
    }
    /// The founder alone governs (single-admin family).
    #[must_use]
    pub const fn founder_only() -> Self {
        Self::new(QuorumRule::FounderOnly)
    }
    /// The founder alone, OR every co-owner (the collective-when-offline default).
    #[must_use]
    pub const fn founder_or_unanimity() -> Self {
        Self::new(QuorumRule::FounderOrUnanimity)
    }
    /// The founder alone, OR at least `m` co-owners.
    #[must_use]
    pub const fn founder_or_threshold(m: usize) -> Self {
        Self::new(QuorumRule::FounderOrThreshold(m))
    }
    /// A flat `m`-of-N over the signers (Owner + co-owners), no special founder path.
    #[must_use]
    pub const fn threshold(m: usize) -> Self {
        Self::new(QuorumRule::Threshold(m))
    }
}

impl KeyringQuorum {
    /// Active members matching `pred` (a role test), minus the change's own target member.
    fn signer_set(
        state: &KeyringState,
        excluded: Option<&String>,
        pred: impl Fn(KeyringRole) -> bool,
    ) -> HashSet<String> {
        state
            .members
            .iter()
            .filter(|(id, m)| m.is_active() && pred(m.role) && Some(*id) != excluded)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

impl QuorumPolicy<String, KeyringRole, Ed25519> for KeyringQuorum {
    fn eligible(&self, state: &KeyringState, target: &KeyringAction) -> HashSet<String> {
        // Any signer may propose/approve under every rule; the rule only decides how many are required.
        Self::signer_set(state, target_member(target), KeyringRole::is_signer)
    }

    fn requirement(&self, state: &KeyringState, target: &KeyringAction) -> Requirement<String> {
        let Some(founder) = active_owner(state) else {
            return Requirement::All(HashSet::new()); // fail-closed: no founder, no founder-equivalence
        };
        // Founder-equivalent, not founder-exceeding: a quorum can authorize exactly what the founder
        // could do alone. What even the Owner can't do directly (self-removal, a second Owner, …), no
        // quorum can do either — so owner-immutability holds on the quorum path.
        if !KeyringAccess.is_authorized(state, &founder, target) {
            return Requirement::All(HashSet::new());
        }
        let excluded = target_member(target);
        let co_owners = || Self::signer_set(state, excluded, |r| r == KeyringRole::CO_OWNER);
        let sole = || Box::new(Requirement::Sole(founder.clone()));
        match self.rule {
            QuorumRule::FounderOnly => Requirement::Sole(founder),
            QuorumRule::FounderOrUnanimity => {
                Requirement::Either(sole(), Box::new(Requirement::All(co_owners())))
            }
            QuorumRule::FounderOrThreshold(m) => {
                Requirement::Either(sole(), Box::new(Requirement::Threshold(m, co_owners())))
            }
            QuorumRule::Threshold(m) => {
                Requirement::Threshold(m, Self::signer_set(state, excluded, KeyringRole::is_signer))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyeo_dag::{ApplyOutcome, Keyeo, StrongRemove};

    fn sk(seed: u8) -> edsign::SigningKey {
        edsign::SigningKey::from_seed(&[seed; 32])
    }
    fn vk(seed: u8) -> [u8; 32] {
        sk(seed).verifying_key().to_bytes()
    }
    /// OPE-543: a member id is now the self-certifying `uuid8` of its own author key, so every fixture id is
    /// derived from the member's seed (not a free label) — the admission gate (`Add`/`Create`) refuses any
    /// binding where `member_id != derive_member_id(author_key)`.
    fn mid(seed: u8) -> String {
        openom_keyring_api::derive_member_id(&vk(seed))
    }
    fn minit(role: KeyringRole, seed: u8) -> KeyringMemberInit {
        KeyringMemberInit {
            id: mid(seed),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
        }
    }
    fn engine(members: &[KeyringMemberInit]) -> KeyringEngine {
        Keyeo::new(
            KeyringState::create(keyeo_dag::GroupId::unscoped(), members),
            KeyringAccess,
            StrongRemove,
        )
    }
    fn add(role: KeyringRole, seed: u8) -> KeyringAction {
        MembershipAction::Add {
            member: mid(seed),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
            member_proof: None,
        }
    }
    fn members(k: &KeyringEngine) -> Vec<(String, KeyringRole)> {
        let mut m = k.state().active_members();
        m.sort();
        m
    }
    /// Build a sorted expected roster from `(seed, role)` pairs — since ids are now derived uuid8 strings,
    /// their sort order is by hash, not by label, so exact-roster assertions sort the expected set too.
    fn roster(pairs: &[(u8, KeyringRole)]) -> Vec<(String, KeyringRole)> {
        let mut v: Vec<(String, KeyringRole)> = pairs.iter().map(|(s, r)| (mid(*s), *r)).collect();
        v.sort();
        v
    }

    #[test]
    fn founder_signed_governance_resolves_through_keyeo() {
        // founder (Owner) creates the group and adds bob as a CoOwner (a signer); bob (a signer) then
        // adds an ordinary Editor. The openom seams (Ed25519, KeyringRole, KeyringAccess) resolve end
        // to end.
        let mut k = engine(&[minit(KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![minit(KeyringRole::OWNER, 1)],
            },
            &sk(1),
        ))
        .unwrap();
        // founder adds bob into the signer set (touching a signer → needs Owner ✓)
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(1),
            add(KeyringRole::CO_OWNER, 2),
            &sk(1),
        ))
        .unwrap();
        // bob (a signer) adds carol as an ordinary Editor (touching an ordinary member → needs a signer ✓)
        k.apply(sign_op(
            [3; 32],
            vec![[2; 32]],
            mid(2),
            add(KeyringRole::EDITOR, 3),
            &sk(2),
        ))
        .unwrap();

        assert_eq!(
            members(&k),
            roster(&[
                (2, KeyringRole::CO_OWNER),
                (3, KeyringRole::EDITOR),
                (1, KeyringRole::OWNER),
            ])
        );
    }

    #[test]
    fn a_maintainer_cannot_write_the_keyring() {
        // A Maintainer is NOT a signer, so it has NO keyring-write authority — not even to add an
        // ordinary member. Admit-then-resolve: the op is admitted (valid signature) but has no effect.
        let mut k = engine(&[
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::MAINTAINER, 4),
        ]);
        let r = k
            .apply(sign_op(
                [1; 32],
                vec![],
                mid(4),
                add(KeyringRole::EDITOR, 9),
                &sk(4),
            ))
            .unwrap();
        assert!(matches!(r, ApplyOutcome::Applied { events } if events.is_empty()));
        assert!(
            !members(&k).iter().any(|(m, _)| m == &mid(9)),
            "a Maintainer is not a signer and cannot add a member"
        );
    }

    #[test]
    fn only_the_owner_may_touch_the_signer_set() {
        // A CoOwner is a signer, but still cannot promote someone INTO the signer set nor remove another
        // signer — that requires the Owner (founder-signed governance; unanimity/quorum is v2).
        let mut k = engine(&[
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::EDITOR, 3),
        ]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(2),
            MembershipAction::ChangeRole {
                member: mid(3),
                new_role: KeyringRole::CO_OWNER,
            },
            &sk(2),
        ))
        .unwrap();
        assert!(
            members(&k).contains(&(mid(3), KeyringRole::EDITOR)),
            "a CoOwner can't create another signer"
        );
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(2),
            MembershipAction::Remove { member: mid(1) },
            &sk(2),
        ))
        .unwrap();
        assert!(
            members(&k).iter().any(|(m, _)| m == &mid(1)),
            "a CoOwner can't remove the Owner"
        );
    }

    #[test]
    fn the_owner_is_unique_and_immutable() {
        // No second Owner may be created, and the Owner may not be removed or demoted — not even by
        // themselves ("the founder can't leave"). Each op is admitted but has no effect.
        let mut k = engine(&[minit(KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![minit(KeyringRole::OWNER, 1)],
            },
            &sk(1),
        ))
        .unwrap();
        // a second Owner is forbidden
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(1),
            add(KeyringRole::OWNER, 5),
            &sk(1),
        ))
        .unwrap();
        assert!(
            !members(&k).iter().any(|(m, _)| m == &mid(5)),
            "no second Owner"
        );
        // the Owner cannot self-remove
        k.apply(sign_op(
            [3; 32],
            vec![[1; 32]],
            mid(1),
            MembershipAction::Remove { member: mid(1) },
            &sk(1),
        ))
        .unwrap();
        // ...nor self-demote
        k.apply(sign_op(
            [4; 32],
            vec![[3; 32]],
            mid(1),
            MembershipAction::ChangeRole {
                member: mid(1),
                new_role: KeyringRole::CO_OWNER,
            },
            &sk(1),
        ))
        .unwrap();
        assert_eq!(
            members(&k),
            roster(&[(1, KeyringRole::OWNER)]),
            "the Owner remains, alone and unchanged"
        );
    }

    #[test]
    fn a_second_create_cannot_re_found_and_wipe_the_roster() {
        // OPE-271: keyeo's `apply_action` applies a Create by REPLACING GroupState, and a Create is
        // self-certifying (the engine authenticates it against its own initial_members), so both attack
        // shapes below are admitted with a valid signature. Without the empty-state gate on Create, either
        // would wipe the resolved roster and install mallory as sole Owner. The gate makes any Create at a
        // populated causal position a no-op, so the real roster survives untouched.
        let mut k = engine(&[minit(KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![minit(KeyringRole::OWNER, 1)],
            },
            &sk(1),
        ))
        .unwrap();
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(1),
            add(KeyringRole::CO_OWNER, 2),
            &sk(1),
        ))
        .unwrap();

        // Attack A — a second genesis childed on the real chain (sorts AFTER it in topo order: the classic
        // "later Create replaces the accumulated state" wipe).
        let re_found = |id: u8, parents: Vec<[u8; 32]>| {
            sign_op(
                [id; 32],
                parents,
                mid(9),
                MembershipAction::Create {
                    initial_members: vec![minit(KeyringRole::OWNER, 9)],
                },
                &sk(9),
            )
        };
        k.apply(re_found(9, vec![[2; 32]])).unwrap(); // admitted (self-certifying), folded as a no-op
                                                      // Attack B — a CONCURRENT second genesis (no parents) whose OpId [0;32] sorts BEFORE the real
                                                      // genesis [1;32], so it is folded FIRST — defeating any naive "first Create wins" rule.
        k.apply(re_found(0, vec![])).unwrap();

        assert_eq!(
            members(&k),
            roster(&[(2, KeyringRole::CO_OWNER), (1, KeyringRole::OWNER),]),
            "neither a later nor an OpId-grinding concurrent Create may re-found the group"
        );
        assert!(
            !k.state().members.contains_key(&mid(9)),
            "the attacker's self-signed re-genesis has no effect"
        );
    }

    #[test]
    fn an_op_carrying_a_key_that_is_not_the_authors_registered_key_is_ignored() {
        // D3 (retarget-tolerant authentication): admission verifies an op against its OWN carried key, so
        // an impostor CAN get a forged op admitted by claiming a member's id and signing with their own
        // key. Authority is then decided at the op's causal position, where the carried key must equal the
        // author's REGISTERED key — so the forgery has no effect. (This is also what will let a late op
        // signed under a since-retargeted key resolve identically on every replica once recovery lands.)
        let mut k = engine(&[
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
        ]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![
                    minit(KeyringRole::OWNER, 1),
                    minit(KeyringRole::CO_OWNER, 2),
                ],
            },
            &sk(1),
        ))
        .unwrap();

        // Mallory forges an op AS "bob" (a co-owner who could add an editor) but signs it with HER key
        // (seed 9), so the op carries vk(9), not bob's registered vk(2).
        let forged = sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(2),
            add(KeyringRole::EDITOR, 9),
            &sk(9),
        );
        let outcome = k.apply(forged).unwrap(); // admitted — the signature matches its own carried key ...
        assert!(
            matches!(outcome, ApplyOutcome::Applied { events } if events.is_empty()),
            "the forged op is admitted but resolves to no membership change"
        );
        assert!(
            !members(&k).iter().any(|(m, _)| m == &mid(9)),
            "an op signed under a key that isn't the author's registered key carries no authority"
        );

        // Control: the REAL bob, signing with his registered key (seed 2), adds an editor as expected.
        k.apply(sign_op(
            [3; 32],
            vec![[1; 32]],
            mid(2),
            add(KeyringRole::EDITOR, 3),
            &sk(2),
        ))
        .unwrap();
        assert!(
            members(&k).iter().any(|(m, _)| m == &mid(3)),
            "the same action by the author's registered key is authorized — the key identity is the gate"
        );
    }

    // ---- bounded fork-merge horizon (OPE-270) ----

    #[test]
    fn a_fork_branching_from_before_the_merge_horizon_is_rejected() {
        // GHOST-derived anti-rollback hygiene: once a stable frontier is pinned as the merge horizon, an
        // op that branches from BEFORE it is rejected as a stale fork, not merged — closing the
        // rollback/equivocation vector of re-introducing history past the compaction cut. An op that
        // builds ON the horizon is accepted.
        let mut k = engine(&[minit(KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![minit(KeyringRole::OWNER, 1)],
            },
            &sk(1),
        ))
        .unwrap();
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(1),
            add(KeyringRole::CO_OWNER, 2),
            &sk(1),
        ))
        .unwrap();

        // Pin the horizon at the current tip [2].
        k.set_merge_horizon(vec![[2; 32]]);

        // A fork off [1] (before the horizon) is rejected outright.
        let stale = k.apply(sign_op(
            [4; 32],
            vec![[1; 32]],
            mid(1),
            add(KeyringRole::EDITOR, 9),
            &sk(1),
        ));
        assert!(
            matches!(stale, Err(keyeo_dag::Error::StaleFork)),
            "a fork from before the horizon is rejected, not merged"
        );
        assert!(
            !k.state().members.contains_key(&mid(9)),
            "and never enters the resolved state"
        );

        // An op building ON the horizon [2] is accepted normally.
        k.apply(sign_op(
            [3; 32],
            vec![[2; 32]],
            mid(1),
            add(KeyringRole::EDITOR, 3),
            &sk(1),
        ))
        .unwrap();
        assert!(
            k.state().members.contains_key(&mid(3)),
            "an op that builds on the horizon is accepted"
        );
    }

    #[test]
    fn any_non_owner_may_remove_themselves() {
        // The widen decision: any non-Owner may self-remove (a BYO/offline convenience), even an Editor.
        let mut k = engine(&[minit(KeyringRole::OWNER, 1), minit(KeyringRole::EDITOR, 6)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(6),
            MembershipAction::Remove { member: mid(6) },
            &sk(6),
        ))
        .unwrap();
        assert!(
            !members(&k).iter().any(|(m, _)| m == &mid(6)),
            "an Editor may remove themselves"
        );
    }

    #[test]
    fn a_co_owner_manages_ordinary_members() {
        // A signer (CoOwner) may add and remove ordinary members.
        let mut k = engine(&[
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::EDITOR, 3),
        ]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(2),
            add(KeyringRole::EDITOR, 4),
            &sk(2),
        ))
        .unwrap();
        assert!(
            members(&k).iter().any(|(m, _)| m == &mid(4)),
            "a CoOwner may add an ordinary member"
        );
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(2),
            MembershipAction::Remove { member: mid(3) },
            &sk(2),
        ))
        .unwrap();
        assert!(
            !members(&k).iter().any(|(m, _)| m == &mid(3)),
            "a CoOwner may remove an ordinary member"
        );
    }

    #[test]
    fn the_edsign_seam_rejects_a_forged_signature() {
        // A structurally-valid op whose signature is over the wrong bytes must be rejected by the
        // engine's authenticate step, i.e. by Ed25519::verify (edsign verify_strict).
        let mut k = engine(&[minit(KeyringRole::OWNER, 1)]);
        let action = MembershipAction::Remove { member: mid(1) };
        let bad_sig = sk(1).sign(b"not the canonical op bytes").to_bytes();
        let op = keyeo_dag::Op::new(
            [1; 32],
            keyeo_dag::GroupId::unscoped(),
            vec![],
            mid(1),
            action,
            bad_sig,
            vk(1),
        );
        assert!(matches!(
            k.apply(op).unwrap_err(),
            keyeo_dag::Error::BadSignature
        ));
    }

    // ---- v2 multi-signer quorum (FounderOrUnanimity) ----

    fn quorum_engine_with(
        members: &[KeyringMemberInit],
        quorum: KeyringQuorum,
    ) -> KeyringQuorumEngine {
        Keyeo::with_quorum(
            KeyringState::create(keyeo_dag::GroupId::unscoped(), members),
            KeyringAccess,
            StrongRemove,
            quorum,
        )
    }
    fn quorum_engine(members: &[KeyringMemberInit]) -> KeyringQuorumEngine {
        quorum_engine_with(members, KeyringQuorum::founder_or_unanimity())
    }
    fn genesis(members: &[KeyringMemberInit]) -> KeyringOp {
        sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: members.to_vec(),
            },
            &sk(1),
        )
    }
    fn propose(
        id: u8,
        parents: Vec<[u8; 32]>,
        author: impl Into<String>,
        seed: u8,
        target: KeyringAction,
    ) -> KeyringOp {
        sign_op(
            [id; 32],
            parents,
            author,
            MembershipAction::Propose {
                proposal_id: [7; 32],
                target: Box::new(target),
            },
            &sk(seed),
        )
    }
    fn approve(id: u8, parents: Vec<[u8; 32]>, author: impl Into<String>, seed: u8) -> KeyringOp {
        sign_op(
            [id; 32],
            parents,
            author,
            MembershipAction::Approve {
                proposal_id: [7; 32],
            },
            &sk(seed),
        )
    }
    fn commit(id: u8, parents: Vec<[u8; 32]>, author: impl Into<String>, seed: u8) -> KeyringOp {
        sign_op(
            [id; 32],
            parents,
            author,
            MembershipAction::Commit {
                proposal_id: [7; 32],
            },
            &sk(seed),
        )
    }
    fn promote(seed: u8, new_role: KeyringRole) -> KeyringAction {
        MembershipAction::ChangeRole {
            member: mid(seed),
            new_role,
        }
    }
    fn q_role_of(k: &KeyringQuorumEngine, member: &str) -> Option<KeyringRole> {
        k.state()
            .members
            .get(member)
            .filter(|m| m.is_active())
            .map(|m| m.role)
    }

    #[test]
    fn unanimous_co_owners_promote_a_signer_without_the_founder() {
        // Promoting an Editor into the signer set normally needs the Owner. Via quorum, unanimity of the
        // co-owners (bob + carol) authorizes it with no founder approval — the co-owners-collective path.
        let m = [
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::CO_OWNER, 3),
            minit(KeyringRole::EDITOR, 6),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(
            2,
            vec![[1; 32]],
            mid(2),
            2,
            promote(6, KeyringRole::CO_OWNER),
        ))
        .unwrap();
        k.apply(approve(3, vec![[2; 32]], mid(3), 3)).unwrap();
        k.apply(commit(4, vec![[3; 32]], mid(2), 2)).unwrap();
        assert_eq!(
            q_role_of(&k, &mid(6)),
            Some(KeyringRole::CO_OWNER),
            "unanimity of co-owners promotes"
        );
    }

    #[test]
    fn one_co_owner_short_of_unanimity_does_not_promote() {
        // Same target, but carol never approves — unanimity is unmet and the founder isn't in the tally,
        // so ed stays an Editor (fail-closed).
        let m = [
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::CO_OWNER, 3),
            minit(KeyringRole::EDITOR, 6),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(
            2,
            vec![[1; 32]],
            mid(2),
            2,
            promote(6, KeyringRole::CO_OWNER),
        ))
        .unwrap();
        k.apply(commit(3, vec![[2; 32]], mid(2), 2)).unwrap();
        assert_eq!(
            q_role_of(&k, &mid(6)),
            Some(KeyringRole::EDITOR),
            "bob alone is not unanimity"
        );
    }

    #[test]
    fn the_founder_alone_promotes_via_the_sole_path() {
        // The founder needs no co-owner approvals: Sole(founder) is satisfied by the proposer alone.
        let m = [
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::EDITOR, 6),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(
            2,
            vec![[1; 32]],
            mid(1),
            1,
            promote(6, KeyringRole::CO_OWNER),
        ))
        .unwrap();
        k.apply(commit(3, vec![[2; 32]], mid(1), 1)).unwrap();
        assert_eq!(
            q_role_of(&k, &mid(6)),
            Some(KeyringRole::CO_OWNER),
            "founder alone suffices"
        );
    }

    #[test]
    fn quorum_cannot_remove_the_immutable_owner() {
        // Owner-immutability binds the quorum path: even unanimity of every co-owner can't evict the
        // founder, because the founder couldn't do it directly (self-removal is forbidden) and the quorum
        // is founder-EQUIVALENT, never founder-exceeding. The requirement is fail-closed.
        let m = [
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::CO_OWNER, 3),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(
            2,
            vec![[1; 32]],
            mid(2),
            2,
            MembershipAction::Remove { member: mid(1) },
        ))
        .unwrap();
        k.apply(approve(3, vec![[2; 32]], mid(3), 3)).unwrap();
        k.apply(commit(4, vec![[3; 32]], mid(2), 2)).unwrap();
        assert_eq!(
            q_role_of(&k, &mid(1)),
            Some(KeyringRole::OWNER),
            "no quorum can remove the Owner"
        );
    }

    // ---- dynamic quorum: per-keyring QuorumRule ----

    #[test]
    fn founder_only_rule_ignores_co_owner_unanimity() {
        // A single-admin family: even unanimity of every co-owner can't act; only the founder (Sole) can.
        let m = [
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::CO_OWNER, 3),
            minit(KeyringRole::EDITOR, 6),
        ];
        // co-owners bob + carol try to promote ed -> refused under FounderOnly.
        let mut k = quorum_engine_with(&m, KeyringQuorum::founder_only());
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(
            2,
            vec![[1; 32]],
            mid(2),
            2,
            promote(6, KeyringRole::CO_OWNER),
        ))
        .unwrap();
        k.apply(approve(3, vec![[2; 32]], mid(3), 3)).unwrap();
        k.apply(commit(4, vec![[3; 32]], mid(2), 2)).unwrap();
        assert_eq!(
            q_role_of(&k, &mid(6)),
            Some(KeyringRole::EDITOR),
            "co-owner unanimity is powerless here"
        );
        // the founder alone still governs.
        let mut k2 = quorum_engine_with(&m, KeyringQuorum::founder_only());
        k2.apply(genesis(&m)).unwrap();
        k2.apply(propose(
            2,
            vec![[1; 32]],
            mid(1),
            1,
            promote(6, KeyringRole::CO_OWNER),
        ))
        .unwrap();
        k2.apply(commit(3, vec![[2; 32]], mid(1), 1)).unwrap();
        assert_eq!(
            q_role_of(&k2, &mid(6)),
            Some(KeyringRole::CO_OWNER),
            "founder alone governs"
        );
    }

    #[test]
    fn threshold_rule_needs_m_of_n_signers() {
        // A "3 of 4" family: founder + 3 co-owners, any 3 signers suffice, no special founder path.
        let m = [
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::CO_OWNER, 3),
            minit(KeyringRole::CO_OWNER, 4),
            minit(KeyringRole::EDITOR, 6),
        ];
        // Two signers (bob proposer + carol) is short of 3 -> refused.
        let mut short = quorum_engine_with(&m, KeyringQuorum::threshold(3));
        short.apply(genesis(&m)).unwrap();
        short
            .apply(propose(
                2,
                vec![[1; 32]],
                mid(2),
                2,
                promote(6, KeyringRole::CO_OWNER),
            ))
            .unwrap();
        short.apply(approve(3, vec![[2; 32]], mid(3), 3)).unwrap();
        short.apply(commit(4, vec![[3; 32]], mid(2), 2)).unwrap();
        assert_eq!(
            q_role_of(&short, &mid(6)),
            Some(KeyringRole::EDITOR),
            "2 of 4 is short of the threshold"
        );
        // Three signers (bob + carol + dave) meet 3-of-4 -> applied, without the founder.
        let mut ok = quorum_engine_with(&m, KeyringQuorum::threshold(3));
        ok.apply(genesis(&m)).unwrap();
        ok.apply(propose(
            2,
            vec![[1; 32]],
            mid(2),
            2,
            promote(6, KeyringRole::CO_OWNER),
        ))
        .unwrap();
        ok.apply(approve(3, vec![[2; 32]], mid(3), 3)).unwrap();
        ok.apply(approve(4, vec![[3; 32]], mid(4), 4)).unwrap();
        ok.apply(commit(5, vec![[4; 32]], mid(2), 2)).unwrap();
        assert_eq!(
            q_role_of(&ok, &mid(6)),
            Some(KeyringRole::CO_OWNER),
            "3 of 4 signers meet the threshold"
        );
    }

    #[test]
    fn an_in_dag_create_seeds_only_an_empty_group_with_one_owner_author() {
        // The OPE-271 Create gate: a Create seeds ONLY an empty group, with EXACTLY one Owner, authored by
        // one of the op's OWN members — the gate that stops a second attacker-signed Create from re-founding
        // an established group.
        let founder = minit(KeyringRole::OWNER, 1);
        let mut k = engine(&[]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![founder],
            },
            &sk(1),
        ))
        .unwrap();
        assert_eq!(
            members(&k),
            roster(&[(1, KeyringRole::OWNER)]),
            "a well-formed Create seeds the empty group"
        );

        // A Create carrying TWO Owners does NOT seed (the owner count must be exactly one).
        let mut k2 = engine(&[]);
        k2.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![minit(KeyringRole::OWNER, 1), minit(KeyringRole::OWNER, 9)],
            },
            &sk(1),
        ))
        .unwrap();
        assert!(
            members(&k2).is_empty(),
            "a two-Owner Create must not seed the group"
        );
    }

    #[test]
    fn a_quorum_demotion_excludes_the_target_from_the_denominator() {
        // Demoting a co-owner via founder-or-unanimity must NOT need the target's own approval — the target
        // is excluded from both the eligible set and the unanimity denominator. bob + carol (unanimity
        // minus the target dave) demote dave; if dave were counted, his missing approval would block it.
        let m = [
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
            minit(KeyringRole::CO_OWNER, 3),
            minit(KeyringRole::CO_OWNER, 4),
        ];
        let mut k = quorum_engine(&m);
        k.apply(genesis(&m)).unwrap();
        k.apply(propose(
            2,
            vec![[1; 32]],
            mid(2),
            2,
            promote(4, KeyringRole::EDITOR),
        ))
        .unwrap();
        k.apply(approve(3, vec![[2; 32]], mid(3), 3)).unwrap();
        k.apply(commit(4, vec![[3; 32]], mid(2), 2)).unwrap();
        assert_eq!(
            q_role_of(&k, &mid(4)),
            Some(KeyringRole::EDITOR),
            "bob + carol demote dave without dave's own approval"
        );
    }

    #[test]
    fn a_removed_member_cannot_authorize_a_later_change() {
        // A member removed at an earlier causal position has no authority over a later op it authors: the
        // change must not take effect. (The resolver voids a removed author's op, so this holds independent
        // of the is_authorized `is_active` guard — which is why that guard is a defensive one.)
        let mut k = engine(&[
            minit(KeyringRole::OWNER, 1),
            minit(KeyringRole::CO_OWNER, 2),
        ]);
        k.apply(sign_op(
            [2; 32],
            vec![],
            mid(1),
            MembershipAction::Remove { member: mid(2) },
            &sk(1),
        ))
        .unwrap();
        // bob's add is a CHILD of his own removal — bob is inactive at this position.
        k.apply(sign_op(
            [3; 32],
            vec![[2; 32]],
            mid(2),
            add(KeyringRole::EDITOR, 3),
            &sk(2),
        ))
        .unwrap();
        assert!(
            !members(&k).iter().any(|(id, _)| id == &mid(3)),
            "a removed (inactive) member cannot authorize a change"
        );
    }

    // ---- OPE-543 self-cert admission gate ----

    /// A well-signed Add whose member id is NOT the uuid8 of its own carried author key is UNAUTHORIZED at
    /// every replica (admitted, but folded to no effect) — the self-cert binding the resolver enforces.
    #[test]
    fn an_add_whose_member_id_does_not_bind_its_key_is_unauthorized() {
        let mut k = engine(&[minit(KeyringRole::OWNER, 1)]);
        k.apply(sign_op(
            [1; 32],
            vec![],
            mid(1),
            MembershipAction::Create {
                initial_members: vec![minit(KeyringRole::OWNER, 1)],
            },
            &sk(1),
        ))
        .unwrap();
        let forged_id = "aaaaaaaa-aaaa-8aaa-8aaa-aaaaaaaaaaaa".to_string();
        assert_ne!(
            forged_id,
            mid(3),
            "the forged id is deliberately not the key's uuid8"
        );
        k.apply(sign_op(
            [2; 32],
            vec![[1; 32]],
            mid(1),
            MembershipAction::Add {
                member: forged_id.clone(),
                role: KeyringRole::EDITOR,
                author_public_key: vk(3),
                hpke_public_key: [3; 32],
                member_proof: None,
            },
            &sk(1),
        ))
        .unwrap();
        assert!(
            !k.state().members.contains_key(&forged_id),
            "a non-self-certifying member id is refused admission"
        );
    }

    /// The genesis Create gate enforces the same binding: an initial member whose id is not the uuid8 of its
    /// carried key must not seed the group.
    #[test]
    fn a_create_with_a_non_binding_member_does_not_seed() {
        let mut k = engine(&[]);
        let forged = KeyringMemberInit {
            id: "aaaaaaaa-aaaa-8aaa-8aaa-aaaaaaaaaaaa".to_string(),
            role: KeyringRole::OWNER,
            author_public_key: vk(1),
            hpke_public_key: [1; 32],
        };
        k.apply(sign_op(
            [1; 32],
            vec![],
            forged.id.clone(),
            MembershipAction::Create {
                initial_members: vec![forged],
            },
            &sk(1),
        ))
        .unwrap();
        assert!(
            members(&k).is_empty(),
            "a Create with a non-self-certifying member does not seed"
        );
    }
}
