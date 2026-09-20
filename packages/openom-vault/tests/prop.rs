//! Fuzz surface for the vault: it decodes untrusted keyring bytes from a partly-trusted server, so
//! `unlock`/`recover` on ARBITRARY bytes must never panic — only ever return an error. (Random bytes never
//! decode to a keyring, so these return before any crypto runs — cheap.)

use openom_crypto::Passphrase;
use openom_protocol::ids::{MemberId, ReplicaId, TreeId};
use openom_vault::vault::{recover, unlock, RecoverWatermark};
use openom_vault::AccountKeystore;
use proptest::prelude::*;

proptest! {
    #[test]
    fn unlock_on_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // OPE-543: unlock takes the durable ACCOUNT identity; the arbitrary bytes are the untrusted keyring.
        let (_ks, _code, account) = AccountKeystore::create(b"pass").unwrap();
        let r = unlock(
            &bytes,
            account,
            &TreeId::new(b"tree-uuid-16byte".as_slice()),
            &MemberId::new("acct-1"),
            &ReplicaId::new(b"replica-0".as_slice()),
        );
        prop_assert!(r.is_err());
    }

    #[test]
    fn recover_on_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Recovery is account-keystore-mediated; a valid keystore blob + code, arbitrary (untrusted) keyring.
        let (ks, code, _account) = AccountKeystore::create(b"pass").unwrap();
        let r = recover(
            &bytes,
            &ks.to_bytes().unwrap(),
            &code,
            &Passphrase::new(b"pass".to_vec()),
            &TreeId::new(b"tree-uuid-16byte".as_slice()),
            &MemberId::new("acct-1"),
            &ReplicaId::new(b"replica-0".as_slice()),
            &RecoverWatermark { min_revision: 0, write_key_id: &[], dek_hash: &[] },
        );
        prop_assert!(r.is_err());
    }
}
