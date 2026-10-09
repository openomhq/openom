# OpenTofu state encryption

This document defines the custody and rollover contract for OpenTofu state. Each persistent root uses an
independent, randomly generated passphrase from Infisical. OpenTofu derives a 32-byte key with PBKDF2-SHA512
and encrypts state with AES-256-GCM.

| root | state key | Infisical secret |
| --- | --- | --- |
| `infra/terraform/` | `staging/terraform.tfstate` | `TOFU_STATE_PASSPHRASE_SERVER` |
| `infra/terraform/domain/` | `domain/staging.tfstate` | `TOFU_STATE_PASSPHRASE_DOMAIN` |
| `infra/terraform/web/` | `web/staging.tfstate` | `TOFU_STATE_PASSPHRASE_WEB` |
| `infra/terraform/preview/` | `preview/terraform.tfstate` | `TOFU_STATE_PASSPHRASE_PREVIEW_PLATFORM` |

The server secret is available to the GitHub Staging environment through the Infisical sync. The other roots
are admin-applied and their secrets remain in Infisical's Production `/admin` path. Infisical is currently the
sole recovery store. Losing a root's passphrase makes its encrypted state unreadable.

## Initial encryption

Migrate one root at a time:

1. Confirm the expected state object and record its current S3 version ID. Do not print or download it into the
   repository.
2. Supply the root's passphrase as a sensitive, ephemeral OpenTofu variable. Never put it in HCL, a tfvars file,
   a saved plan command, or process output. Ephemeral variables are omitted from state and plan files.
3. Configure PBKDF2 as the primary key provider and AES-GCM as the primary state method. Temporarily configure
   `unencrypted` only as the state fallback.
4. Run `tofu apply -refresh-only`. It refreshes and rewrites state without changing remote infrastructure.
5. Inspect the stored object structurally: it must contain the OpenTofu encryption envelope and must not expose
   normal state fields or known fixture values.
6. Remove the unencrypted method and fallback, set `enforced = true`, and run `tofu plan` again.
7. Confirm that a missing or incorrect passphrase fails before OpenTofu can plan.

The unencrypted fallback is migration-only. It must never remain in the final configuration.

## Passphrase rotation

Do not overwrite the old Infisical value before the state has been re-encrypted:

1. Create a new random passphrase while retaining the old one temporarily.
2. Add the new PBKDF2 provider and AES-GCM method as the primary method. Give its encrypted metadata a new alias.
3. Keep the old provider and method only as the fallback, with the metadata alias stored in the current state.
4. Run `tofu apply`; OpenTofu reads through the fallback and writes through the new primary method.
5. Remove the old provider, method, fallback, and old Infisical value only after a clean plan succeeds with the
   new passphrase and fails with the old passphrase.

Metadata aliases are part of the encrypted envelope. Do not rename one in place. For repeated rotations, use a
new alias or alternate between two aliases after the previous envelope is no longer current.

## Recovery

If the current state object is damaged, select a known-good S3 version and the passphrase that encrypted that
version. Rehearse the candidate without replacing the live object:

1. Create a clean checkout outside the repository and download the selected object version to a temporary file.
   Never print or check in the file.
2. Configure that checkout with a local backend and the encryption method that matches the selected version. A
   pre-encryption version may use the unencrypted fallback only in this isolated recovery checkout.
3. Run `tofu init`, then `tofu state list -state=<temporary-file>`. Compare resource addresses with current state;
   do not render resource values merely to prove readability.
4. Delete the checkout and downloaded state after the rehearsal.

For an actual restore, freeze applies and confirm the active root, bucket, key, version ID, and matching
passphrase before copying the selected version onto the active key. S3 creates a new current version, so the
displaced state remains recoverable. Reinitialize the backend and inspect the full plan. An older state can omit
newer resources; import those resources before applying rather than recreating or replacing them. If the restored
version is plaintext, enable the migration fallback only long enough to run a refresh-only encryption apply, then
remove it and restore enforced mode.

Encryption protects confidentiality; S3 versioning provides recovery, while replay and rollback decisions remain
an operator responsibility.

Run the executable proof with `task test:terraform`. It uses disposable local state to verify
plaintext migration, enforced encryption, missing- and wrong-passphrase rejection, and passphrase rollover.
