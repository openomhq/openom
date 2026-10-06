variable "state_passphrase" {
  description = "Passphrase used to encrypt this root's OpenTofu state."
  type        = string
  sensitive   = true
  ephemeral   = true
}

terraform {
  encryption {
    key_provider "pbkdf2" "current" {
      passphrase               = var.state_passphrase
      encrypted_metadata_alias = "openom_state"
    }

    method "aes_gcm" "current" {
      keys = key_provider.pbkdf2.current
    }

    state {
      method   = method.aes_gcm.current
      enforced = true
    }
  }
}
