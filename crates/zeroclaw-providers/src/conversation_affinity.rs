//! Opaque per-conversation tokens for provider-side cache affinity.
//!
//! Some backends keep a prompt cache warm only for requests that say which
//! conversation they belong to. The identity ZeroClaw has for a conversation is
//! its session key ([`zeroclaw_api::TOOL_LOOP_SESSION_KEY`]), and session keys
//! embed channel and user identifiers — `sanitize_session_key` covers inputs
//! shaped like `whatsapp_123@g.us_user_a`. Forwarding one verbatim would hand a
//! third party a cross-service-linkable per-user identifier, which the privacy
//! contract in `docs/book/src/contributing/privacy.md` forbids. Providers
//! therefore send a digest of the scope, never the scope.
//!
//! The digest is domain-separated but unsalted, so it is deterministic across
//! restarts — which is what preserves affinity for a conversation that spans a
//! daemon restart. The tradeoff is explicit: this prevents plaintext exposure
//! of channel and user identifiers and gives the recipient a stable pseudonym
//! per conversation, but it is not a defense against a party who knows
//! ZeroClaw's session-key format brute-forcing a low-entropy key space.
//! Defeating that would require a per-install salt, which would cost the
//! cross-restart affinity this is for.

use sha2::{Digest, Sha256};

/// Bytes of SHA-256 output kept. 128 bits is far beyond what backend selection
/// needs and keeps the token short.
pub(crate) const TOKEN_BYTES: usize = 16;

/// The ambient conversation scope, or `None` outside one or when it is blank.
///
/// This reads a `tokio` task-local, which **does not** cross `tokio::spawn`.
/// The streaming provider paths build their requests inside
/// `zeroclaw_spawn::spawn!`, whose macro propagates only the tracing span, so a
/// read from inside a spawned task silently sees no conversation. Resolve the
/// value before the spawn and move it in.
pub(crate) fn scope() -> Option<String> {
    zeroclaw_api::TOOL_LOOP_SESSION_KEY
        .try_with(Clone::clone)
        .ok()
        .flatten()
        .filter(|key| !key.trim().is_empty())
}

/// Domain-separated, truncated SHA-256 of one affinity scope, as lowercase hex.
///
/// `domain` keeps a token derived for one provider from colliding with a
/// digest this codebase derives from the same scope for another purpose.
pub(crate) fn digest(domain: &str, scope: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    // A length-free separator would let a crafted scope reproduce another
    // domain's preimage; a NUL cannot appear in the tag, so it terminates it
    // unambiguously.
    hasher.update([0u8]);
    hasher.update(scope.as_bytes());
    hex::encode(&hasher.finalize()[..TOKEN_BYTES])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_domain_separated_and_fixed_length() {
        let one = digest("zeroclaw.test.one.v1", "telegram_1001_user_a");
        let two = digest("zeroclaw.test.two.v1", "telegram_1001_user_a");
        assert_ne!(
            one, two,
            "one scope must not yield one token in two domains"
        );
        assert_eq!(one.len(), TOKEN_BYTES * 2);
        assert!(
            one.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        // A scope that reproduces the tag's bytes must not collide with it.
        assert_ne!(
            digest("zeroclaw.test.one.v1", ""),
            digest("zeroclaw.test.one.v1", "zeroclaw.test.one.v1")
        );
    }

    #[tokio::test]
    async fn scope_is_absent_outside_a_conversation_and_when_blank() {
        assert_eq!(scope(), None);
        for blank in [None, Some("   ".to_string())] {
            let seen = zeroclaw_api::TOOL_LOOP_SESSION_KEY
                .scope(blank, async { scope() })
                .await;
            assert_eq!(seen, None);
        }
        let seen = zeroclaw_api::TOOL_LOOP_SESSION_KEY
            .scope(Some("gw_one".to_string()), async { scope() })
            .await;
        assert_eq!(seen.as_deref(), Some("gw_one"));
    }
}
