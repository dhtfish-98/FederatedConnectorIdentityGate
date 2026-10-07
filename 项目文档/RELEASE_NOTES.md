# Version 0.1.1

Corrects the README, design and validation statements that still described remote CI and publication as pending after v0.1.0 had been published. The dated record links the exact earlier commit, successful main/tag runs and independently downloaded asset hashes. Version declarations and the existing version checks are updated to 0.1.1; the identity/session/resource implementation, test cases and validation flow are unchanged.

The original source and third-party rights remain attributed to their actual owners. This documentation correction does not establish production suitability or CVP qualification or approval.

# Version 0.1.0

FederatedConnectorIdentityGate 0.1.0 guards a downstream application's local subject, session and resource mapping after federated login through Dex. It verifies a Dex-signed ID token, then keys ownership to the trusted issuer plus signed connector and upstream user identifiers. A test-only email-keyed baseline collides when two live local identity sources use the same email; the guarded implementation preserves their separation.

Local validation uses a real Dex binary built from fixed upstream commit `c7ced47db7f9dc92192969e6c396e393275278eb` and two original loopback OIDC sources. It covers valid authorization-code flow, both cross-resource denials, session rotation and persistence, equal upstream IDs under different connectors, and rejection of wrong nonce, audience, trusted issuer, altered signature, expired real token, missing federated identifiers and unverified email.

This is an independently written downstream application experiment, not a Dex vulnerability or patch. Dex and Go module licenses remain with their respective owners. The state file requires a caller-protected directory and a single process. CVP qualification and approval remain OPEN.
