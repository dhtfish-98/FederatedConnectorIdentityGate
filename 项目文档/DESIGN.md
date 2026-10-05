# FederatedConnectorIdentityGate: local experiment and boundary

Status: **local live and extracted source-package acceptance PASS at the pinned Dex commit; public CI OPEN**. No published repository or CVP eligibility claim exists.

## Boundary

The protected component is an independently written **downstream application** receiving an ID token from a locally running, pinned Dex. The application verifies Dex's signature and `iss`, `aud`, `exp`, and authorization-flow `nonce` before it uses the signed `federated_claims.connector_id` and `federated_claims.user_id`. Its local subject key includes the Dex issuer and both federated identifiers. Email is display data, never the account key. Resources and application sessions are owned by that local subject key.

This is **not a proposed Dex vulnerability or Dex patch**. At fixed Dex commit [`c7ced47db7f9dc92192969e6c396e393275278eb`](https://github.com/dexidp/dex/commit/c7ced47db7f9dc92192969e6c396e393275278eb), Dex's [login finalization](https://github.com/dexidp/dex/blob/c7ced47db7f9dc92192969e6c396e393275278eb/server/authflow/finalize.go) queries identities and offline sessions by `(userID, connectorID)`. Its [subject generator](https://github.com/dexidp/dex/blob/c7ced47db7f9dc92192969e6c396e393275278eb/server/tokens/claims.go) encodes that pair, and [token issuance](https://github.com/dexidp/dex/blob/c7ced47db7f9dc92192969e6c396e393275278eb/server/tokens/issuer.go) can carry federated identifiers when the [`federated:id` scope](https://github.com/dexidp/dex/blob/c7ced47db7f9dc92192969e6c396e393275278eb/server/tokens/scopes.go) is requested. The experiment tests whether a separate application's own mapping preserves those distinctions.

## Local actors and comparison

Two self-written OIDC test identity sources run only on loopback. They issue distinct upstream `sub` values with the **same email**. A pinned Dex executable uses two different OIDC connector IDs, completes real authorization-code exchanges, and signs the resulting ID tokens. A test-only application baseline keys local accounts by email and shows a cross-account resource collision. The guarded implementation keys by `(Dex issuer, connector ID, upstream user ID)`, issues separate application sessions, and keeps resource ownership separate.

| Case | Expected guarded result |
| --- | --- |
| Two verified upstream identities share one email | Two local subjects, sessions, and resource owners |
| Same upstream user ID appears through a different connector | Separate local subjects |
| Unverified email | Reject binding before local session creation |
| Wrong trusted Dex issuer, audience, nonce, expired real Dex token, altered signature, or missing federated claims | Reject before account or resource mutation |
| A session tries to access B's resource | Deny; no account merge |
| B logs in while A's cookie is present | Rotate/revoke that browser's prior local session, then bind B independently; old cookie replay fails |

The session test is limited to application account isolation and revocation on login. It does not show that an otherwise valid bearer cookie is immune to theft or replay outside this controlled flow. The wrong-issuer case supplies an incorrect configured discovery URL and observes fail-closed rejection; it does not represent a second Dex deployment. The expiry case first verifies a real Dex-signed ID token with an eight-second test lifetime, waits past its signed `exp`, then verifies that same token is rejected.

## Hard acceptance and rights

Acceptance requires real locally run Dex at the exact fixed commit, two live local OIDC sources, Dex-signed tokens, signature/claim verification, local persistent identity/session/resource state, and the weak-versus-guarded comparison. Hand-authored JSON or a fabricated JWT cannot replace that gate. The pinned binary was built under centralized `Build` with an isolated Go 1.27.0 toolchain; its embedded VCS revision is the pinned commit and `vcs.modified=false`. Both the source checkout and an extracted versioned source archive passed the live test, with sanitized local evidence under `Build/验证/FederatedConnectorIdentityGate-20261006`. Independent review, remote CI and publication remain separate gates.

The caller must place the persistent state file beneath a directory it controls and protects from other users. `OpenStore` rejects a non-regular existing file but does not sandbox a caller-selected path, authenticate filesystem ownership, resist hostile parent-directory replacement, or coordinate multiple processes. The in-memory lock protects only one `Store` instance. The lab runs one process; a production application would need process-wide transactional storage, hardened filesystem ownership and recovery policy. Local HTTP endpoints are loopback-only test fixtures, not a production TLS deployment.

Dex is Apache-2.0 at its [fixed-commit license](https://github.com/dexidp/dex/blob/c7ced47db7f9dc92192969e6c396e393275278eb/LICENSE). Dex code and its binary remain local test dependencies under `Build` and are not copied into this project's source package. New implementation code is attributed to dhtfish98; its own rights notice and third-party dependency attribution are documented separately. `OAuthCodePkceReplayReview` concerns code/PKCE reuse; `ProxyIdentityHeaderTrust` concerns backend identity headers. This experiment concerns the **post-login downstream local subject and resource mapping**. CVP identity, qualifying task, and provider approval remain **OPEN**.
