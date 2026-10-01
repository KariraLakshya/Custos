# 0007: Agent key custody, issuer-signed credentials, and proof of possession

**Status:** Accepted, 2026-09-25. Decisions 1, 2 and 4 implemented (Phase 5b steps 1–2; see "Implementation notes" below); decision 3 (proof of possession on `POST /tokens`) implemented in step 3. See "Implementation notes" for both. Scope is tracked as Phase 5b in `docs/build-plan.md`. Design discussion: Notion, "12 — Auth security review".

## Context

Two properties of the Phase 1–5 design combine into one gap.

1. **The agent's credential is a bearer credential.** `POST /tokens` on the vault accepts the agent's signed credential and nothing else (`services/vault/src/tokens/issue.ts`). The signature proves the credential was not altered. It does not prove the caller is the agent. Anyone holding a copy of `agent.json` can obtain scoped tokens as that agent.
2. **The agent never holds its own private key.** `services/identity/src/agents/register.ts` creates the agent's keypair in the identity service's `KeyProvider`, signs the credential with it, and returns only the credential. So even if the vault demanded proof of possession, the agent could not produce it.

The credential is also **self-issued**: `issuer` and `credentialSubject.id` are both the agent's DID, signed with the agent's key. It asserts "I am agent X", signed by agent X. Nobody vouches for the agent, which undercuts the audit direction in CLAUDE.md §10 ("which agent, acting under whose authority").

Three decisions follow, and they have to be made together.

### 1. The agent generates and holds its own key (Option A)

**Decision:** the agent creates its Ed25519 keypair locally and sends only the public key at registration. The private key never crosses the wire, the identity service's memory, or any Custos log.

Rejected, Option B: the key stays in a KMS and the agent asks the KMS to sign. The agent would still have to prove to the KMS who it is, so the authentication problem moves one layer down rather than going away. It would also put a live KMS call on the path of every proof.

**Registration must itself prove possession.** Otherwise a caller could register a public key it does not control. The registration request carries a signature by the submitted key over the request (same construction as decision 3), the way a TLS certificate request is self-signed.

**Where the agent's key lives is the agent's responsibility,** and that needs stating against CLAUDE.md §4 ("private signing keys never touch disk"). That rule governs Custos's own keys: service signing keys and the issuer key. An agent's key belongs to the agent's deployment. Custos's obligations are to never receive it, and to make the safe path the default:

- The SDK keeps the key in memory and hands persistence to the caller.
- The CLI writes it to its own file, separate from the credential, with owner-only permissions.
- The README says it must be stored like any private key.

### 2. The identity service issues and signs agent credentials (Option 2)

With decision 1, the identity service can no longer sign "as" the agent. Someone else must sign the credential.

**Decision:** the identity service gets its own `did:web` identity and signing key, the same pattern the revocation and audit services already use, and signs every agent credential as **issuer**. The credential becomes: _issuer = the identity service; subject = the agent's DID; the subject's public key embedded in `credentialSubject`._

Rejected, agent self-signs its credential: it proves only that someone generated a keypair, and a self-signed credential for an invented agent verifies exactly as well as a real one.

**The agent's public key goes inside the credential,** not only in the agent's hosted DID document. A verifier then needs just the issuer's public key, which is cached, one key for every agent, to check both the credential and every proof of possession. That keeps verification fully offline (CLAUDE.md §3). It is also what Phase 6 requires: "machine A's server is switched off entirely; B still verifies A's agent from the credential alone". Under that test the agent's DID document, hosted on A's server, would be unreachable. The identity service keeps publishing agent DID documents, but no Custos verifier depends on them.

**The agent's identity is `credentialSubject.id`, never `issuer`.** Today the vault keys revocation checks, allowlist lookups, and audit records on `agentCredential.issuer`, which is correct only while credentials are self-issued. Every one of those reads must move to the subject in the same change. A missed one would key decisions to the identity service's DID, so every agent would share one revocation bit and one allowlist. Negative tests must cover it.

### 3. Proof of possession gates token issuance, not tool calls

**Decision:** `POST /tokens` requires a proof, a signature by the key embedded in the credential, over:

- the HTTP method and target URL,
- an issued-at timestamp,
- a unique proof ID,
- a hash of the presented credential.

This follows the RFC 9449 (DPoP) pattern rather than a new construction (CLAUDE.md §4: no novel constructions). It is encoded in the existing compact Ed25519 envelope family (ADR 0003), not JWT.

The vault verifies, failing closed on any miss:

- the credential against the issuer key,
- the proof against the subject key,
- the timestamp within a bounded skew window (explicit configuration, CLAUDE.md §3),
- the proof ID not seen before within that window. Replay cache: in-memory for the current single-instance vault, behind an interface so Redis can back it when the vault runs as several instances.

No server-issued nonce, which saves a round trip per token request. RFC 9449 makes the nonce optional, and the skew window plus replay cache cover the same replay threat. A server nonce can be added behind the same check later if needed.

**The hot path is unchanged.** Proof of possession runs once per token request. The resulting 60s scoped token (ADR 0003) authorizes `/call` as today, with no extra signature check per tool call.

### 4. Prerequisite: the issuer key must be stable across restarts

Every service today uses `createLocalKeyProvider()`, which generates a new key per process. That is harmless for the audit and revocation services, which re-sign on read (ADR 0006) or rebuild live (ADR 0005). It is fatal for an issuer: credentials are signed once, at registration, and held by agents, so a restart with a new key would invalidate every credential ever issued.

**Decision:** before the identity service becomes an issuer, it gets a key that survives restarts, behind the existing `KeyProvider` interface (ADR 0002):

- **Production: AWS KMS.** It supports Ed25519 (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512` with `MessageType: RAW`, since November 2025). This is pure Ed25519, so signatures verify with `@noble/ed25519` unchanged. The private key never leaves KMS.
- **Local development: key material from an environment variable.** Same precedent and same trade-off as `VAULT_MASTER_KEY` (ADR 0004): explicitly dev-only, no default, refuses to boot without it. It is never written to disk by Custos.

`KeyProvider` gains a way to use an existing key by ID (today it can only create one). That is an additive interface change.

Key rotation for the issuer is not designed here. When it is, the issuer's DID document will list both old and new keys during a transition window. Until then it is a recorded known gap, alongside agent key rotation and multi-host agents, both deferred in the design discussion.

## Consequences

- A copied `agent.json` no longer grants anything: token issuance requires a signature only the holder of the agent's private key can make. This must be proven by a negative test in CI (CLAUDE.md §4).
- Credentials now say who vouched for the agent. That is the basis for the §10 audit claim and for Phase 6 federation, where another organisation trusts one issuer key rather than every agent individually.
- The issuer key becomes the most sensitive key in the system: whoever can sign with it can mint any agent. That is why decision 4 puts it in KMS (sign-only, never exportable) and why every issuance is audited.
- **Breaking change, no migration path:** credentials issued before this change fail verification. Accepted deliberately. There are no external users, and a dual-format verifier would be exactly the kind of bypassable security check CLAUDE.md §4 forbids.
- The SDK needs Ed25519 key generation and signing. See the implementation notes: it uses a light `@custos/core/possession` entry point rather than a direct `@noble/ed25519` dependency.
- The CLI's `register` writes two files: the credential and, separately, the agent's private key. The README walkthrough and the dry run must be redone against the new flow. That is the reason Phase 5's non-author validation is scheduled after Phase 5b rather than before it.
- Operator authentication for the control-plane endpoints (`/credentials`, `/policies`, the revocation service's `/revocations`) is a separate decision with its own ADR (0008), written when that work starts. It is not decided here. The vault's own `POST /revocations` (the tombstone receiver, which shares its path with the revocation service's operator endpoint) is not a control-plane endpoint: it is already authenticated by the tombstone's own signature and must stay reachable by the revocation service.

## Implementation notes (Phase 5b steps 1–2, 2026-09-25)

Decisions made while implementing, recorded here because they shape the security model:

- **Embedding the agent's key needs an inline JSON-LD context.** No bundled context defines `publicKeyMultibase` outside a verification-method object, and the signing suite's safe mode refuses undefined terms: signing fails rather than silently leaving the field unsigned. The credential carries an inline context mapping `publicKeyMultibase` to `https://w3id.org/security#publicKeyMultibase`. Inline, so verification still fetches nothing. Tests prove that swapping the embedded key or the subject breaks the signature.
- **The vault pins its trusted issuer** (`VAULT_TRUSTED_ISSUER_DID`, default `did:web:localhost%3A4001`) and refuses any other issuer before any other check (`UNTRUSTED_ISSUER`). This was implicit in decision 2 but is the load-bearing part: without it, a self-issued credential from anyone's own did:web domain would verify. The issuer's DID document is resolved once and cached, and it must name the DID it was fetched for. A rotation needs a vault restart, the same as the revocation issuer.
- **Revocation and the allowlist are now checked after signature verification,** not before. The agent's identity is read from `credentialSubject.id`, which is only trustworthy once verified. Checking revocation first would also have written an unverified claimant's chosen DID into the audit log.
- **Registration proof:** `typ: custos-registration-proof`, `aud` = the identity service's DID, `iat` within ±60 s (`IDENTITY_REGISTRATION_PROOF_MAX_SKEW_SECONDS`), and a `jti`. Replay is defeated by a **unique constraint on the agent's public key**, one key per agent, rather than a `jti` cache: a replayed request gets `KEY_ALREADY_REGISTERED` (409). The request is fully checked before a status list index is allocated, so bad requests consume nothing.
- **Deviation: the SDK uses `@custos/core/possession`,** a new light entry point exporting only Ed25519, multibase/did:web helpers and the proof envelope. It doesn't take a direct `@noble/ed25519` dependency. Reason: the proof envelope is a signed wire format, and a second copy in the SDK could drift from the verifier's. The entry point doesn't load the JSON-LD stack at runtime.
- **The identity service's issuer key is required at boot, with no default.** `IDENTITY_KEY_PROVIDER` selects `local` (`IDENTITY_ISSUER_SEED`) or `kms` (`IDENTITY_ISSUER_KMS_KEY_ID`; AWS region and credentials from standard AWS configuration). A missing setting for the chosen provider is a boot failure, never a fallback to the other one, and the public key is read at boot, so an unusable KMS key or credential stops the service before it serves. A real-KMS check (`pnpm --filter @custos/identity test:kms`, opt-in, never in CI) proves KMS signatures verify with `@custos/core`. Run against real AWS KMS on 2026-10-01 (`ap-south-1`): 3/3 passed, including a KMS-signed agent credential that verifies against the issuer DID document. The `agents.key_id` column is now nullable and unused, not dropped (non-destructive migration `0005`).
- **Still open, by design:** `POST /agents` itself is unauthenticated, so anyone can register an agent, though never with a key they don't hold. Operator authorization of registration belongs with ADR 0008. `agent.json` alone still obtains tokens until step 3 adds proof of possession to `POST /tokens`.

## Implementation notes (Phase 5b step 3, 2026-09-25)

- **Proof claims:** `typ: custos-token-request-proof`, `aud` = the vault's own `/tokens` URL, `iat` within ±60 s (`VAULT_TOKEN_PROOF_MAX_SKEW_SECONDS`), and a `jti`. `aud` covers both the HTTP method and the target URL of decision 3: `/tokens` accepts only POST, so the URL alone identifies the request.
- **The vault's URL comes from configuration** (`VAULT_PUBLIC_URL`, default `http://localhost:4002`), never from the request's Host header, which the client or a proxy controls. Consequence: agents must call the vault at exactly that URL; `localhost` and `127.0.0.1` are different audiences. The README's troubleshooting table covers it.
- **Deviation: no hash of the presented credential in the proof.** Decision 3 listed it. It adds nothing here: the proof is verified against the public key _embedded in_ the presented credential, and each key belongs to exactly one agent (unique constraint, steps 1–2). So a valid proof already binds to that agent's credential. Dropping it also avoids a credential-hashing rule that client and vault would have to keep byte-identical.
- **Order:** credential verified, then the agent's key is read from `credentialSubject.publicKeyMultibase` (missing: `INVALID_AGENT_CREDENTIAL / MISSING_AGENT_KEY`), then the proof is checked, then the replay cache, and only then revocation and the allowlist. A copied credential gets `INVALID_PROOF_OF_POSSESSION` (401) and learns nothing about the agent's revocation or grants.
- **Replay cache:** in memory, behind a `ReplayCache` interface (`services/vault/src/tokens/replay-cache.ts`) so Redis can back it for multi-instance vaults. Keyed on agent DID + `jti`, kept until `iat + skew`, recorded only after the signature verifies, so nobody but the agent can use up its `jti`s. It's bounded (100 000 entries): when full of unexpired ids it refuses (`REPLAY_CACHE_FULL`) rather than evicting a live id.
- **Proof failures are not written to the audit log.** The audit record means "this agent did X", and a failed proof is by definition not the agent. Recording impostor attempts is a separate security-events concern, not built.
- **Clients:** the SDK signs a fresh proof per call (`connect()` now needs `secretKey`). The CLI's `use` reads `--key` (default `agent.key`), and rejects anything that isn't 64 hex characters before contacting the vault.
