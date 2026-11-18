# Agent identity

Every Custos agent has two things: a **DID**, its name on the network, and a **credential**, a signed statement that ties that name to the agent's public key.

## The DID

A DID (decentralised identifier) is a URI that names something and says where its public key is published. Custos uses `did:web`, which maps to a web address:

```text
did:web:localhost%3A4001:agents:3f2b8c1e-...
   →  http://localhost:4001/agents/3f2b8c1e-.../did.json
```

(`%3A` is an encoded `:` before the port.) The identity service is itself a `did:web` identity, `did:web:localhost%3A4001` locally, and publishes its own key at `/.well-known/did.json`. The domain comes from `IDENTITY_DID_DOMAIN`.

## The credential

When you register an agent, the identity service returns a W3C Verifiable Credential (VC Data Model 2.0). In outline:

```json
{
  "type": ["VerifiableCredential"],
  "issuer": "did:web:localhost%3A4001",
  "validFrom": "2026-11-18T10:00:00.000Z",
  "credentialSubject": {
    "id": "did:web:localhost%3A4001:agents:3f2b8c1e-...",
    "publicKeyMultibase": "z6Mk..."
  },
  "credentialStatus": {
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "...": "..."
  },
  "proof": { "type": "Ed25519Signature2020", "...": "..." }
}
```

- **`issuer`** is the identity service. It signs every agent credential with its **issuer key**.
- **`credentialSubject.id`** is the agent. Custos always identifies the agent by the subject, never by the issuer.
- **`publicKeyMultibase`** is the agent's own public key, inside the credential. A verifier needs only the issuer's key to check both the credential and every request the agent signs. It never has to fetch the agent's own DID document.
- **`credentialStatus`** points at the agent's bit in the revocation status list ([Revocation](/concepts/revocation)).

The signature is a JSON-LD Data Integrity proof (`Ed25519Signature2020`), made with established libraries rather than hand-written code (ADR 0001). The JSON-LD contexts are bundled and never fetched from the network, which closes a known class of attack where a credential points the verifier at an attacker's context.

::: warning No expiry yet
Agent credentials have a `validFrom` and no `validUntil`, so they do not expire. Revocation is the way to end an agent today.
:::

## Registration

1. The CLI or SDK generates an Ed25519 key pair **where the agent runs**.
2. It sends only the public key, with a **registration proof**: a signature by that key, addressed to the identity service, made in the last minute (`IDENTITY_REGISTRATION_PROOF_MAX_SKEW_SECONDS`, default 60). This stops anyone registering a public key they don't control.
3. The identity service reserves the agent's slot in the revocation status list. **If the revocation service can't be reached, registration fails**: an agent that could never be revoked is worse than a failed registration.
4. It signs the credential and returns it. An operator key with the `agents:register` scope is required.

An optional **name** (1 to 64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit) is stored beside the agent and returned. It is not in the credential, not in the DID document and not in the audit record, and it doesn't have to be unique, so commands always take the id.

## Checking a credential

`custos verify agent.json` fetches the issuer's DID document fresh and checks the credential's signature itself. The vault does the same check on every token request, against the one issuer it trusts (`VAULT_TRUSTED_ISSUER_DID`).

## Keys that must stay the same

The issuer key must survive restarts, or every credential it signed stops verifying. In development it is derived from `IDENTITY_ISSUER_SEED` (64 hex characters, no default: identity refuses to start without it). In production it can be an AWS KMS key, which can sign but never be read out. See [Keep keys in AWS KMS](/how-to/kms-keys).

Sources: ADR 0001 (credential format), ADR 0007 (agent-held keys, issuer-signed credentials), ADR 0022 (names).
