# Glossary

Each term is explained once here; the other pages link back.

**Agent.** A program that acts on someone's behalf and calls tools. In Custos an agent is registered once and then identified by its id or DID.

**Tool.** An outside service an agent calls through Custos, such as Stripe, or the built-in stand-ins `mock-database` and `mock-slack`. Each tool has a **connector** (an adapter) inside the vault.

**Action.** One operation on a tool, such as `query` on `mock-database` or `list-customers` on `stripe`.

**Operator.** The person, or the script, that runs Custos: registers agents, grants tools, revokes agents. Operators authenticate with an **operator key** or by signing in with SSO.

**DID (decentralised identifier).** A URI that names something and says how to find its public key. Custos uses **`did:web`**, where the key is published as a JSON file on a web address: `did:web:localhost%3A4001:agents:<id>` means "the document at `http://localhost:4001/agents/<id>/did.json`". `%3A` is an encoded `:` before the port.

**DID document.** The JSON file a `did:web` DID points to. It lists the public key that verifies what the DID's owner signs. Each Custos service publishes its own at `/.well-known/did.json`.

**Verifiable credential (VC).** A signed statement in the W3C Verifiable Credentials 2.0 format. An agent's credential says "agent X holds public key K", signed by the identity service. The file `custos register` writes, `agent.json`, is one.

**Issuer.** Whoever signs a credential. For agent credentials that is your identity service.

**Ed25519.** The signature algorithm every Custos key uses. Signing and checking take microseconds.

**Proof of possession.** A fresh signature, made with the agent's private key, that shows the caller holds the key named in the credential. A copied `agent.json` without the key is useless. See [Proof of possession](/concepts/proof-of-possession).

**Scoped token.** The short-lived pass (60 seconds) the vault issues for one agent, one tool and one action. See [Scoped tokens](/concepts/scoped-tokens).

**Grant.** An operator's permission for one agent to use one tool. Without a grant every call is refused ("deny by default").

**Revocation.** Cutting an agent off from every tool, permanently. See [Revocation](/concepts/revocation).

**Tombstone.** The signed notice "agent X is revoked" that the revocation service pushes to every vault.

**Status list.** A signed list with one bit per agent, set when the agent is revoked (W3C Bitstring Status List). The durable, public record of who is revoked.

**Fail closed.** When Custos cannot be sure an answer is safe (a service is down, a list is too old), it refuses. It never allows on a guess.

**Bounded staleness.** The explicit limit on how out of date a local copy may be before Custos stops trusting it. For the vault's revocation view the default is 30 seconds.

**Audit ledger.** The audit log, kept as a hash chain: each entry includes the hash of the one before, so an edit anywhere breaks every later link. See [The audit ledger](/concepts/audit-ledger).

**Seal.** A signature over the newest entry of the ledger, made every 10 seconds when the log has moved. A seal vouches for every entry up to it.

**Seal store.** A separate place every seal is copied to, which the audit service can add to but not change: a separate Postgres server in development, an S3 bucket with Object Lock in production.

**Hand-off.** A signed note in which one agent passes some of its access to another. A chain of hand-offs is a **delegation**. See [Delegation](/concepts/delegation).

**Federation.** One organisation accepting agents another organisation issued. See [Federation](/concepts/federation).

**Trust anchor.** The public keys and list address that organisation B writes down once for organisation A, out of band, so B can check A's agents without calling A.

**Publisher.** The program (`custos-admin publish-status`) that signs organisation A's status list and writes it to a static host, so other organisations can read it while A's services are off.

**API key.** A secret of the form `custos_<kind>_<id>_<secret>`. **Operator keys** are for people and scripts; **service keys** are for Custos services calling each other. Each key has **scopes**, such as `agents:register`, that say what it may do.

**mTLS (mutual TLS).** Both ends of a connection show a certificate. Custos services can use certificates instead of service keys, through an Envoy proxy.

**SSO (single sign-on).** Signing in with a company account through an OpenID Connect provider. `custos login` uses it.

**KMS (key management service).** A cloud service that holds a private key and signs with it, but never lets anyone read the key. Custos can use AWS KMS.

**Hot path and cold path.** The hot path runs on every tool call and must be fast; the cold path (issuing, granting, revoking, writing audit) can be slower. See [Architecture](/concepts/architecture).

**Control plane.** The administrative side of Custos: registering, granting, revoking, storing tool passwords.
