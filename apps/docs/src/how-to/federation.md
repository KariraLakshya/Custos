# Trust another organisation

This guide lets **organisation B** accept agents issued by **organisation A**, with A able to revoke them even while its own services are off. Read Federation first for how the pieces fit.

## Watch it first

```bash
pnpm demo:federation
```

It starts A's identity and revocation services, B's audit service and the dashboard (ports 4001, 4003, 4004, 4005, and 4006 for the list's file host), registers two agents at A and has them call B every few seconds. Open `http://localhost:4005`: the "Across organisations" panel shows B's decisions. Press Enter to switch A off (the agents keep working), Enter again to revoke agent 1 through A's publisher (B refuses it, while agent 2 carries on), and Enter or Ctrl-C to stop. In this demo A's database stays up, because B's audit service shares it.

The same story runs as a test, with two databases and A's database refusing connections:

```bash
pnpm --filter @custos/admin test:e2e
```

## A's side: the publisher

The publisher signs A's revocation status list and writes it to a file that any static host serves. It signs **as A's revocation service**, so it uses the same key. The key comes from the environment only, never a flag:

- development: `CUSTOS_PUBLISHER_SIGNING_SEED` set to A's `REVOCATION_SIGNING_SEED`;
- production: `CUSTOS_PUBLISHER_KEY_PROVIDER=kms` and `CUSTOS_PUBLISHER_KMS_KEY_ID` set to the revocation service's KMS key ([Keep keys in AWS KMS](/how-to/kms-keys)).

Start a publisher once:

```bash
CUSTOS_PUBLISHER_SIGNING_SEED=<A's REVOCATION_SIGNING_SEED> pnpm -s custos-admin publish-status init \
  --domain <A's revocation domain> --dir ./publisher --out ./site/status.json --validity-seconds 3600 \
  --confirm-nothing-is-published
```

`--dir` holds the publisher's journal, last signed state and lock. `--out` is the file the host serves. `--confirm-nothing-is-published` states that this publisher has never published; otherwise give `--host-url` so it can check the host.

Keep the list fresh with a regular stamp, shorter than `--validity-seconds` **and** shorter than every receiver's `maxStatusAgeSeconds`. Nothing can check that for you: if the stamp is too slow, receivers refuse between stamps.

```bash
pnpm -s custos-admin publish-status run --domain <domain> --dir ./publisher --out ./site/status.json \
  --validity-seconds 3600 --stamp-seconds 600
```

(`publish-status once` signs one stamp.) To revoke an agent, preferably from its credential file:

```bash
pnpm -s custos-admin publish-status revoke --domain <domain> --dir ./publisher --out ./site/status.json \
  --validity-seconds 3600 --credential agent.json \
  --identity-did <A's identity DID> --identity-public-key <its key, from /.well-known/did.json> \
  --operator <your name> --reason <why>
```

Without the credential, use `--index <n> --confirm-index <n>`, the agent's status-list index typed twice. `publish-status show --domain <domain>` prints the publisher's DID, list address and public key, for B to pin. Every option is in the [custos-admin reference](/reference/admin-cli#publish-status).

Keep the operator machine's clock on NTP: it sets every list's signed time.

## B's side: anchor, cache and gate

B embeds `@custos/federation` in its own service. A sketch:

```ts
import {
  createForeignAgentGate,
  createInMemoryReplayGuard,
  createStatusCache,
  parseTrustAnchors,
} from "@custos/federation";

const parsed = parseTrustAnchors([
  {
    domain: "a.example",
    credentialIssuerDid: "did:web:id.a.example",
    credentialIssuerPublicKey: "z6Mk...", // from A, out of band
    statusIssuerDid: "did:web:revocation.a.example",
    statusIssuerPublicKey: "z6Mk...",
    statusListId: "https://revocation.a.example/status/revocation",
    statusFetchUrl: "https://lists.a.example/status.json",
    maxStatusAgeSeconds: 3600,
    enabled: true,
  },
]);
if (!parsed.ok) throw new Error(parsed.error.issues.join("; "));
const anchors = parsed.value;

const now = () => new Date();
const cache = createStatusCache({ anchors, pollIntervalMs: 20_000, maxClockSkewSeconds: 5, now });
await cache.start();

const gate = createForeignAgentGate({
  anchors,
  statusViewFor: (anchor) => cache.viewFor(anchor),
  audience: "https://b.example/api", // proofs must be addressed to this
  replay: createInMemoryReplayGuard(),
  now,
  maxProofSkewSeconds: 60,
  maxClockSkewSeconds: 5,
  // audit: an AuditReporter, to record decisions in B's own audit log
});

// Per request. tool and action come from B's own routing, never from the caller.
const decision = await gate.check({ credential, proof, tool: "orders", action: "read" });
if (!decision.ok) {
  // decision.error.status is 401, 403 or 503; send decision.error.code
}
```

The values above are placeholders. `statusListId` must equal both the `statusListCredential` in A's agent credentials and the list's own `id`. A's agent signs its proof with `buildForeignCallProof` from `@custos/core/possession`, addressed to B's `audience` and bound to the tool and action.

## A's own revocation service (optional)

So that a revocation made through the publisher while A was off also reaches A's own vault, A's revocation service can merge the published list. Apply migration `0009` first, then set `REVOCATION_PUBLISHED_LIST_URL`, `REVOCATION_PUBLISHED_MAX_AGE_SECONDS` and `REVOCATION_PUBLISHED_POLL_SECONDS` together (no defaults). While it is on and the newest list is too old, A's revocation service answers `503 PUBLISHED_STATE_UNKNOWN` and A's vault refuses calls.
