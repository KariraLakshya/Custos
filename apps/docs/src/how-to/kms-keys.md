# Keep keys in AWS KMS

In development, each Custos signing key is derived from a seed in an environment variable. In production, three of them can live in **AWS KMS** instead, where the key can sign but can never be read out. Each is a **separate** key.

| Key                    | Signs                                       | Development               | KMS settings                                                   |
| ---------------------- | ------------------------------------------- | ------------------------- | -------------------------------------------------------------- |
| Identity issuer key    | Every agent credential                      | `IDENTITY_ISSUER_SEED`    | `IDENTITY_KEY_PROVIDER=kms`, `IDENTITY_ISSUER_KMS_KEY_ID`      |
| Revocation signing key | Every revocation notice and the status list | `REVOCATION_SIGNING_SEED` | `REVOCATION_KEY_PROVIDER=kms`, `REVOCATION_SIGNING_KMS_KEY_ID` |
| Audit seal key         | The audit ledger's seals                    | `AUDIT_SIGNING_SEED`      | `AUDIT_KEY_PROVIDER=kms`, `AUDIT_SIGNING_KMS_KEY_ID`           |

The vault's token key and its `VAULT_MASTER_KEY` cannot use KMS yet.

## 1. Create an Ed25519 key

```bash
aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY --description "Custos issuer key"
```

Do this once per key in the table.

## 2. Give each service only what it needs

Give the service's AWS identity `kms:GetPublicKey` and `kms:Sign` on **its own key**, and nothing else. Region and credentials come from the standard AWS configuration (`AWS_REGION`, `AWS_PROFILE`, an instance role, and so on).

## 3. Start the service on it

```bash
export IDENTITY_KEY_PROVIDER=kms
export IDENTITY_ISSUER_KMS_KEY_ID=<key id or ARN>
pnpm --filter @custos/identity start
```

The same pattern applies to revocation and audit with their own variables. Each service reads its public key at start and **refuses to start** if it can't, so a wrong key id or a missing permission shows up straight away, not at the first request. With KMS, the seed is not needed.

## Signing cost

- The audit service signs at most one seal every `AUDIT_SEAL_INTERVAL_MS` (10 seconds by default), however busy the log is. Recording an entry never calls KMS.
- The revocation service reuses a signed status list for `REVOCATION_STATUS_REUSE_MS` (5 seconds by default) while it hasn't changed, so anonymous requests can't each cost a KMS signature. A new revocation is signed straight away. Keep this well below the vault's `REVOCATION_MAX_STALENESS_MS`.

## The cross-organisation publisher

`custos-admin publish-status` signs **as the revocation service**, so it uses the **same** key. Give the operator's AWS identity `kms:GetPublicKey` and `kms:Sign` on it, then:

```bash
export CUSTOS_PUBLISHER_KEY_PROVIDER=kms
export CUSTOS_PUBLISHER_KMS_KEY_ID=<the same key id or ARN>
```

Whoever holds `kms:Sign` on that key can sign any status list for your organisation, including one that leaves out a revocation. That permission can be withdrawn in IAM and every use is logged by AWS, unlike the development seed.

## Check a key end to end

This signs with a real KMS key and verifies the signature with Custos's own code. It creates nothing:

```bash
CUSTOS_TEST_KMS_KEY_ID=<key id or ARN> pnpm --filter @custos/kms test:kms
```

## Seal copies in S3

For the audit ledger's outside copies, point `AUDIT_SEAL_STORE_URL` (on the audit service) and `CUSTOS_AUDIT_SEAL_STORE_URL` (for `custos audit-log`) at `s3://<bucket>`. The bucket needs Object Lock with a default COMPLIANCE retention, or the audit service refuses to start. The IAM policies for the audit service and for auditors are in `infra/seal-store/aws/`.

Sources: ADR 0002, ADR 0007, ADR 0016, ADR 0017.
