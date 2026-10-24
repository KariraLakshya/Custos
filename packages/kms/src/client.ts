import { KMSClient } from "@aws-sdk/client-kms";

/** The one method Custos uses; tests pass a stand-in (`@custos/kms/testing`). */
export type KmsClient = Pick<KMSClient, "send">;

// A signing call that hangs holds up whatever asked for the signature (a
// revocation, a status list), so a slow KMS fails within seconds instead.
const CONNECTION_TIMEOUT_MS = 2_000;
const REQUEST_TIMEOUT_MS = 5_000;
const MAX_ATTEMPTS = 2;

/**
 * A KMS client with bounded timeouts and retries (ADR 0016). Credentials and
 * region come from the deployment's standard AWS configuration
 * (`AWS_PROFILE`, `AWS_REGION`, an instance role); nothing is contacted here.
 */
export function createKmsClient(): KmsClient {
  return new KMSClient({
    maxAttempts: MAX_ATTEMPTS,
    requestHandler: {
      connectionTimeout: CONNECTION_TIMEOUT_MS,
      requestTimeout: REQUEST_TIMEOUT_MS,
    },
  });
}
