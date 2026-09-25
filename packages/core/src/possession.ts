// Light entry point, `@custos/core/possession`: what an agent-side client
// (the SDK) needs to hold its own key and prove possession of it, without
// loading the JSON-LD credential stack the main entry pulls in. Imports only
// Ed25519, multibase/did:web helpers, and the proof envelope.
export { generateKeyPair, sign } from "./crypto/ed25519.js";
export { didWebFromDomain, publicKeyToMultibase } from "./did/did-web.js";
export {
  buildRegistrationRequest,
  buildTokenRequestProof,
  issuePossessionProof,
  REGISTRATION_PROOF_TYPE,
  TOKEN_REQUEST_PROOF_TYPE,
  type PossessionProofClaims,
  type RegistrationRequest,
} from "./proof/possession.js";
