#!/usr/bin/env node
// One-off operational step: store a real tool credential in a running
// vault, encrypted at rest (docs/adr/0004-vault-credential-encryption.md).
// Usage: node scripts/seed-credential.mjs <tool> <secret>
const [tool, secret] = process.argv.slice(2);
if (!tool || !secret) {
  console.error("usage: node scripts/seed-credential.mjs <tool> <secret>");
  process.exit(1);
}

// Storing a tool credential is an operator action (ADR 0008).
const operatorKey = process.env.CUSTOS_OPERATOR_KEY;
if (!operatorKey) {
  console.error(
    "set CUSTOS_OPERATOR_KEY to an operator key (create one with: pnpm custos-admin dev-keys)",
  );
  process.exit(1);
}

const vaultUrl = process.env.VAULT_URL ?? "http://localhost:4002";
const response = await fetch(new URL("/credentials", vaultUrl), {
  method: "POST",
  headers: { "content-type": "application/json", authorization: `Bearer ${operatorKey}` },
  body: JSON.stringify({ tool, secret }),
});
if (!response.ok) {
  console.error(`seeding failed: vault returned ${response.status}`);
  process.exit(1);
}
console.log(`stored credential for tool "${tool}"`);
