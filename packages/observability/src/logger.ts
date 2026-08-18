import pino, { type Logger, type LoggerOptions } from "pino";

const SECRET_FIELD_NAMES = [
  "token",
  "accessToken",
  "refreshToken",
  "privateKey",
  "secret",
  "secretKey",
  "apiKey",
  "password",
  "credential",
  "credentials",
];

export const redactionPaths = SECRET_FIELD_NAMES.flatMap((field) => [
  field,
  `*.${field}`,
  `*.*.${field}`,
]);

export function createLogger(
  options: LoggerOptions = {},
  destination?: pino.DestinationStream,
): Logger {
  const merged: LoggerOptions = {
    level: "info",
    ...options,
    // Re-applied after the spread so a caller-supplied `redact` can never disable it.
    redact: { paths: redactionPaths, censor: "[REDACTED]" },
  };
  return destination ? pino(merged, destination) : pino(merged);
}
