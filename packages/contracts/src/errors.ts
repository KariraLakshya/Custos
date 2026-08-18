export const ErrorCode = {
  UNKNOWN: "UNKNOWN",
  INVALID_INPUT: "INVALID_INPUT",
  CONFIGURATION_INVALID: "CONFIGURATION_INVALID",
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export class CustosError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.code = code;
    this.name = "CustosError";
  }
}
