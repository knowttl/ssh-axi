export class SshError extends Error {
  constructor(readonly code: string, message: string, readonly exitCode = 1) {
    super(message)
  }
}
