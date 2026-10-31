import { SshError } from './errors.js'

// Share the same vocabulary at command admission, worker output and the parent
// boundary. Values never become diagnostics or persisted scanner state.
export function secretPatterns(secrets: readonly string[]): string[] {
  return [...new Set(secrets.filter(Boolean).flatMap(secret => {
    const values = [secret, ...secret.split(/\r?\n/).filter(line => line.length >= 16)]
    return values.flatMap(value => [value, JSON.stringify(value).slice(1, -1),
      encodeURIComponent(value), Buffer.from(value).toString('base64'), Buffer.from(value).toString('base64url'),
      Buffer.from(value).toString('hex'), Buffer.from(value).toString('hex').toUpperCase(),
      [...value].map(character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')])
  }))]
}

export function containsSecret(value: string, patterns: readonly string[]): boolean {
  return patterns.some(pattern => value.includes(pattern))
    || /-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:Bearer |gh[pousr]_|github_pat_)[A-Za-z0-9_./+=-]{16,}/i.test(value)
}

export function checkCommand(command: string, secrets: readonly string[]): void {
  if (command.includes('\0') || Buffer.byteLength(command) > 16 * 1024 || !command.length) {
    throw new SshError('COMMAND_INVALID', 'Commands must contain 1-16384 UTF-8 bytes and no NUL.', 2)
  }
  if (containsSecret(command, secretPatterns(secrets))) throw new SshError('SECRET_IN_COMMAND', 'Command contains protected material; nothing was journaled or dispatched.')
}

export class Output {
  private readonly decoder = new TextDecoder('utf-8')
  private tail = ''
  private text = ''
  private terminal: 'text' | 'escape' | 'csi' | 'osc' | 'oscEscape' = 'text'
  private readonly window: number
  receivedBytes = 0
  retainedBytes = 0
  truncated = false
  encodingLoss = false
  withheld = false

  constructor(private readonly patterns: readonly string[], private readonly limit: number) {
    this.window = Math.max(256, ...patterns.map(pattern => pattern.length))
  }

  push(bytes: Buffer): void {
    this.receivedBytes += bytes.length
    this.consume(this.decoder.decode(bytes, { stream: true }))
  }

  private consume(value: string): void {
    this.encodingLoss ||= value.includes('\uFFFD')
    const scan = this.tail + value
    this.withheld ||= containsSecret(scan, this.patterns)
    this.tail = scan.slice(-this.window)
    if (this.withheld) { this.text = ''; this.retainedBytes = 0; return }
    // Escape sequences can span chunks. Keep only the parser state, never an
    // unbounded pending OSC title or CSI parameter string.
    let safe = ''
    for (const character of value) {
      if (this.terminal === 'osc' || this.terminal === 'oscEscape') {
        if (character === '\x07' || character === '\x9c' || this.terminal === 'oscEscape' && character === '\\') this.terminal = 'text'
        else this.terminal = character === '\x1b' ? 'oscEscape' : 'osc'
      } else if (this.terminal === 'csi') {
        if (character >= '@' && character <= '~') this.terminal = 'text'
      } else if (this.terminal === 'escape') {
        this.terminal = character === '[' ? 'csi' : character === ']' ? 'osc' : 'text'
      } else if (character === '\x1b') this.terminal = 'escape'
      else if (character === '\x9b') this.terminal = 'csi'
      else if (character === '\x9d') this.terminal = 'osc'
      else if (!/[\x00-\x08\x0b-\x1f\x7f-\x9f]/.test(character)) safe += character
    }
    const bytes = Buffer.from(safe)
    const remaining = this.limit - this.retainedBytes
    let retained = bytes.subarray(0, remaining).toString('utf8')
    // Do not introduce a replacement character by splitting a retained codepoint.
    if (bytes.length > remaining) retained = retained.replace(/\uFFFD$/, '')
    this.text += retained
    this.retainedBytes += Buffer.byteLength(retained)
    this.truncated ||= bytes.length > remaining
  }

  finish() {
    this.consume(this.decoder.decode())
    return { text: this.withheld ? '' : this.text, receivedBytes: this.receivedBytes,
      retainedBytes: this.retainedBytes, truncated: this.truncated, encodingLoss: this.encodingLoss,
      withheld: this.withheld, unit: 'bytes' as const }
  }
}
