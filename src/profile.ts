import { readFileSync, lstatSync, openSync, fstatSync, closeSync, constants } from 'node:fs'
import { dirname, isAbsolute, join, parse, resolve } from 'node:path'
import { homedir } from 'node:os'
import { isIP } from 'node:net'
import { Ajv } from 'ajv'
import schema from '../axi-credential.schema.json' with { type: 'json' }
import { SshError } from './errors.js'

export type SecretRef = { env: string } | { file: string }
export interface Profile {
  address: string
  port: number
  username: string
  approvedHostKeys: string[]
  allowedAddresses: string[]
  privateKey?: SecretRef
  passphrase?: SecretRef
}
export interface Configuration { version: 1, defaultProfile?: string, profiles: Record<string, Profile> }
const validate = new Ajv({ strict: false }).compile<Profile>(schema)
const profileName = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/

export function validateProfile(value: unknown): Profile {
  if (!validate(value) || value.allowedAddresses.some(address => !isIP(address))) {
    throw new SshError('CONFIG_INVALID', 'Invalid SSH profile; use the packaged credential schema. Secret fields require env or file references.')
  }
  return value
}

export function configPath(explicit?: string): string {
  if (explicit || process.env.SSH_AXI_CONFIG) return resolve(explicit ?? process.env.SSH_AXI_CONFIG!)
  const base = process.platform === 'win32'
    ? process.env.APPDATA
    : process.env.XDG_CONFIG_HOME && isAbsolute(process.env.XDG_CONFIG_HOME) ? process.env.XDG_CONFIG_HOME : join(homedir(), '.config')
  if (!base || !isAbsolute(base)) throw new SshError('CONFIG_INVALID', 'An absolute configuration directory is required.')
  return join(base, 'ssh-axi', 'config.json')
}

export function openPrivateFile(file: string, secret: boolean): number {
  if (!isAbsolute(file)) throw new SshError('CONFIG_INSECURE', 'Private file paths must be absolute.')
  // Until native DACL verification is available, Windows custody fails closed.
  if (process.platform === 'win32') throw new SshError('PLATFORM_PENDING', 'Native Windows file custody validation is pending.')
  let parent = dirname(file)
  while (parent !== parse(parent).root) {
    const info = lstatSync(parent)
    if (!info.isDirectory() || info.isSymbolicLink() || (info.uid !== process.getuid!() && info.uid !== 0)
      || ((info.mode & 0o022) !== 0 && !(info.uid === 0 && (info.mode & 0o1000) !== 0))) {
      throw new SshError('CONFIG_INSECURE', `Private file parent ${JSON.stringify(parent)} must be an actual directory owned by this user or root and protected against replacement. Remove group write access with chmod g-w (and other write access with chmod o-w), or select a protected location.`)
    }
    parent = dirname(parent)
  }
  const descriptor = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const info = fstatSync(descriptor)
    if (!info.isFile() || info.uid !== process.getuid!() || (info.mode & (secret ? 0o077 : 0o022)) !== 0) {
      throw new SshError('CONFIG_INSECURE', 'Private files must be regular, owned by this user and protected.')
    }
    return descriptor
  } catch (error) {
    closeSync(descriptor)
    throw error
  }
}

export function readPrivateFile(file: string, secret: boolean): string {
  const descriptor = openPrivateFile(file, secret)
  try {
    return readFileSync(descriptor, 'utf8').replace(/^\uFEFF/, '').trimEnd()
  } finally { closeSync(descriptor) }
}

export function loadConfiguration(file: string): Configuration {
  let value: unknown
  try { value = JSON.parse(readPrivateFile(file, false)) }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, profiles: {} }
    if (error instanceof SshError) throw error
    throw new SshError('CONFIG_INVALID', 'Cannot read the protected SSH configuration.')
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new SshError('CONFIG_INVALID', 'Invalid configuration object.')
  const config = value as Record<string, unknown>
  if (Object.keys(config).some(key => !['version', 'defaultProfile', 'profiles'].includes(key)) || config.version !== 1
    || !config.profiles || typeof config.profiles !== 'object' || Array.isArray(config.profiles)) {
    throw new SshError('CONFIG_INVALID', 'Expected configuration version 1 with named profiles.')
  }
  for (const [name, profile] of Object.entries(config.profiles)) {
    if (!profileName.test(name)) throw new SshError('CONFIG_INVALID', 'Invalid profile name.')
    validateProfile(profile)
  }
  if (config.defaultProfile !== undefined && (typeof config.defaultProfile !== 'string'
    || !Object.hasOwn(config.profiles, config.defaultProfile))) throw new SshError('CONFIG_INVALID', 'Default profile does not exist.')
  return config as unknown as Configuration
}

export function selectProfile(config: Configuration, explicit?: string): { name: string, profile: Profile } {
  const name = explicit ?? process.env.SSH_AXI_PROFILE
  if (name) {
    const profile = Object.hasOwn(config.profiles, name) ? config.profiles[name] : undefined
    if (!profile) throw new SshError('NOT_FOUND', 'Host not found.')
    return { name, profile }
  }
  const fields = ['ADDRESS', 'PORT', 'USERNAME', 'APPROVED_HOST_KEYS', 'ALLOWED_ADDRESSES', 'PRIVATE_KEY', 'PASSPHRASE']
  if (fields.some(field => process.env[`SSH_AXI_${field}`] !== undefined)) {
    let value: unknown
    try {
      value = { address: process.env.SSH_AXI_ADDRESS, port: Number(process.env.SSH_AXI_PORT), username: process.env.SSH_AXI_USERNAME,
        approvedHostKeys: JSON.parse(process.env.SSH_AXI_APPROVED_HOST_KEYS ?? 'null'),
        allowedAddresses: JSON.parse(process.env.SSH_AXI_ALLOWED_ADDRESSES ?? 'null'), privateKey: { env: 'SSH_AXI_PRIVATE_KEY' },
        ...(process.env.SSH_AXI_PASSPHRASE === undefined ? {} : { passphrase: { env: 'SSH_AXI_PASSPHRASE' } }) }
    } catch { throw new SshError('CONFIG_INVALID', 'A complete environment profile is required.') }
    return { name: 'env', profile: validateProfile(value) }
  }
  const selected = config.defaultProfile ?? (Object.keys(config.profiles).length === 1 ? Object.keys(config.profiles)[0] : undefined)
  if (!selected) throw new SshError('PROFILE_REQUIRED', 'Select a configured host with --profile <name>.')
  return { name: selected, profile: config.profiles[selected]! }
}

export function resolveSecret(reference: SecretRef | undefined, fallback: string, required: boolean): string | undefined {
  const selected = reference ?? { env: fallback }
  let value: string | undefined
  try { value = 'env' in selected ? process.env[selected.env] : readPrivateFile(selected.file, true) }
  catch (error) {
    if (error instanceof SshError) throw error
    throw new SshError('KEY_UNAVAILABLE', 'The selected protected secret file is unavailable.')
  }
  if (!value && required) throw new SshError('KEY_UNAVAILABLE', 'The selected private key is unavailable.')
  return value
}
