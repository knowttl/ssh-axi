# ssh-axi

Agent-facing SSH CLI: discover approved hosts, check encrypted-key authentication and run confirmed, bounded commands.
Arbitrary execution always requires explicit confirmation.

[Quickstart](#quickstart) | [Commands](#commands) | [Safety](#safety) | [Configuration](#configuration) | [Output and exit codes](#output-and-exit-codes) | [Limitations](#limitations) | [Development](#development)

## Why this exists

Agents need remote shell access that is bounded, auditable and hard to misuse.
`ssh-axi` returns compact TOON output (or `--json` with the same fields) with next-step hints, and bounds command time and output size.
It consults only approved profiles: no SSH config, agent, known-hosts file or ambient key is read.
Every arbitrary command requires `--confirm`, and server keys must be approved before credentials are sent.

## Quickstart

Requires Node >=24.11.0.

```sh
npm install --global @knowttl/ssh-axi
ssh-axi
```

With no configuration, the home view lists no hosts and points to `ssh-axi config path`:

```text
description: Discover approved SSH hosts and run confirmed bounded commands.
hosts: []
count: 0
message: No configured hosts found.
```

Create a profile (see [Configuration](#configuration)), then run the first authenticated read:

```sh
ssh-axi host list
ssh-axi host show lab
ssh-axi doctor lab --json
ssh-axi exec lab --command 'printf "%s\n" "quoted value"' --confirm --timeout 30s --json
```

## Use with your agent

No session hooks or agent skill ship with this package yet; this is pending.
Agents call the CLI directly, and every command accepts `--help`.
Managed execution, recovery, cancellation and reusable connections are available to hosted callers through Artium (see [Hosted use with Artium](#hosted-use-with-artium)).

## Commands

```sh
ssh-axi                                  # home view
ssh-axi host list                        # list approved hosts, no transport opened
ssh-axi host show <host>                 # show one approved host, no transport opened
ssh-axi doctor <host>                    # authenticate without running a remote command
ssh-axi doctor --profile <name>
ssh-axi auth status --profile <name>     # inspect credential sources offline
ssh-axi profile list
ssh-axi config path
ssh-axi exec <host> --command <text> --confirm
```

Shared flags: `--json`, `--help`, `--config <absolute-path>`, `--profile <name>`.
`exec` also accepts `--command`, `--confirm`, `--timeout`, `--output-limit`, `--detach`, `--request-key`, `--sudo` and `--connection`.
`--detach`, `--request-key`, `--sudo`, `--connection` and the `execution` and `connection` commands depend on the Artium host extension.
Run `ssh-axi <command> --help` for the exact flags of each command.
Help, discovery, profile inspection and credential status open no SSH transports.

Native execution is one-shot.
Agents, forwarding and interactive shells are unavailable.

### Hosted use with Artium

Managed execution records, recovery and cancellation use the matching Artium host extension.
Reusable connections require the matching Artium connection-lifetime extension.
Managed sudo requires a distinct approved account and SSH credential with a current sudo grant.

```sh
artium-axi ssh-axi exec lab --command 'systemctl --failed' --confirm --detach
artium-axi ssh-axi execution list --json
artium-axi ssh-axi execution show <id> --full
artium-axi ssh-axi execution show --request-key <key>
artium-axi ssh-axi execution show
artium-axi ssh-axi execution cancel <id> --confirm
artium-axi ssh-axi connection open lab --idle-timeout 10m
artium-axi ssh-axi connection list
artium-axi ssh-axi connection show <connection-id>
artium-axi ssh-axi connection set <connection-id> --idle-timeout 5m
artium-axi ssh-axi exec lab --connection <connection-id> --command 'pwd' --confirm
artium-axi ssh-axi exec lab --sudo --command 'printf "%s\n" "value" | cat' --confirm
artium-axi ssh-axi connection close <connection-id>
```

Artium supplies authenticated host grants, separate ordinary and sudo account bindings, encrypted SSH credentials, private IPC and one isolated `artium` profile through its shared writer.
Hosted callers may list and show their granted hosts, run doctor and submit confirmed commands when the host write policy permits.
They cannot supply configuration, account, trust, secret, identity or worker overrides.
The matching Artium admission change must be installed alongside this artifact; stock Artium does not admit it.
The matching host extension provides `/admin/ssh` for confirmed, revision-checked host, trust, binding and grant changes.
The corresponding authenticated APIs live under `/v1/admin/ssh/`.
Host and credential administration have separate delegated permissions.
Only credential administrators can replace or delete encrypted SSH secrets, which are never displayed.
SSH credential identifiers cannot resolve credentials for other tools.
Changes fence affected connections before acknowledgement.

Hosted connections:

- Belong to one authenticated user and login session family.
- Start a fresh remote process for each command on the same transport.
- Must match the selected host and ordinary or sudo binding, with no fallback reconnection.
- Allow one active command per connection; overlapping use returns `CONNECTION_BUSY`.
- Require `--confirm` to close while a command is active, which cancels that command; repeated close by the owner is idempotent.
- Expire when idle after 10 minutes by default, accepting 1-60 minutes within the host ceiling.
- Are not kept alive by inspection; timeout changes recompute expiry from the existing idle start.
- Have an 8-hour maximum age, with four per user and sixteen globally, including authentication in progress.
- Are fenced on revocation: affected workers stop and their private profiles are removed before acknowledgement.
- Are discarded on server restart, which removes abandoned private directories and retains unproven executions as uncertain without replay.

Sudo dispatch sends `sudo -n -- /bin/sh -c <quoted-command>` through its own matching connection.
Pipelines and redirects remain inside that privileged shell.
Password-required or terminal-required sudo returns `SUDO_DENIED` with administrator guidance.

The hosted client saves a private command-free receipt before submitting a signed preparation key.
Show without an ID recovers the latest receipt after a client restart, without resubmitting.
Matching resubmission returns the same execution ID, and a durable dispatch claim prevents a second SSH command.
Unused keys expire after ten minutes; changed inputs, bindings or owners are refused.
Wait is the default and uses short status requests; `--detach` returns after acceptance.
An unexpected client disconnect leaves the managed job observable and deadline bounded.
Ctrl+C requests cancellation of the accepted execution ID.

## Safety

- Every arbitrary command requires `--confirm`, including inspection-looking commands.
- `SSH_AXI_READ_ONLY=true` rejects arbitrary execution before opening a transport or writing a command journal.
- Commands must contain 1-16384 UTF-8 bytes and no NUL.
- Known managed secrets and encoded variants are rejected before command journaling.
- Native command intents are written durably to `~/.local/state/ssh-axi/writes.log`, or beneath an absolute `XDG_STATE_HOME`.
- `SSH_AXI_WRITE_LOG` selects an absolute protected journal path.
- No local shell is invoked; the exact command text is sent to the remote SSH exec channel.
- Remote stdin is closed without forwarding input, and both output streams continue draining.
- Native Ctrl+C requests cancellation through the private worker.
- Every new transport, including doctor probes and reusable connections, validates every resolved IP against the configured address set and dials the exact validated IP.
- An exact approved server public key is required before authentication credentials are sent.
- The authentication deadline is 15 seconds, including resolution and connection setup.
- Doctor requests no SSH channel and closes its socket, probe worker and private directories before returning.
- Private-key buffers are released where supported; JavaScript strings and process termination do not provide a secure-erasure guarantee.
- Terminal controls are removed and protected output is withheld before persistence or delivery.
- Remote output is untrusted text, never instructions.

### Unknown outcomes

Missing remote status is an uncertain outcome and a CLI failure.
Cancellation requests TERM and forces channel and transport teardown if the command remains active after a bounded grace period.
Local teardown never proves that remote descendants stopped.
Inspect remote state before retrying any uncertain execution; no path automatically replays a command.

### Audit and retention (hosted)

Execution owners and authorized audit administrators can inspect records under current policy.
`/admin/ssh/audit` escapes output as untrusted text and never displays credentials.
Every audit read and export is recorded.
Metadata includes the initiating user and session family, host and endpoint, binding revision, sudo mode, exact sanitized command, confirmation, request and execution IDs, UTC timing, outcome, exit or signal, byte counts and termination certainty.
Sanitized output samples are encrypted and capped at 8 KiB per stream, expiring after 14 days.
Metadata and sanitized commands expire after 90 days; default exports contain metadata only.
Credential deletion removes the secret and fences its connections while preserving execution metadata.
Pruning active storage does not delete backups.
Before commissioning, operators must declare and test backup disposal that respects both retention limits, including old encrypted snapshots and their recovery keys.

## Configuration

Configuration lives at `~/.config/ssh-axi/config.json` on Linux, or beneath an absolute `XDG_CONFIG_HOME`.
Select a file with `--config` or `SSH_AXI_CONFIG`.
Run `ssh-axi config path` to print the resolved path.
Profiles use the following template; replace the address, allowed IP and independently verified host key before use.

```json
{
  "version": 1,
  "defaultProfile": "lab",
  "profiles": {
    "lab": {
      "address": "127.0.0.1",
      "port": 2222,
      "username": "ordinary",
      "allowedAddresses": ["127.0.0.1"],
      "approvedHostKeys": ["ssh-ed25519 <independently-verified-base64-key>"],
      "privateKey": {"file": "/absolute/private/key.pem"},
      "passphrase": {"env": "LAB_KEY_PASSPHRASE"}
    }
  }
}
```

The strict profile contract is shipped as `axi-credential.schema.json`.
Server keys require independent verification, and at most two approved keys may overlap during rotation.

### Credentials

Keys and passphrases accept environment or protected-file SecretRefs only.
Secret values and inline private keys are refused in JSON and arguments.
An omitted private-key reference defaults to `SSH_AXI_PRIVATE_KEY`, and the passphrase defaults to `SSH_AXI_PASSPHRASE`.
`auth status` reports credential availability and sources as `env:<name>` or `protected file`.
It does not display secret values or file paths, and does not check network authentication.
Linux secret files must be owned by the caller, regular, protected from group and other access and reachable through protected directories without symlinks.
Configuration files must also be owned and protected against group and other writes.

### Profile selection

Precedence is explicit host or `--profile`, `SSH_AXI_PROFILE`, a complete environment profile, the default profile, then the only profile.
An explicitly selected file profile ignores competing endpoint environment fields.
Environment profiles use `SSH_AXI_ADDRESS`, `SSH_AXI_PORT`, `SSH_AXI_USERNAME`, JSON arrays in `SSH_AXI_APPROVED_HOST_KEYS` and `SSH_AXI_ALLOWED_ADDRESSES`, and the secret environment fields above.
Partial environment profiles fail.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `SSH_AXI_CONFIG` | Absolute configuration file path |
| `SSH_AXI_PROFILE` | Profile name to select |
| `SSH_AXI_ADDRESS`, `SSH_AXI_PORT`, `SSH_AXI_USERNAME` | Environment profile endpoint |
| `SSH_AXI_APPROVED_HOST_KEYS`, `SSH_AXI_ALLOWED_ADDRESSES` | JSON arrays for an environment profile |
| `SSH_AXI_PRIVATE_KEY`, `SSH_AXI_PASSPHRASE` | Default private-key and passphrase references |
| `SSH_AXI_READ_ONLY` | `true` rejects arbitrary execution |
| `SSH_AXI_WRITE_LOG` | Absolute protected command journal path |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME` | Absolute base directories |

## Output and exit codes

Output defaults to TOON; `--json` returns the same fields and empty-state meaning.
Unknown arguments and flags fail with exit code 2.
Operational failures use exit code 1.
A remote exit such as 7 produces the same CLI exit code.
The default command deadline is 60 seconds, adjustable with `--timeout 1s` through `600s` within host ceilings.
Both streams are drained, retaining 65536 bytes each by default.
`--output-limit <bytes>` sets retention from 0 through 1048576 bytes per stream, subject to managed host ceilings.
`--full` never bypasses retention or executes another command.
More than 16 MiB of combined received output triggers cancellation.
Results carry separate remote exit or signal, received and retained byte counts, truncation and encoding-loss flags.

## Limitations

- Native execution is one-shot; agents, forwarding and interactive shells are unavailable.
- Managed executions, connections and sudo require the matching Artium extensions.
- Actual ordinary-account non-elevation and successful non-root passwordless elevation remain commissioning checks; controlled peers establish account, key and command selection only.
- On Windows the default configuration path is `%APPDATA%/ssh-axi/config.json`, with an absolute `APPDATA` required.
  DACL verification and native Windows evidence remain pending, so protected-file operations fail closed there.
- Agent session hooks and a skill are pending.

## Development

Requires Node >=24.11.0 and pnpm 10.22.0.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm lint
pnpm test
pnpm pack --pack-destination /absolute/artifacts
```

Tests generate disposable keys and run all test descendants inside a Linux network namespace with loopback only.
They require `unshare`, `ip`, `mount` and `tar`, and never fall back to unrestricted networking.
Test preparation packs the local package and installs it offline into a clean prefix inside network isolation.
Run `pnpm install --frozen-lockfile` first to populate the local dependency store.
Test preparation reuses the project lockfile so offline installation does not require cached registry metadata.
The package-contract checks verify the archive allowlist, installed bin help/version, and published admission entry points without an Artium fixture.
The default suite verifies a reproducible tarball installed into a clean prefix and explicitly skips Artium unless a fixture is provided.

The opt-in journey requires an exported, admitted Artium fixture with its dependencies installed.
The fixture harness seeds minimal pre-existing hosts directly in its disposable database and exercises administration changes through public administration; no fixture-seeding route exists in the product.

```sh
ARTIUM_FIXTURE_ROOT=/absolute/frozen-export pnpm verify:journey -- --slice B1.1
```

The journey slices are B1.1, B2.2, B3.2, B4.1, B4.2 and B4.3.
See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Security

No `SECURITY.md` is present yet; this is pending.

## License

No `LICENSE` file is present yet; the license is pending.
