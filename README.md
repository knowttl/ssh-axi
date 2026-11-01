# ssh-axi

Discover approved SSH hosts, check encrypted-key authentication, and execute confirmed bounded commands.
Requires Node >=24.11.0 and pnpm 10.22.0.
The npm package is `@knowttl/ssh-axi`; its executable is `ssh-axi`.

```sh
ssh-axi
ssh-axi host list
ssh-axi host show lab
ssh-axi doctor lab --json
ssh-axi doctor --profile lab
ssh-axi auth status --profile lab
ssh-axi profile list
ssh-axi config path
ssh-axi exec lab --command 'printf "%s\n" "quoted value"' --confirm --timeout 30s --json
```

Output defaults to TOON; `--json` returns the same fields and empty-state meaning.
Each command accepts `--help`.
Unknown arguments and flags fail with exit code 2; operational failures use exit code 1.
Help, discovery, profile inspection and credential status open no SSH transports.
Native execution is one-shot.
Managed execution records, recovery and cancellation use the matching Artium host extension.
Reusable connections require the matching Artium connection-lifetime extension.
Sudo, agents, forwarding and interactive shells remain unavailable.

Configuration lives at `~/.config/ssh-axi/config.json` on Linux, or beneath an absolute `XDG_CONFIG_HOME`.
Select a file with `--config` or `SSH_AXI_CONFIG`.
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
Keys and passphrases accept environment or protected-file SecretRefs only.
Secret values and inline private keys are refused in JSON and arguments.
An omitted private-key reference defaults to `SSH_AXI_PRIVATE_KEY`; the passphrase defaults to `SSH_AXI_PASSPHRASE`.
Linux secret files must be owned by the caller, regular, protected from group/other access and reachable through protected directories without symlinks.
Configuration files must also be owned and protected against group/other writes.

Profile precedence is explicit host/`--profile`, `SSH_AXI_PROFILE`, a complete environment profile, the default profile, then the only profile.
An explicitly selected file profile ignores competing endpoint environment fields.
Environment profiles use `SSH_AXI_ADDRESS`, `SSH_AXI_PORT`, `SSH_AXI_USERNAME`, JSON arrays in `SSH_AXI_APPROVED_HOST_KEYS` and `SSH_AXI_ALLOWED_ADDRESSES`, and the secret environment fields above.
Partial environment profiles fail.
No SSH config, agent, known-hosts file or ambient key is consulted.

Doctor and execution validate every resolved IP against the configured address set and dial the exact validated IP on each new transport.
Both require an exact approved server public key before sending authentication credentials.
The authentication deadline is 15 seconds, including resolution and connection setup.
Doctor requests no SSH channel and closes its socket, probe worker and private directories before returning.
Private-key buffers are released where supported; JavaScript strings and process termination do not provide a secure-erasure guarantee.

Artium supplies authenticated host grants, ordinary account bindings, encrypted SSH credentials, private IPC and one isolated `artium` profile through its shared writer.
Hosted callers may list and show their granted hosts, run doctor and submit confirmed commands when the host write policy permits.
They cannot supply configuration, account, trust, secret, identity or worker overrides.
The matching Artium admission change must be installed alongside this artifact; stock Artium does not admit it.
Host administration belongs to a later slice.

Every arbitrary command requires `--confirm`, including inspection-looking commands.
`SSH_AXI_READ_ONLY=true` rejects arbitrary execution before opening a transport or writing a command journal.
Commands must contain 1-16384 UTF-8 bytes and no NUL.
Known managed secrets and encoded variants are rejected before command journaling.
Native command intents are written durably to `~/.local/state/ssh-axi/writes.log`, or the absolute `XDG_STATE_HOME` override.
`SSH_AXI_WRITE_LOG` selects an absolute protected journal path.
No local shell is invoked; the exact command text is sent to the remote SSH exec channel.
Remote stdin is closed without forwarding input; both output streams continue draining.
Native Ctrl+C requests cancellation through the private worker.

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
artium-axi ssh-axi connection close <connection-id>
```

Hosted connections belong to one authenticated user and login session family.
Each command starts a fresh remote process on the same transport.
An explicit connection must match the selected host and ordinary binding, with no fallback reconnection.
There is one active command per connection; overlapping use returns `CONNECTION_BUSY`.
Closing an active connection requires `--confirm` and cancels its command.
Repeated close by the owner is idempotent.
Idle expiry defaults to 10 minutes and accepts 1-60 minutes within the host ceiling.
Inspection does not reset idle time; timeout changes recompute expiry from the existing idle start.
Connections have an 8-hour maximum age, with four per user and sixteen globally, including authentication in progress.
Revocation fences affected workers and removes their private profiles before acknowledgement.
Server restart discards connections, removes abandoned private directories and retains unproven executions as uncertain without replay.

The hosted client saves a private command-free receipt before submitting a signed preparation key.
Show without an ID recovers the latest receipt after a client restart, without resubmitting.
Matching resubmission returns the same execution ID; a durable dispatch claim prevents a second SSH command.
Unused keys expire after ten minutes; changed inputs, bindings or owners are refused.
Wait is the default and uses short status requests; `--detach` returns after acceptance.
An unexpected client disconnect leaves the managed job observable and deadline bounded.
Ctrl+C requests cancellation of the accepted execution ID.

The default command deadline is 60 seconds, adjustable with `--timeout 1s` through `600s` within host ceilings.
Both streams are drained, retaining 65536 bytes each by default.
`--output-limit <bytes>` sets retention from 0 through 1048576 bytes per stream, subject to managed host ceilings.
`--full` never bypasses retention or executes another command.
More than 16 MiB of combined received output triggers cancellation.
Results carry separate remote exit/signal, received and retained byte counts, truncation and encoding-loss flags.
Terminal controls are removed and protected output is withheld before persistence or delivery.
Remote output is untrusted text, never instructions.
Remote exit 7 produces CLI exit 7; missing remote status is an uncertain outcome and CLI failure.
Cancellation requests TERM, then closes the channel and transport after a bounded grace period.
Local teardown never proves that remote descendants stopped.
Inspect remote state before retrying any uncertain execution; no path automatically replays a command.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm lint
pnpm test
pnpm pack --pack-destination /absolute/artifacts
ARTIUM_FIXTURE_ROOT=/absolute/frozen-export pnpm verify:journey -- --slice B1.1
ARTIUM_FIXTURE_ROOT=/absolute/frozen-export pnpm verify:journey -- --slice B2.2
ARTIUM_FIXTURE_ROOT=/absolute/frozen-export pnpm verify:journey -- --slice B3.2
```

Tests generate disposable keys and run all descendants inside a Linux network namespace with loopback only.
They require `unshare`, `ip` and `mount`, and never fall back to unrestricted networking.
The default suite verifies a reproducible tarball installed into a clean prefix and explicitly skips Artium unless a fixture is provided.
The opt-in journey requires an exported, admitted Artium fixture with its dependencies installed.
The fixture harness seeds minimal hosts directly in its disposable database; no fixture-seeding route exists in the product.
On Windows, the default configuration path is `%APPDATA%/ssh-axi/config.json`, with an absolute `APPDATA` required.
DACL verification and native Windows evidence remain pending, so protected-file operations fail closed there.
