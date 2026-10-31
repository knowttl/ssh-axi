# ssh-axi

Discover approved SSH hosts and check encrypted-key authentication without executing a remote command.
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
```

Output defaults to TOON; `--json` returns the same fields and empty-state meaning.
Each command accepts `--help`.
Unknown arguments and flags fail with exit code 2; operational failures use exit code 1.
Help, discovery, profile inspection and credential status open no SSH transports.
There are no login, command-execution, sudo, agent, forwarding or interactive-shell commands in this slice.

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

Doctor validates every resolved IP against the configured address set and dials the exact validated IP on each new transport.
It requires an exact approved server public key before sending authentication credentials.
The authentication deadline is 15 seconds, including resolution and connection setup.
Doctor requests no SSH channel and closes its socket, probe worker and private directories before returning.
Private-key buffers are released where supported; JavaScript strings and process termination do not provide a secure-erasure guarantee.

Artium supplies authenticated host grants, ordinary account bindings, encrypted SSH credentials, private IPC and one isolated `artium` profile through its shared writer.
Hosted callers may list and show their granted hosts and run doctor.
They cannot supply configuration, account, trust, secret, identity or worker overrides.
The matching Artium admission change must be installed alongside this artifact; stock Artium does not admit it.
Host administration and reusable connections belong to later slices.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm lint
pnpm test
pnpm pack --pack-destination /absolute/artifacts
ARTIUM_FIXTURE_ROOT=/absolute/frozen-export pnpm verify:journey -- --slice B1.1
```

Tests generate disposable keys and run all descendants inside a Linux network namespace with loopback only.
They require `unshare`, `ip` and `mount`, and never fall back to unrestricted networking.
The default suite verifies a reproducible tarball installed into a clean prefix and explicitly skips Artium unless a fixture is provided.
The opt-in journey requires an exported, admitted Artium fixture with its dependencies installed.
The fixture harness seeds minimal hosts directly in its disposable database; no fixture-seeding route exists in the product.
On Windows, the default configuration path is `%APPDATA%/ssh-axi/config.json`, with an absolute `APPDATA` required.
DACL verification and native Windows evidence remain pending, so protected-file operations fail closed there.
