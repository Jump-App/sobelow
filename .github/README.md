This is Jump's fork of [Sobelow](https://github.com/sobelow/sobelow).
Read the original [README](../README.md) for usage. This document just describes the changes
between the fork and the upstream.

## New checks

| Check | Rule id | What it reports |
| --- | --- | --- |
| `Config.TLSVerify` | `SBLW034` | Disabled TLS certificate verification: literal `verify: :verify_none` (including Gun `tls_opts` maps), hackney's `:insecure`, and WebTransport's `verify` option. Scans source files and production config, and skips `dev.exs` and `test.exs` like the other config checks. |
| `DOS.DecodeAtoms` | `SBLW036` | Dynamic input passed to a decoder with atom-creating options: Jason and Poison `keys: :atoms`, and YamlElixir string readers with `atoms: true`. |
| `DOS.Consult` | `SBLW037` | Dynamic file selection in `:file.consult/1` and `:file.path_consult/2`, which can create atoms from untrusted term files. Controller params get medium confidence, other dynamic paths low. |
| `Crypto.WeakHash` | `SBLW038` | Legacy hash algorithms (MD4, MD5, SHA-1, RIPEMD-160) in `:crypto` hash calls and `:erlang.md5/1`: medium confidence in controllers, low elsewhere. HMAC-MD5 is reported at low. Only literal algorithms are inspected, never the names of the values being hashed, so a fast hash used for password storage is not reported. |
| `Crypto.WeakCipher` | `SBLW039` | Weak ciphers passed to `:crypto` encryption APIs. DES, 3DES, RC2, RC4, Blowfish and ECB modes get high confidence. Unauthenticated AES modes (CBC, CTR, CFB, OFB) and raw ChaCha20 get low. |

## Changed behavior

### `Misc.BinToTerm`

- Calls to `:erlang.binary_to_term/2` with an explicit `:safe` option are now
  reported at **medium** confidence instead of high. This changes the outcome
  of `--exit high` for projects that relied on those findings.
- `Plug.Crypto.non_executable_binary_to_term/1,2` is now covered. It rejects
  executable terms, but is still reported at high confidence unless `:safe` is
  also passed.
- Computed options are never assumed safe.

## Merged pending upstream PRs

These upstream pull requests are still open, but their changes are already
merged into this fork. Once a PR lands upstream, remove it from this list.

| PR | What it changes |
| --- | --- |
| [#52](https://github.com/sobelow/sobelow/pull/52) | Adds the `--only` switch, which runs a chosen set of checks or categories, e.g. `mix sobelow --only XSS.Raw,SQL`. It takes the same names as `--ignore`, which still applies on top. Unknown names fail the run. `.sobelow-conf` accepts `only:`. |
| [#54](https://github.com/sobelow/sobelow/pull/54) | Adds the `DOS.DecodeAtoms` check (see [New checks](#new-checks)). |
| [#57](https://github.com/sobelow/sobelow/pull/57) | `CI.OS`, `Misc.BinToTerm` and `DOS.BinToAtom` now detect calls made through explicit Erlang imports, such as `import :os, only: [cmd: 1]` followed by `cmd(input)`. |
| [#59](https://github.com/sobelow/sobelow/pull/59) | `DOS.ListToAtom` now also reports `:erlang.list_to_atom/1`, including piped calls. |
