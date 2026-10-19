This is Jump's fork of [Sobelow](https://github.com/sobelow/sobelow).
Read the original [README](../README.md) for usage. This document just describes the changes
between the fork and the upstream.

## New checks

| Check | Rule id | What it reports |
| --- | --- | --- |
| `Config.TLSVerify` | `SBLW034` | Disabled TLS certificate verification: literal `verify: :verify_none` (including Gun `tls_opts` maps), hackney's `:insecure`, and WebTransport's `verify` option. Scans source files and production config, and skips `dev.exs` and `test.exs` like the other config checks. |
| `DOS.DecodeAtoms` | `SBLW036` | Dynamic input passed to a decoder with atom-creating options: Jason and Poison `keys: :atoms`, and YamlElixir string readers with `atoms: true`. |
| `DOS.Consult` | `SBLW037` | Dynamic file selection in `:file.consult/1` and `:file.path_consult/2`, which can create atoms from untrusted term files. Controller params get medium confidence, other dynamic paths low. |

## Changed behavior

### `Misc.BinToTerm`

- Calls to `:erlang.binary_to_term/2` with an explicit `:safe` option are now
  reported at **medium** confidence instead of high. This changes the outcome
  of `--exit high` for projects that relied on those findings.
- `Plug.Crypto.non_executable_binary_to_term/1,2` is now covered. It rejects
  executable terms, but is still reported at high confidence unless `:safe` is
  also passed.
- Computed options are never assumed safe.
