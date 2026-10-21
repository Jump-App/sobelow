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
| `Crypto.WeakRandom` | `SBLW040` | `:rand`, `:random`, `Enum.random/1`, `Enum.take_random/2` and `Enum.shuffle/1` used in a likely security context: medium when the enclosing function, assignment target or map key names a token, secret, nonce, salt, OTP, reset or session value; low for the ambiguous word "code". Other uses aren't reported. |

## Changed behavior

### `Misc.BinToTerm`

- Calls to `:erlang.binary_to_term/2` with an explicit `:safe` option are now
  reported at **medium** confidence instead of high. This changes the outcome
  of `--exit high` for projects that relied on those findings.
- `Plug.Crypto.non_executable_binary_to_term/1,2` is now covered. It rejects
  executable terms, but is still reported at high confidence unless `:safe` is
  also passed.
- Computed options are never assumed safe.
