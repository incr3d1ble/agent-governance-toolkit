# MCP Canonical Signing v2 (`mcp-sig-v2`) — Cross-SDK Spec

Fixes #4199. This document is the single source of truth for the canonical
string that the Python signer (`agent_os.mcp_message_signer`) and the Rust
signer (`agent-governance-rust/agentmesh-mcp`) both HMAC. If the two SDKs
ever drift apart, cross-SDK signed-envelope compatibility breaks silently —
the shared test vectors below exist to catch that.

## Why the old encoding was unsafe

Both prior encodings joined variable-length fields with a separator and no
escaping:

- Python v1/v2: `"{nonce}|{timestamp_ms}|{sender_id or ''}|{payload}"`
- Rust v1:      `"{timestamp_secs}:{nonce}:{payload}"`

Any field value containing the separator character can merge two distinct
field tuples into one identical HMAC input. Concretely (Rust, fixed
timestamp): nonce `n` + payload `x:y` and nonce `n:x` + payload `y` both
produce `{timestamp}:n:x:y`. An attacker holding a legitimately signed
envelope for the first tuple can reframe its fields to the second tuple and
retain the original signature; a verifier with an independent nonce store
accepts it. The Python pipe encoding has the same class of ambiguity.

## The v2 representation

```
canonical := "mcp-sig-v2"
           + "|" + <nonce_blen>   ":" + nonce
           + "|" + <sender_blen>  ":" + sender
           + "|" + <payload_blen> ":" + payload
           + "|" + <timestamp_ms>
```

- `<field>_blen` is the DECIMAL length of the field's UTF-8 encoding.
  Length-prefixed fields are injective without escaping: no two distinct
  tuples can produce the same canonical string.
- `sender_id=None` and `""` share the single `0:` encoding (documented
  equivalence, asserted by tests in both SDKs).
- `timestamp_ms` is millisecond Unix time, placed last; all preceding bytes
  are length-delimited, so the numeric suffix is unambiguous.
- Signature = `base64(STANDARD)` (with padding) of `HMAC-SHA256(secret,
  canonical.encode("utf-8"))`.
- Signature verification happens before the nonce store is consulted, and
  replay protection is unchanged.

## Shared fixed test vectors

Secret (UTF-8 bytes):
`mcp-sig-v2-cross-sdk-vector-key-000001`
(hex `6d63702d7369672d76322d63726f73732d73646b2d766563746f722d6b65792d303030303031`,
base64 `bWNwLXNpZy12Mi1jcm9zcy1zZGstdmVjdG9yLWtleS0wMDAwMDE=`)

Timestamp: `1700000000000` ms (whole second — float-exact through Python's
`int(timestamp.timestamp() * 1000)` path).

| ID | nonce | sender | payload | canonical | signature (base64 std) |
|----|-------|--------|---------|-----------|------------------------|
| V1 | `n` | None | `x:y` | `mcp-sig-v2\|1:n\|0:\|3:x:y\|1700000000000` | `39NyejcFc/+OwkXUgFZ1lKL/kBsw4tG78Hys703XO/o=` |
| V2 | `n:x` | None | `y` | `mcp-sig-v2\|3:n:x\|0:\|1:y\|1700000000000` | `Y8meNY8PW2b36UjsUJi0m1meP8wnyS39dNtU56a6ATo=` |
| V3 | `a\|b` | `s\|t` | `p\|q` | `mcp-sig-v2\|3:a\|b\|3:s\|t\|3:p\|q\|1700000000000` | `b65/xI6FSiAfkS3W88TjSzo9wnkSIsGhi+R1Ocezbhw=` |
| V4 | `நி` | None | `🚀 {"json":[1,2]}` | `mcp-sig-v2\|6:நி\|0:\|19:🚀 {"json":[1,2]}\|1700000000000` | `4NFaIHP94Y2o3bT+Wqk76aIf3rXZ2AxqqmVQ5I/l59g=` |
| V5 | `` (empty) | `agent-1` | `hello` | `mcp-sig-v2\|0:\|7:agent-1\|5:hello\|1700000000000` | `DTfBQSd5X5lWxpqJNTyqdfVomQOrfFOUyog8kRo5RTc=` |

V1/V2 are the reframing pair from #4199: distinct tuples, distinct
signatures, and the reframed envelope must be REJECTED on verify (regression
test in both SDKs, no legacy fallback).

## Breaking changes and coordinated migration

- Rust `McpSignedMessage`: `timestamp_secs` → `timestamp_ms` and gains
  `sender_id: Option<String>`; `McpMessageSigner::sign` takes an explicit
  `sender_id: Option<&str>`; base64 alphabet changes from URL-safe-no-pad to
  standard-with-padding.
- Python: canonical string version-tagged `mcp-sig-v2`; signatures from
  pre-v2 envelopes no longer verify (fail closed with `Invalid signature.`).
- Envelopes signed with the old encodings MUST be treated as invalid during
  migration; there is no legacy fallback. Deploy both SDKs in the same
  maintenance window.
