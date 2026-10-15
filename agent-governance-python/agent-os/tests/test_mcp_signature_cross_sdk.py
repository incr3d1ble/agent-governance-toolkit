"""Cross-SDK shared HMAC vectors for MCP canonical signing v2 (#4199).

The Rust SDK (``agent-governance-rust/agentmesh-mcp``) asserts the identical
vector set in ``src/mcp/signing.rs`` (``matches_python_v2_shared_vectors``).
Vectors were generated once from the shared canonical spec; if this test
fails, the two SDKs have drifted and cross-SDK signed-envelope compatibility
is broken.
"""

from __future__ import annotations

from datetime import UTC, datetime

import agent_os.mcp_message_signer as signer_module
from agent_os.mcp_message_signer import MCPMessageSigner, MCPSignedEnvelope

SECRET = b"mcp-sig-v2-cross-sdk-vector-key-000001"
TS_MS = 1_700_000_000_000
# Whole-second epoch so int(timestamp.timestamp() * 1000) is float-exact.
TS = datetime.fromtimestamp(1_700_000_000, tz=UTC)

# (nonce, sender, payload, expected base64-standard signature at TS_MS)
VECTORS = [
    ("n", None, "x:y", "39NyejcFc/+OwkXUgFZ1lKL/kBsw4tG78Hys703XO/o="),
    ("n:x", None, "y", "Y8meNY8PW2b36UjsUJi0m1meP8wnyS39dNtU56a6ATo="),
    ("a|b", "s|t", "p|q", "b65/xI6FSiAfkS3W88TjSzo9wnkSIsGhi+R1Ocezbhw="),
    ("நி", None, "🚀 {\"json\":[1,2]}", "4NFaIHP94Y2o3bT+Wqk76aIf3rXZ2AxqqmVQ5I/l59g="),
    ("", "agent-1", "hello", "DTfBQSd5X5lWxpqJNTyqdfVomQOrfFOUyog8kRo5RTc="),
]


def _signer(nonce: str) -> MCPMessageSigner:
    return MCPMessageSigner(SECRET, nonce_generator=lambda: nonce)


def _frozen_clock():
    """Pin _utcnow to the shared vector timestamp, restoring on exit."""
    original = signer_module._utcnow
    signer_module._utcnow = lambda: TS
    return original


def test_matches_shared_vectors() -> None:
    original = _frozen_clock()
    try:
        for nonce, sender, payload, expected in VECTORS:
            envelope = _signer(nonce).sign_message(payload, sender)
            assert envelope.nonce == nonce
            assert envelope.timestamp == TS
            assert envelope.signature == expected, f"vector mismatch for nonce={nonce!r}"
    finally:
        signer_module._utcnow = original


def test_reframed_envelope_is_rejected() -> None:
    """Regression for #4199: (nonce "n", payload "x:y") and
    (nonce "n:x", payload "y") must not share a signature."""
    original = _frozen_clock()
    try:
        signer = _signer("n")
        signed = signer.sign_message("x:y", None)
        assert signed.signature == VECTORS[0][3]

        reframed = MCPSignedEnvelope(
            payload="y",
            nonce="n:x",
            timestamp=signed.timestamp,
            sender_id=signed.sender_id,
            signature=signed.signature,
        )
        result = signer.verify_message(reframed)
        assert not result.is_valid
        assert result.failure_reason == "Invalid signature."
    finally:
        signer_module._utcnow = original


def test_sender_none_and_empty_share_one_encoding() -> None:
    """Documented sender semantics: ``None`` and ``""`` encode identically."""
    original = _frozen_clock()
    try:
        without = _signer("n").sign_message("payload", None)
        empty = _signer("n").sign_message("payload", "")
        assert without.signature == empty.signature
    finally:
        signer_module._utcnow = original
