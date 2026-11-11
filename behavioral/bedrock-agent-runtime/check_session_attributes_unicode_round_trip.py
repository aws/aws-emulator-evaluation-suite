"""session-attributes-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-attributes-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode session attribute values written via UpdateSession come back
    byte-for-byte identical from GetSession (server persists the exact UTF-8
    string rather than re-encoding, truncating, or normalizing it)."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]

    def _cleanup():
        try:
            client.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            client.delete_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    unicode_values = {
        "greeting_fr": "Bonjour, ça va ? Café à emporter, s'il vous plaît.",
        "greeting_cjk": "こんにちは世界 你好世界 안녕하세요 세계",
        "emoji": "🚀🔥✅ tëst — em—dash and “curly quotes”",
        "mixed_rtl": "שלום עולם hello مرحبا بالعالم",
    }

    client.update_session(sessionIdentifier=session_id, sessionMetadata=unicode_values)

    fetched = client.get_session(sessionIdentifier=session_id)
    metadata = fetched["sessionMetadata"]

    for key, expected in unicode_values.items():
        assert key in metadata, f"key {key!r} missing from returned sessionMetadata"
        actual = metadata[key]
        assert actual == expected, (
            f"unicode round-trip mismatch for {key!r}: sent {expected!r}, got {actual!r}"
        )
        # Byte-for-byte, not just string-equal, in case of any normalization.
        assert actual.encode("utf-8") == expected.encode("utf-8"), (
            f"utf-8 byte mismatch for {key!r}: sent {expected.encode('utf-8')!r}, "
            f"got {actual.encode('utf-8')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
