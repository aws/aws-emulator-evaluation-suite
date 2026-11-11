"""session-empty-vs-absent-attribute-preserved."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-empty-vs-absent-attribute-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSession returns an explicitly empty sessionMetadata value as "" and never invents a key that was
    not set, and UpdateSession replaces the metadata, so a key left out of a later update is gone."""
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

    # Step 1: set one explicit-empty and one non-empty key. Never touch a
    # third key at all.
    client.update_session(
        sessionIdentifier=session_id,
        sessionMetadata={"explicit_empty": "", "explicit_value": "present"},
    )
    fetched = client.get_session(sessionIdentifier=session_id)
    metadata = fetched["sessionMetadata"]

    assert "explicit_empty" in metadata, "explicitly-empty key vanished from sessionMetadata"
    assert metadata["explicit_empty"] == "", "explicit empty string was not preserved as empty"
    assert metadata["explicit_value"] == "present", (
        f"expected explicit_value='present', got {metadata.get('explicit_value')!r}"
    )
    assert "never_set_key" not in metadata, (
        "a key that was never written appeared in sessionMetadata "
        f"(full map: {metadata!r})"
    )

    # Step 2: UpdateSession replaces the whole map -- dropping
    # "explicit_value" here must remove it, proving the map isn't merged.
    client.update_session(
        sessionIdentifier=session_id,
        sessionMetadata={"explicit_empty": "still-empty-key-now-has-value"},
    )
    fetched2 = client.get_session(sessionIdentifier=session_id)
    metadata2 = fetched2["sessionMetadata"]
    assert "explicit_value" not in metadata2, (
        "sessionMetadata was merged instead of replaced: stale key survived an update "
        f"that omitted it (full map: {metadata2!r})"
    )
    assert metadata2["explicit_empty"] == "still-empty-key-now-has-value", (
        f"expected explicit_empty='still-empty-key-now-has-value', got "
        f"{metadata2.get('explicit_empty')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
