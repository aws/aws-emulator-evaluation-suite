"""create-session-invalid-encryption-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-session-invalid-encryption-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateSession with a malformed encryptionKeyArn is rejected with ValidationException and creates nothing."""
    client = ctx.client("bedrock-agent-runtime")

    # Break exactly one thing: encryptionKeyArn does not match the required KMS ARN pattern.
    try:
        client.create_session(encryptionKeyArn="not-a-valid-kms-arn")
        raise AssertionError("expected malformed encryptionKeyArn to be rejected")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ValidationException", f"expected ValidationException, got {code!r}"
        expected_message = (
            "1 validation error detected: Value 'not-a-valid-kms-arn' at 'encryptionKeyArn' "
            "failed to satisfy constraint: Member must satisfy regular expression pattern: "
            "arn:aws(|-cn|-us-gov|-iso|-iso-b|-iso-f):kms:[a-zA-Z0-9-]*:[0-9]{12}:key/[a-zA-Z0-9-]{36}"
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control (same file): a normal CreateSession call, with no encryptionKeyArn,
    # succeeds and produces an ACTIVE session -- the validation failure above did not
    # leave the service unable to create sessions at all.
    created = client.create_session()
    session_id = created["sessionId"]

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

    assert created["sessionStatus"] == "ACTIVE"

    # Independent read at the destination, through a different operation than the one
    # that mutated: GetSession must agree the session it created is really there and ACTIVE.
    fetched = client.get_session(sessionIdentifier=session_id)
    assert fetched["sessionId"] == session_id
    assert fetched["sessionStatus"] == "ACTIVE", (
        f"expected GetSession to independently confirm ACTIVE, got {fetched['sessionStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
