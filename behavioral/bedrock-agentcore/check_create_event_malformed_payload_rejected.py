"""create-event-malformed-payload-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "create-event-malformed-payload-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateEvent with a conversational payload whose role is outside the enum is rejected with
    ValidationException before the memory lookup, while a well-formed payload on the same
    nonexistent memory gets ResourceNotFoundException ('Memory not found: <memoryId>').
    """
    agentcore = ctx.client("bedrock-agentcore")
    memory_id = "sim2realmissingmem-def1234567"
    actor_id = "sim2real-actor-3"
    timestamp = datetime.now(timezone.utc)

    # `role` is an enum (ASSISTANT|USER|TOOL|OTHER); botocore's client-side validator does
    # not enforce enum membership, so this reaches the service and is rejected there.
    malformed_payload = [{"conversational": {"content": {"text": "hello"}, "role": "NOT_A_VALID_ROLE"}}]

    # Primary assertion: structurally malformed payload -> ValidationException.
    code, message = _error(
        lambda: agentcore.create_event(
            memoryId=memory_id,
            actorId=actor_id,
            eventTimestamp=timestamp,
            payload=malformed_payload,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'payload.1.member.conversational.role' failed to "
        "satisfy constraint: Member must satisfy enum value set: [USER, OTHER, TOOL, ASSISTANT]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Contrast: a well-formed payload against the same nonexistent memory reaches the
    # resource-existence check instead.
    well_formed_payload = [{"conversational": {"content": {"text": "hello"}, "role": "USER"}}]
    contrast_code, contrast_message = _error(
        lambda: agentcore.create_event(
            memoryId=memory_id,
            actorId=actor_id,
            eventTimestamp=timestamp,
            payload=well_formed_payload,
        )
    )
    assert contrast_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed payload on missing memory, got {contrast_code}"
    )
    expected_contrast = f"Memory not found: {memory_id}"
    assert contrast_message == expected_contrast, (
        f"expected message {expected_contrast!r}, got {contrast_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

