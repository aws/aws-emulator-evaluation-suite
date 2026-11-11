"""get-event-missing-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-event-missing-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEvent with a well-formed eventId on a nonexistent memory returns
    ResourceNotFoundException ('Memory not found: <memoryId>'), while a malformed eventId on the
    same memory returns ValidationException with the exact pattern message.
    """
    agentcore = ctx.client("bedrock-agentcore")
    memory_id = "sim2realmissingmem-abc7654321"
    session_id = "sim2real-session-2"
    actor_id = "sim2real-actor-2"

    well_formed_missing_event_id = "1700000001#cdcdcdcdcdcdcdcd"
    malformed_event_id = "totally not an event id!!"

    # Primary assertion: well-formed but missing eventId -> ResourceNotFoundException.
    code, message = _error(
        lambda: agentcore.get_event(
            memoryId=memory_id,
            sessionId=session_id,
            actorId=actor_id,
            eventId=well_formed_missing_event_id,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Memory not found: {memory_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Contrast: a syntactically malformed eventId on the same memory/session/actor takes
    # a different code path -- the eventId is a URI-path parameter validated against its
    # pattern before dispatch, which AgentCore reports as a generic ValidationException,
    # proving the emulator doesn't just blanket-return ResourceNotFoundException for every
    # GetEvent call.
    contrast_code, contrast_message = _error(
        lambda: agentcore.get_event(
            memoryId=memory_id,
            sessionId=session_id,
            actorId=actor_id,
            eventId=malformed_event_id,
        )
    )
    assert contrast_code == "ValidationException", (
        f"expected ValidationException for malformed id, got {contrast_code}"
    )
    expected_contrast = (
        "1 validation error detected: Value at 'eventId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [0-9]+#[a-fA-F0-9]+"
    )
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
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
