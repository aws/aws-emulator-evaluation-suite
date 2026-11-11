"""get-event-malformed-id-invalid-input."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-event-malformed-id-invalid-input"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEvent with an eventId that fails the `[0-9]+#[a-fA-F0-9]+` pattern returns
    ValidationException with the exact pattern message, while a well-formed eventId on the same
    nonexistent memory returns ResourceNotFoundException ('Memory not found: <memoryId>').
    """
    agentcore = ctx.client("bedrock-agentcore")
    memory_id = "sim2realmissingmem-abc1234567"
    session_id = "sim2real-session-1"
    actor_id = "sim2real-actor-1"

    malformed_event_id = "not-a-valid-event-id"
    well_formed_missing_event_id = "1700000000#abababababababab"

    # Primary assertion: malformed eventId -> ValidationException (the eventId is a URI-path
    # parameter validated against its `^[0-9]+#[a-fA-F0-9]+$` pattern before dispatch, which
    # AgentCore reports as a generic ValidationException, distinct from the service-level
    # InvalidInputException/ResourceNotFoundException classes below).
    code, message = _error(
        lambda: agentcore.get_event(
            memoryId=memory_id,
            sessionId=session_id,
            actorId=actor_id,
            eventId=malformed_event_id,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'eventId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [0-9]+#[a-fA-F0-9]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    # Contrast: a well-formed but nonexistent eventId on the same memory/session/actor
    # takes a different code path (existence lookup), proving the emulator doesn't just
    # blanket-return ValidationException for every GetEvent call.
    contrast_code, contrast_message = _error(
        lambda: agentcore.get_event(
            memoryId=memory_id,
            sessionId=session_id,
            actorId=actor_id,
            eventId=well_formed_missing_event_id,
        )
    )
    assert contrast_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed missing id, got {contrast_code}"
    )
    expected_contrast = f"Memory not found: {memory_id}"
    assert contrast_message == expected_contrast, (
        f"expected message {expected_contrast!r}, got {contrast_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises. An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses fails naming what it returned."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
