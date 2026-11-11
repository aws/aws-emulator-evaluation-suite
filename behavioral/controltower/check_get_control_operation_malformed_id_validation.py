"""get-control-operation-malformed-id-validation."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-control-operation-malformed-id-validation"
GROUP = "error-semantics"
SERVICES = ["controltower"]

NO_LANDING_ZONE_MESSAGE = (
    "AWS Control Tower cannot complete the operation, because you must create a landing "
    "zone first. To continue, create your landing zone from the console, or call the "
    "CreateLandingZone API."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetControlOperation rejects a 36-character non-UUID operationIdentifier with BadRequestException
    "Invalid request body", and a well-formed unknown UUID with ResourceNotFoundException and the
    "create a landing zone first" message: the pattern is checked before the lookup."""
    ct = ctx.client("controltower")

    # 36 characters (the shape's fixed length) but not hex: botocore checks only the length locally,
    # so the service itself must reject the pattern.
    malformed_but_right_length = "z" * 8 + "-" + "z" * 4 + "-" + "z" * 4 + "-" + "z" * 4 + "-" + "z" * 12
    assert len(malformed_but_right_length) == 36, "fixture bug: must match the shape's pinned length"

    malformed_code, malformed_message = _error(
        lambda: ct.get_control_operation(operationIdentifier=malformed_but_right_length)
    )
    assert malformed_code == "BadRequestException", (
        f"expected BadRequestException for malformed operationIdentifier, got {malformed_code}"
    )
    assert malformed_message == "Invalid request body", (
        f"expected 'Invalid request body' for a malformed operationIdentifier, "
        f"got {malformed_message!r}"
    )

    wellformed_missing_code, wellformed_missing_message = _error(
        lambda: ct.get_control_operation(operationIdentifier=str(uuid.uuid4()))
    )
    assert wellformed_missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but unknown operationIdentifier, "
        f"got {wellformed_missing_code}"
    )
    assert wellformed_missing_message == NO_LANDING_ZONE_MESSAGE, (
        f"expected the no-landing-zone message for a well-formed but unknown "
        f"operationIdentifier, got {wellformed_missing_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error ``(code, message)``. An unexpected SUCCESS raises. A
    ParamValidationError is never caught here: it means the request never left the SDK, and for this
    check's inputs that would mean the fixture's own length assumption is wrong."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
