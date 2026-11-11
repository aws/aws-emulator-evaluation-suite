"""list-enabled-controls-target-filter-validation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-enabled-controls-target-filter-validation"
GROUP = "error-semantics"
SERVICES = ["controltower"]

NO_LANDING_ZONE_MESSAGE = (
    "AWS Control Tower cannot complete the operation, because you must create a landing "
    "zone first. To continue, create your landing zone from the console, or call the "
    "CreateLandingZone API."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEnabledControls rejects a malformed targetIdentifier with BadRequestException "Invalid request
    body", and a well-formed unknown target ARN with ResourceNotFoundException and the "create a landing
    zone first" message: the pattern is checked before the lookup."""
    ct = ctx.client("controltower")

    # targetIdentifier has a botocore-modelled min length of 20: a shorter string never
    # leaves the SDK (ParamValidationError), so this must be long enough to reach the
    # service and exercise ITS pattern check, not botocore's local length check.
    # Confirmed against real AWS: the service's own format rejection is
    # BadRequestException, not ValidationException.
    malformed_code, malformed_message = _error(
        lambda: ct.list_enabled_controls(targetIdentifier="not-an-arn-but-long-enough-to-clear-the-sdk-length-check")
    )
    assert malformed_code == "BadRequestException", (
        f"expected BadRequestException for a malformed targetIdentifier, got {malformed_code}"
    )
    assert malformed_message == "Invalid request body", (
        f"expected 'Invalid request body' for a malformed targetIdentifier, "
        f"got {malformed_message!r}"
    )

    fake_ou_arn = (
        f"arn:aws:organizations::{_account_id(ctx)}:ou/o-aaaaaaaaaa/ou-aaaa-aaaaaaaa"
    )
    wellformed_missing_code, wellformed_missing_message = _error(
        lambda: ct.list_enabled_controls(targetIdentifier=fake_ou_arn)
    )
    assert wellformed_missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent target, "
        f"got {wellformed_missing_code}"
    )
    assert wellformed_missing_message == NO_LANDING_ZONE_MESSAGE, (
        f"expected the no-landing-zone message for a well-formed but nonexistent target, "
        f"got {wellformed_missing_message!r}"
    )


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
