"""disable-control-missing-identifiers-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disable-control-missing-identifiers-rejected"
GROUP = "overly-permissive"
SERVICES = ["controltower"]

NO_LANDING_ZONE_MESSAGE = (
    "AWS Control Tower cannot complete the operation, because you must create a landing "
    "zone first. To continue, create your landing zone from the console, or call the "
    "CreateLandingZone API."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "identity:standalone", "phase:standalone", "plane:control")
def run(ctx) -> None:
    """With no landing zone, DisableControl with no identifiers or a well-formed unknown enabled-control ARN
    fails with ResourceNotFoundException and the "create a landing zone first" message, while a non-ARN
    enabledControlIdentifier fails earlier with BadRequestException "Invalid request body"."""
    ct = ctx.client("controltower")

    missing_code, missing_message = _error(lambda: ct.disable_control())
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException when no identifiers are supplied, got {missing_code}"
    )
    assert missing_message == NO_LANDING_ZONE_MESSAGE, (
        f"expected the no-landing-zone message when no identifiers are supplied, "
        f"got {missing_message!r}"
    )

    # 20+ chars so botocore's own min-length check (Arn shape, min 20) lets this
    # through the SDK -- a shorter string never leaves the client and would only
    # be testing botocore, not the service.
    malformed_code, malformed_message = _error(
        lambda: ct.disable_control(
            enabledControlIdentifier="this-is-not-an-arn-and-is-long-enough"
        )
    )
    assert malformed_code == "BadRequestException", (
        f"expected BadRequestException for a malformed (non-ARN) enabledControlIdentifier, "
        f"got {malformed_code}"
    )
    assert malformed_message == "Invalid request body", (
        f"expected 'Invalid request body' for a malformed enabledControlIdentifier, "
        f"got {malformed_message!r}"
    )

    fake_enabled_control_arn = (
        f"arn:aws:controltower:{ctx.region}:{_account_id(ctx)}:"
        "enabledcontrol/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    wellformed_missing_code, wellformed_missing_message = _error(
        lambda: ct.disable_control(enabledControlIdentifier=fake_enabled_control_arn)
    )
    assert wellformed_missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent "
        f"enabledControlIdentifier, got {wellformed_missing_code}"
    )
    assert wellformed_missing_message == NO_LANDING_ZONE_MESSAGE, (
        f"expected the no-landing-zone message for a well-formed but nonexistent "
        f"enabledControlIdentifier, got {wellformed_missing_message!r}"
    )


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
