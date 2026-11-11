"""enable-baseline-malformed-target-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "enable-baseline-malformed-target-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["controltower"]

NO_ADMIN_ROLE_MESSAGE = (
    "AWS Control Tower could not complete the operation because it could not assume the "
    "'AWSControlTowerAdmin' role. Check the configuration for this role and try again."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "identity:standalone", "phase:standalone", "plane:control")
def run(ctx) -> None:
    """EnableBaseline rejects a non-ARN targetIdentifier with BadRequestException "Invalid request body",
    and a well-formed unknown OU ARN with ResourceNotFoundException when a landing zone exists, else with
    ValidationException and the AWSControlTowerAdmin role message."""
    ct = ctx.client("controltower")
    baseline_arn = _core_baseline_arn(ct)
    has_landing_zone = bool(ct.list_landing_zones(maxResults=1)["landingZones"])

    # 20+ chars so botocore's own min-length check (Arn shape, min 20) lets this
    # through the SDK -- botocore does not enforce the "pattern" constraint locally,
    # only min/max length, so a shorter string never leaves the client and would only
    # be testing botocore, not the service.
    malformed_code, malformed_message = _error(
        lambda: ct.enable_baseline(
            baselineIdentifier=baseline_arn,
            baselineVersion="4.0",
            targetIdentifier="this-is-not-an-arn-and-is-long-enough",
        )
    )
    assert malformed_code == "BadRequestException", (
        f"expected BadRequestException for a malformed targetIdentifier, got {malformed_code}"
    )
    assert malformed_message == "Invalid request body", (
        f"expected 'Invalid request body' for a malformed targetIdentifier, "
        f"got {malformed_message!r}"
    )

    fake_ou_arn = f"arn:aws:organizations::{_account_id(ctx)}:ou/o-aaaaaaaaaa/ou-aaaa-aaaaaaaa"
    wellformed_missing_code, wellformed_missing_message = _error(
        lambda: ct.enable_baseline(
            baselineIdentifier=baseline_arn,
            baselineVersion="4.0",
            targetIdentifier=fake_ou_arn,
        )
    )
    expected = "ResourceNotFoundException" if has_landing_zone else "ValidationException"
    assert wellformed_missing_code == expected, (
        f"expected {expected} for a well-formed but nonexistent target OU "
        f"(has_landing_zone={has_landing_zone}), got {wellformed_missing_code}"
    )
    if not has_landing_zone:
        assert wellformed_missing_message == NO_ADMIN_ROLE_MESSAGE, (
            f"expected the AWSControlTowerAdmin role message for a well-formed target OU "
            f"with no landing zone, got {wellformed_missing_message!r}"
        )
    # message varies: only the no-landing-zone message is asserted; the
    # ResourceNotFoundException text with a landing zone present is not pinned.


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


def _core_baseline_arn(ct) -> str:
    baselines = ct.list_baselines(maxResults=100)["baselines"]
    match = next((b for b in baselines if b["name"] == "AWSControlTowerBaseline"), None)
    assert match is not None, "AWSControlTowerBaseline missing from the managed catalog"
    return match["arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
