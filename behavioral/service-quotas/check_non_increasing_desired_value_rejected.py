"""non-increasing-desired-value-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "non-increasing-desired-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _expected_refusal(rejected_value: float, default_value: float) -> str:
    """AWS compares a refused DesiredValue against the AWS default first, then against the
    applied value, and names whichever bound it fell under."""
    if rejected_value < default_value:
        return f"You must provide a quota value greater than the default quota value of {default_value}"
    return "You must provide a quota value greater than the current quota value"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestServiceQuotaIncrease with a DesiredValue strictly below the applied value is refused with
    IllegalArgumentException and the exact message naming the bound, leaves the value unchanged, and a
    higher DesiredValue on the same quota is accepted (or meets an already open request)."""
    from botocore.exceptions import ClientError

    sq = ctx.client("service-quotas")
    try:
        current_value = sq.get_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)[
            "Quota"
        ]["Value"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchResourceException":
            raise
        current_value = sq.get_aws_default_service_quota(
            ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE
        )["Quota"]["Value"]
    default_value = sq.get_aws_default_service_quota(
        ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE
    )["Quota"]["Value"]
    rejected_value = current_value - 1

    code, message = _error_code(
        lambda: sq.request_service_quota_increase(
            ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE, DesiredValue=rejected_value
        )
    )
    # A bare ResourceAlreadyExistsException would mean a request is already open on this quota for
    # ANY DesiredValue.
    assert code == "IllegalArgumentException", (
        f"expected IllegalArgumentException for a non-increasing DesiredValue, got {code!r} "
        "(a bare ResourceAlreadyExistsException here is inconclusive for this check's own "
        "contract, not a pass)"
    )
    expected = _expected_refusal(rejected_value, default_value)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the applied quota value must not have moved.
    unchanged = sq.get_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)["Quota"]
    assert unchanged["Value"] == current_value

    # Positive control: a genuinely higher DesiredValue on the same quota is
    # accepted (tolerate a pre-existing open request on this quota -- only one
    # open request per quota is allowed at a time).
    import time

    jitter = int(time.time() * 1000) % 1000
    try:
        accepted = sq.request_service_quota_increase(
            ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE, DesiredValue=current_value + 2 + jitter
        )["RequestedQuota"]
        assert accepted["DesiredValue"] == current_value + 2 + jitter
        assert accepted["Status"] in {"PENDING", "CASE_OPENED", "APPROVED"}
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceAlreadyExistsException", (
            f"unexpected error on positive-control increase: {e.response['Error']['Code']}"
        )
        expected_open = "Only one open service quota increase request is allowed per quota."
        assert e.response["Error"].get("Message") == expected_open, (
            f"expected message {expected_open!r}, got {e.response['Error'].get('Message')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


