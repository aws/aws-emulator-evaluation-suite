"""request-quota-increase-not-greater-than-current-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-quota-increase-not-greater-than-current-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region


def _current_value(ctx) -> float:
    sq = ctx.client("service-quotas")
    try:
        return float(
            sq.get_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)["Quota"][
                "Value"
            ]
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchResourceException":
            raise
    return float(
        sq.get_aws_default_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)[
            "Quota"
        ]["Value"]
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _expected_refusal(rejected_value: float, default_value: float) -> str:
    """AWS compares a refused DesiredValue against the AWS default first, then against the
    applied value, and names whichever bound it fell under."""
    if rejected_value < default_value:
        return f"You must provide a quota value greater than the default quota value of {default_value}"
    return "You must provide a quota value greater than the current quota value"


def _matching_history_count(ctx, desired_value: float) -> int:
    sq = ctx.client("service-quotas")
    count = 0
    for page in sq.get_paginator(
        "list_requested_service_quota_change_history_by_quota"
    ).paginate(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE):
        count += sum(1 for e in page["RequestedQuotas"] if e["DesiredValue"] == desired_value)
    return count


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Requesting a desired value strictly below the applied value is refused with
    IllegalArgumentException and the exact message naming the bound and adds no history entry, while
    a higher desired value is accepted (or meets an already open request)."""
    sq = ctx.client("service-quotas")
    current_value = _current_value(ctx)
    default_value = float(
        sq.get_aws_default_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)[
            "Quota"
        ]["Value"]
    )
    rejected_value = current_value - 1

    baseline_count = _matching_history_count(ctx, rejected_value)

    code, message = _error_code(
        lambda: sq.request_service_quota_increase(
            ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE, DesiredValue=rejected_value
        )
    )
    assert code == "IllegalArgumentException", (
        f"expected IllegalArgumentException for non-increasing DesiredValue, got {code!r}"
    )
    expected = _expected_refusal(rejected_value, default_value)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_count = _matching_history_count(ctx, rejected_value)
    assert after_count == baseline_count, (
        "a rejected below-current request left a new history entry: "
        f"before={baseline_count} after={after_count}"
    )

    # Positive control: a strictly higher, jittered desired value still succeeds
    # (tolerate a pre-existing open request on this quota — only one open
    # request per quota is allowed at a time).
    jitter = int(time.time() * 1000) % 1000
    control_desired = current_value + 2 + jitter
    try:
        control = sq.request_service_quota_increase(
            ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE, DesiredValue=control_desired
        )["RequestedQuota"]
        assert control["DesiredValue"] == control_desired, (
            f"expected the accepted request to echo DesiredValue={control_desired}, "
            f"got {control['DesiredValue']!r}"
        )
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
