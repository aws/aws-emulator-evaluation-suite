"""non-adjustable-quota-increase-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "non-adjustable-quota-increase-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_CANDIDATE_SERVICES = ["lambda", "vpc", "ec2", "dynamodb", "iam", "s3", "cloudformation"]


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _find_non_adjustable_quota(sq):
    for service_code in _CANDIDATE_SERVICES:
        token = None
        for _ in range(20):
            kwargs = {"ServiceCode": service_code, "MaxResults": 20}
            if token:
                kwargs["NextToken"] = token
            resp = sq.list_service_quotas(**kwargs)
            for q in resp["Quotas"]:
                if q["Adjustable"] is False:
                    return q
            token = resp.get("NextToken")
            if not token:
                break
    return None


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RequestServiceQuotaIncrease on a quota with Adjustable=False is refused with
    IllegalArgumentException and its exact message and leaves its value unchanged, while a request on
    an adjustable vpc quota is accepted, or one is already open, and reads back open."""
    sq = ctx.client("service-quotas")
    non_adjustable = _find_non_adjustable_quota(sq)
    if non_adjustable is None:
        raise AssertionError(
            "no non-adjustable quota found among probed services "
            f"({', '.join(_CANDIDATE_SERVICES)}); cannot exercise this boundary"
        )

    service_code = non_adjustable["ServiceCode"]
    quota_code = non_adjustable["QuotaCode"]
    current_value = non_adjustable["Value"]

    code, message = _client_error(
        lambda: sq.request_service_quota_increase(
            ServiceCode=service_code, QuotaCode=quota_code, DesiredValue=current_value + 1
        )
    )
    assert code == "IllegalArgumentException", code
    expected = "The request failed because the specified quota is not adjustable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = sq.get_service_quota(ServiceCode=service_code, QuotaCode=quota_code)["Quota"]
    assert unchanged["Value"] == current_value
    assert unchanged["Adjustable"] is False

    vpc_quotas = sq.list_service_quotas(ServiceCode="vpc")["Quotas"]
    adjustable = next((q for q in vpc_quotas if q["Adjustable"]), None)
    assert adjustable is not None, "expected at least one adjustable vpc quota"
    quota_code = adjustable["QuotaCode"]
    _open_statuses = {"PENDING", "CASE_OPENED", "APPROVED"}
    try:
        accepted = sq.request_service_quota_increase(
            ServiceCode="vpc", QuotaCode=quota_code, DesiredValue=adjustable["Value"] + 1
        )["RequestedQuota"]
        assert accepted["Status"] in _open_statuses, accepted["Status"]
        # Independent read: the accepted request is durably visible through a
        # different operation than the one that created it, not just echoed
        # back in the mutating call's own response.
        confirmed = sq.get_requested_service_quota_change(RequestId=accepted["Id"])["RequestedQuota"]
        assert confirmed["Status"] in _open_statuses, confirmed["Status"]
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
        # An open request already exists on this quota.
        # Don't just trust the error message as proof the positive control
        # holds — read it back independently: an open request must actually
        # be resolvable for this quota through the history API.
        open_requests = [
            e
            for page in sq.get_paginator(
                "list_requested_service_quota_change_history_by_quota"
            ).paginate(ServiceCode="vpc", QuotaCode=quota_code)
            for e in page["RequestedQuotas"]
            if e["Status"] in _open_statuses
        ]
        assert open_requests, (
            "ResourceAlreadyExistsException on request_service_quota_increase but no "
            "open request found in history for the same quota"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
