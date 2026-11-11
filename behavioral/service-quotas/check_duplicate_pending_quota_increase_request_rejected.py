"""duplicate-pending-quota-increase-request-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-pending-quota-increase-request-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_VCPU_NAME_HINTS = [
    "High Memory instances",
    "P instances",
    "Standard (A, C, D, H, I, M, R, T, Z) instances",
    "G and VT instances",
    "Running On-Demand",
]


def _find_ec2_vcpu_quota(ctx, prefer_index: int = 0) -> tuple[str, str, float]:
    sq = ctx.client("service-quotas")
    quotas: list[dict] = []
    for attempt in range(6):
        try:
            quotas = []
            for page in sq.get_paginator("list_service_quotas").paginate(ServiceCode="ec2"):
                quotas.extend(page["Quotas"])
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "TooManyRequestsException" or attempt == 5:
                raise
            time.sleep(2 ** attempt)
    order = _VCPU_NAME_HINTS[prefer_index:] + _VCPU_NAME_HINTS[:prefer_index]
    for hint in order:
        for q in quotas:
            if hint.lower() in q["QuotaName"].lower() and q.get("Adjustable"):
                return q["QuotaCode"], q["QuotaName"], float(q["Value"])
    raise AssertionError(
        "no adjustable EC2 On-Demand vCPU-family quota found for this "
        "account/region to exercise the duplicate-request rejection"
    )


_OPEN_STATUSES = ("PENDING", "CASE_OPENED")


def _get_or_create_open_request(ctx, service_code: str, quota_code: str, current_value: float):
    """Only one open (PENDING/CASE_OPENED) request is allowed per quota at a
    time on real AWS. Reuse an existing open request for this quota if another
    check already created one, otherwise create a fresh one."""
    sq = ctx.client("service-quotas")
    for page in sq.get_paginator(
        "list_requested_service_quota_change_history_by_quota"
    ).paginate(ServiceCode=service_code, QuotaCode=quota_code):
        for e in page["RequestedQuotas"]:
            if e["Status"] in _OPEN_STATUSES:
                return e, False
    jitter = int(time.time() * 1000) % 100000
    desired = current_value + 1000 + jitter
    try:
        created = sq.request_service_quota_increase(
            ServiceCode=service_code, QuotaCode=quota_code, DesiredValue=desired
        )["RequestedQuota"]
        return created, True
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode=service_code, QuotaCode=quota_code):
            for entry in page["RequestedQuotas"]:
                if entry["Status"] in _OPEN_STATUSES:
                    return entry, False
        raise


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the duplicate quota increase request to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a quota has an open increase request, a second request with a different desired value is
    refused with ResourceAlreadyExistsException and its exact message, adds no history entry, and the
    original request stays open."""
    sq = ctx.client("service-quotas")
    quota_code, _quota_name, current_value = _find_ec2_vcpu_quota(ctx, prefer_index=2)

    first, _fresh = _get_or_create_open_request(ctx, "ec2", quota_code, current_value)
    assert first["Status"] in _OPEN_STATUSES, (
        f"expected the positive-control request to be open (one of {_OPEN_STATUSES}), "
        f"got status {first['Status']!r}"
    )

    jitter = int(time.time() * 1000) % 100000
    other_desired = current_value + 5000 + jitter
    code, message = _error_code(
        lambda: sq.request_service_quota_increase(
            ServiceCode="ec2", QuotaCode=quota_code, DesiredValue=other_desired
        )
    )
    assert code == "ResourceAlreadyExistsException", (
        f"expected ResourceAlreadyExistsException while a request is open, got {code!r}"
    )
    expected = "Only one open service quota increase request is allowed per quota."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected duplicate did not create a history entry for
    # its distinct desired value.
    matches = [
        e
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode="ec2", QuotaCode=quota_code)
        for e in page["RequestedQuotas"]
        if e["DesiredValue"] == other_desired
    ]
    assert len(matches) == 0, f"rejected duplicate unexpectedly created a history entry: {matches}"

    # And the original open request is still resolvable, unaffected.
    refetched = sq.get_requested_service_quota_change(RequestId=first["Id"])["RequestedQuota"]
    assert refetched["Id"] == first["Id"], (
        f"expected the original request id {first['Id']!r}, got {refetched['Id']!r}"
    )
    assert refetched["Status"] in _OPEN_STATUSES, (
        f"expected the original request to remain open (one of {_OPEN_STATUSES}) after "
        f"the rejected duplicate, got status {refetched['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

