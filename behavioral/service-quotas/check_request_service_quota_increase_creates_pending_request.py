"""request-service-quota-increase-creates-pending-request."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "request-service-quota-increase-creates-pending-request"
GROUP = "state"
SERVICES = ["service-quotas"]

_VCPU_NAME_HINTS = [
    "Standard (A, C, D, H, I, M, R, T, Z) instances",
    "G and VT instances",
    "High Memory instances",
    "P instances",
    "Running On-Demand",
]


def _find_ec2_vcpu_quota(ctx, prefer_index: int = 0) -> tuple[str, str, float]:
    sq = ctx.client("service-quotas")
    quotas: list[dict] = []
    for page in sq.get_paginator("list_service_quotas").paginate(ServiceCode="ec2"):
        quotas.extend(page["Quotas"])
    order = _VCPU_NAME_HINTS[prefer_index:] + _VCPU_NAME_HINTS[:prefer_index]
    for hint in order:
        for q in quotas:
            if hint.lower() in q["QuotaName"].lower() and q.get("Adjustable"):
                return q["QuotaCode"], q["QuotaName"], float(q["Value"])
    raise AssertionError(
        "no adjustable EC2 On-Demand vCPU-family quota found for this "
        "account/region to exercise the increase-request lifecycle"
    )


_OPEN_STATUSES = ("PENDING", "CASE_OPENED")


def _get_or_create_open_request(ctx, service_code: str, quota_code: str, current_value: float):
    """Only one open (PENDING/CASE_OPENED) request is allowed per quota at a
    time on real AWS. Reuse an existing open request for this quota if another
    check already created one, otherwise create a fresh one — either way the
    caller gets a genuinely open request to assert against."""
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestServiceQuotaIncrease returns a new request in an open status
    (PENDING, or CASE_OPENED once Support review starts) that
    GetRequestedServiceQuotaChange reflects consistently."""
    sq = ctx.client("service-quotas")
    quota_code, _quota_name, current_value = _find_ec2_vcpu_quota(ctx, prefer_index=0)

    # A large jump on a vCPU-family instance quota always requires manual Support
    # review, so it cannot synchronously resolve to APPROVED in the same response.
    created, _fresh = _get_or_create_open_request(ctx, "ec2", quota_code, current_value)

    assert created["ServiceCode"] == "ec2"
    assert created["QuotaCode"] == quota_code
    assert created["Status"] in _OPEN_STATUSES, f"unexpected initial status: {created['Status']}"
    request_id = created["Id"]

    fetched = sq.get_requested_service_quota_change(RequestId=request_id)["RequestedQuota"]
    assert fetched["Id"] == request_id
    assert fetched["ServiceCode"] == "ec2"
    assert fetched["QuotaCode"] == quota_code
    assert fetched["DesiredValue"] == created["DesiredValue"]
    assert fetched["Status"] == created["Status"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
