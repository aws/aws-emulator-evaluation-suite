"""list-requested-service-quota-change-history-status-filter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-requested-service-quota-change-history-status-filter"
GROUP = "data-plane"
SERVICES = ["service-quotas"]

_OPEN_STATUSES = ("PENDING", "CASE_OPENED")

_VCPU_NAME_HINTS = [
    "High Memory instances",
    "Standard (A, C, D, H, I, M, R, T, Z) instances",
    "P instances",
    "G and VT instances",
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
        "account/region to exercise the Status filter"
    )


def _ids_for_status(ctx, quota_code, status) -> set[str]:
    sq = ctx.client("service-quotas")
    ids: set[str] = set()
    for page in sq.get_paginator(
        "list_requested_service_quota_change_history_by_quota"
    ).paginate(ServiceCode="ec2", QuotaCode=quota_code, Status=status):
        ids.update(e["Id"] for e in page["RequestedQuotas"])
    return ids


def _request_or_adopt_open(ctx, quota_code, desired):
    """Only one open (PENDING/CASE_OPENED) request is allowed per quota at a
    time on real AWS, and a quota increase request cannot be cancelled --
    so a re-run against an account that already holds one from a prior run
    (or a concurrent request on the same quota) must adopt it rather than fail."""
    sq = ctx.client("service-quotas")
    try:
        return sq.request_service_quota_increase(
            ServiceCode="ec2", QuotaCode=quota_code, DesiredValue=desired
        )["RequestedQuota"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode="ec2", QuotaCode=quota_code):
            for entry in page["RequestedQuotas"]:
                if entry["Status"] in _OPEN_STATUSES:
                    return entry
        raise AssertionError(
            "ResourceAlreadyExistsException on RequestServiceQuotaIncrease but no "
            "open (PENDING/CASE_OPENED) request found in the history for "
            f"quota_code={quota_code!r}"
        )


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An open (PENDING or CASE_OPENED) request appears in ListRequestedServiceQuotaChangeHistoryByQuota
    filtered by its own status and is absent when filtered by APPROVED."""
    quota_code, _quota_name, current_value = _find_ec2_vcpu_quota(ctx, prefer_index=1)

    jitter = int(time.time() * 1000) % 100000
    desired = current_value + 1000 + jitter
    created = _request_or_adopt_open(ctx, quota_code, desired)
    status = created["Status"]
    assert status in _OPEN_STATUSES, (
        f"expected a fresh/adopted request to be open ({_OPEN_STATUSES!r}), got {status!r}"
    )
    request_id = created["Id"]

    own_status_ids = _ids_for_status(ctx, quota_code, status)
    assert request_id in own_status_ids, (
        f"request {request_id} missing from history filtered by its own status {status!r}: "
        f"{own_status_ids!r}"
    )

    approved_ids = _ids_for_status(ctx, quota_code, "APPROVED")
    assert request_id not in approved_ids, (
        f"request {request_id} unexpectedly present in history filtered by Status=APPROVED "
        f"while its actual status is {status!r}: {approved_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
