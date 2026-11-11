"""list-requested-quota-change-history-by-quota-includes-pending-request."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-requested-quota-change-history-by-quota-includes-pending-request"
GROUP = "state"
SERVICES = ["service-quotas"]

_VCPU_NAME_HINTS = [
    "G and VT instances",
    "High Memory instances",
    "P instances",
    "Standard (A, C, D, H, I, M, R, T, Z) instances",
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
        "account/region to exercise the increase-request history listing"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An open (PENDING or CASE_OPENED) increase request, new or already open, appears in
    ListRequestedServiceQuotaChangeHistoryByQuota with the same id and desired value and an open
    status."""
    sq = ctx.client("service-quotas")
    quota_code, _quota_name, current_value = _find_ec2_vcpu_quota(ctx, prefer_index=1)

    created, _fresh = _get_or_create_open_request(ctx, "ec2", quota_code, current_value)
    request_id = created["Id"]

    def probe():
        entries = []
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode="ec2", QuotaCode=quota_code):
            entries.extend(page["RequestedQuotas"])
        return entries

    def found(entries):
        return any(e["Id"] == request_id for e in entries)

    entries = _poll_until(probe, found, timeout_s=60.0, interval_s=3.0)
    match = next(e for e in entries if e["Id"] == request_id)
    assert match["DesiredValue"] == created["DesiredValue"], (
        f"expected DesiredValue={created['DesiredValue']!r} in per-quota history for "
        f"request {request_id!r}, got {match['DesiredValue']!r}"
    )
    assert match["Status"] in _OPEN_STATUSES, (
        f"expected an open status {_OPEN_STATUSES!r} for request {request_id!r} in "
        f"per-quota history, got {match['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
