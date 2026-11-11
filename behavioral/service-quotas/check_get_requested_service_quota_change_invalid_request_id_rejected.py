"""get-requested-service-quota-change-invalid-request-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-requested-service-quota-change-invalid-request-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_VCPU_NAME_HINTS = [
    "P instances",
    "Standard (A, C, D, H, I, M, R, T, Z) instances",
    "G and VT instances",
    "High Memory instances",
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
        "account/region to exercise GetRequestedServiceQuotaChange"
    )


def _client_error(fn):
    """Call fn() and return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"expected an error for malformed RequestId, but the call SUCCEEDED: {result!r}"
    )


_OPEN_STATUSES = ("PENDING", "CASE_OPENED")
_CLOSED_STATUSES = ("APPROVED", "DENIED", "CASE_CLOSED", "NOT_APPROVED", "INVALID_REQUEST")
#: An open request advances on Service Quotas' own schedule, so a later read shows its status or
#: a later one: PENDING, then CASE_OPENED, then a closed status.
_LATER_OR_SAME = {
    "PENDING": {"PENDING", "CASE_OPENED", *_CLOSED_STATUSES},
    "CASE_OPENED": {"CASE_OPENED", *_CLOSED_STATUSES},
}


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRequestedServiceQuotaChange with a RequestId that fails its pattern is refused with
    ValidationException and the exact pattern-constraint message, while an existing request still
    reads back with its original id, desired value and status."""
    sq = ctx.client("service-quotas")
    quota_code, _quota_name, current_value = _find_ec2_vcpu_quota(ctx, prefer_index=3)

    real, _fresh = _get_or_create_open_request(ctx, "ec2", quota_code, current_value)
    real_id = real["Id"]

    bogus_id = "!!!not-a-valid-request-id!!!"  # fails pattern: must start alnum
    error = _client_error(lambda: sq.get_requested_service_quota_change(RequestId=bogus_id))
    assert error.get("Code") == "ValidationException", (
        "expected ValidationException for a RequestId that fails the pattern "
        f"(must start alnum), got {error!r}"
    )
    message = error.get("Message")
    expected = (
        "1 validation error detected: Value at 'requestId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [0-9a-zA-Z][a-zA-Z0-9-]{1,128}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent / positive control: the real request is unaffected and still
    # resolvable with its original fields.
    refetched = sq.get_requested_service_quota_change(RequestId=real_id)["RequestedQuota"]
    assert refetched["Id"] == real_id, (
        f"expected the real request {real_id!r} still resolvable, got id {refetched['Id']!r}"
    )
    assert refetched["DesiredValue"] == real["DesiredValue"], (
        "expected the real request's DesiredValue untouched by the rejected call, "
        f"expected {real['DesiredValue']!r}, got {refetched['DesiredValue']!r}"
    )
    assert refetched["Status"] in _LATER_OR_SAME.get(real["Status"], {real["Status"]}), (
        "expected the real request's Status untouched by the rejected call, "
        f"expected {real['Status']!r} or a state Service Quotas moves it to on its own, "
        f"got {refetched['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
