"""requested-quota-change-history-status-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "requested-quota-change-history-status-filter"
GROUP = "state-machine"
SERVICES = ["service-quotas"]

# Deliberately not "vpc"/"dynamodb"/"cloudformation": real AWS allows only one
# open request per quota at a time, so this fixture uses quotas of its own.
_SERVICE_CODE = "lambda"

_OTHER_STATUS = {
    "PENDING": "DENIED",
    "CASE_OPENED": "DENIED",
    "APPROVED": "PENDING",
    "DENIED": "PENDING",
    "CASE_CLOSED": "PENDING",
    "NOT_APPROVED": "PENDING",
    "INVALID_REQUEST": "PENDING",
}


def _scan_for_id(sq, service_code, quota_code, status, request_id, max_pages=50):
    token = None
    for _ in range(max_pages):
        kwargs = {
            "ServiceCode": service_code,
            "QuotaCode": quota_code,
            "Status": status,
            "MaxResults": 20,
        }
        if token:
            kwargs["NextToken"] = token
        resp = sq.list_requested_service_quota_change_history_by_quota(**kwargs)
        if any(item["Id"] == request_id for item in resp["RequestedQuotas"]):
            return True
        token = resp.get("NextToken")
        if not token:
            break
    return False


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRequestedServiceQuotaChangeHistoryByQuota filtered by a request's own status includes its Id,
    and filtered by a different status excludes it: the server applies the Status filter."""
    from botocore.exceptions import ClientError

    sq = ctx.client("service-quotas")
    quotas = sq.list_service_quotas(ServiceCode=_SERVICE_CODE)["Quotas"]
    adjustable = next((q for q in quotas if q["Adjustable"]), None)
    assert adjustable is not None, f"expected at least one adjustable {_SERVICE_CODE} quota"
    quota_code = adjustable["QuotaCode"]

    desired = adjustable["Value"] + 1
    try:
        created = sq.request_service_quota_increase(
            ServiceCode=_SERVICE_CODE, QuotaCode=quota_code, DesiredValue=desired
        )["RequestedQuota"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
        found_open = None
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode=_SERVICE_CODE, QuotaCode=quota_code):
            for item in page["RequestedQuotas"]:
                if item["Status"] in ("PENDING", "CASE_OPENED"):
                    found_open = item
                    break
            if found_open:
                break
        assert found_open is not None, "ResourceAlreadyExistsException but no open request found"
        created = found_open
    request_id = created["Id"]

    fetched = sq.get_requested_service_quota_change(RequestId=request_id)["RequestedQuota"]
    observed_status = fetched["Status"]
    other_status = _OTHER_STATUS[observed_status]

    assert _scan_for_id(sq, _SERVICE_CODE, quota_code, observed_status, request_id), (
        f"request {request_id} missing from history filtered by its own status {observed_status!r}"
    )
    assert not _scan_for_id(sq, _SERVICE_CODE, quota_code, other_status, request_id), (
        f"request {request_id} unexpectedly present in history filtered by status {other_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

