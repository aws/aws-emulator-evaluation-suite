"""requested-quota-change-appears-in-history."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "requested-quota-change-appears-in-history"
GROUP = "state-machine"
SERVICES = ["service-quotas"]

# Deliberately not "vpc"/"dynamodb": real AWS allows only one open request per
# quota at a time, so this fixture uses quotas of its own.
_SERVICE_CODE = "cloudformation"


def _find_in_history(sq, service_code, quota_code, request_id, max_pages=50):
    token = None
    for _ in range(max_pages):
        kwargs = {"ServiceCode": service_code, "QuotaCode": quota_code, "MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        resp = sq.list_requested_service_quota_change_history_by_quota(**kwargs)
        for item in resp["RequestedQuotas"]:
            if item["Id"] == request_id:
                return item
        token = resp.get("NextToken")
        if not token:
            break
    return None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly submitted increase request (or the one already open) is found by Id in
    ListRequestedServiceQuotaChangeHistoryByQuota with the exact DesiredValue submitted."""
    from botocore.exceptions import ClientError

    sq = ctx.client("service-quotas")
    quotas = sq.list_service_quotas(ServiceCode=_SERVICE_CODE)["Quotas"]
    adjustable = next((q for q in quotas if q["Adjustable"]), None)
    assert adjustable is not None, f"expected at least one adjustable {_SERVICE_CODE} quota"

    desired = adjustable["Value"] + 1
    try:
        created = sq.request_service_quota_increase(
            ServiceCode=_SERVICE_CODE, QuotaCode=adjustable["QuotaCode"], DesiredValue=desired
        )["RequestedQuota"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise
        found_open = None
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode=_SERVICE_CODE, QuotaCode=adjustable["QuotaCode"]):
            for item in page["RequestedQuotas"]:
                if item["Status"] in ("PENDING", "CASE_OPENED"):
                    found_open = item
                    break
            if found_open:
                break
        assert found_open is not None, "ResourceAlreadyExistsException but no open request found"
        created = found_open
        desired = found_open["DesiredValue"]
    request_id = created["Id"]

    found = _find_in_history(sq, _SERVICE_CODE, adjustable["QuotaCode"], request_id)
    assert found is not None, f"request {request_id} not found in per-quota change history"
    assert found["DesiredValue"] == desired, (
        f"expected DesiredValue {desired!r} for request {request_id} in history, "
        f"got {found['DesiredValue']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

