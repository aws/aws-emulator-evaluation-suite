"""request-service-quota-increase-creates-valid-request."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "request-service-quota-increase-creates-valid-request"
GROUP = "state-machine"
SERVICES = ["service-quotas"]

# Deliberately not "vpc": real AWS allows only one open request per quota at a
# time, and the first adjustable vpc quota is a common target. DynamoDB keeps this
# fixture independent.
_SERVICE_CODE = "dynamodb"

_VALID_INITIAL_STATUSES = {"PENDING", "CASE_OPENED", "APPROVED"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestServiceQuotaIncrease returns a PENDING, CASE_OPENED or APPROVED request with the given
    ServiceCode, QuotaCode and DesiredValue, and GetRequestedServiceQuotaChange resolves its Id to the
    same fields with a status still in that set."""
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
        # A prior run of this same check already left an open request here;
        # exercise the same read-path assertions against it instead.
        found = None
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode=_SERVICE_CODE, QuotaCode=adjustable["QuotaCode"]):
            for item in page["RequestedQuotas"]:
                if item["Status"] in ("PENDING", "CASE_OPENED"):
                    found = item
                    break
            if found:
                break
        assert found is not None, "ResourceAlreadyExistsException but no open request found"
        created = found
        desired = found["DesiredValue"]

    assert created["ServiceCode"] == _SERVICE_CODE
    assert created["QuotaCode"] == adjustable["QuotaCode"]
    assert created["DesiredValue"] == desired
    assert created["Status"] in _VALID_INITIAL_STATUSES, created["Status"]
    request_id = created["Id"]
    assert request_id

    fetched = sq.get_requested_service_quota_change(RequestId=request_id)["RequestedQuota"]
    assert fetched["Id"] == request_id
    assert fetched["ServiceCode"] == _SERVICE_CODE
    assert fetched["QuotaCode"] == adjustable["QuotaCode"]
    assert fetched["DesiredValue"] == desired
    # Status may have progressed asynchronously since creation (e.g. PENDING ->
    # APPROVED), but a request this fresh must still be open or auto-approved --
    # not already denied/closed/invalidated, which would mean AWS rejected this
    # exact request out from under a check that just successfully created it.
    assert fetched["Status"] in _VALID_INITIAL_STATUSES, fetched["Status"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

