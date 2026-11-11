"""list-aws-default-service-quotas-matches-get-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-aws-default-service-quotas-matches-get-default"
GROUP = "data-plane"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The single-item GetAWSDefaultServiceQuota result agrees exactly with the
    same quota's entry inside the bulk ListAWSDefaultServiceQuotas listing."""
    sq = ctx.client("service-quotas")

    single = sq.get_aws_default_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)[
        "Quota"
    ]

    listed = None
    for page in sq.get_paginator("list_aws_default_service_quotas").paginate(
        ServiceCode=_SERVICE_CODE
    ):
        for q in page["Quotas"]:
            if q["QuotaCode"] == _QUOTA_CODE:
                listed = q
                break
        if listed:
            break

    assert listed is not None, f"{_QUOTA_CODE} missing from ListAWSDefaultServiceQuotas"
    assert listed["Value"] == single["Value"], (
        f"Value mismatch: list={listed['Value']!r} get={single['Value']!r}"
    )
    assert listed["QuotaName"] == single["QuotaName"], (
        f"QuotaName mismatch: list={listed['QuotaName']!r} get={single['QuotaName']!r}"
    )
    assert listed["Unit"] == single["Unit"], (
        f"Unit mismatch: list={listed['Unit']!r} get={single['Unit']!r}"
    )
    assert listed["Adjustable"] == single["Adjustable"], (
        f"Adjustable mismatch: list={listed['Adjustable']!r} get={single['Adjustable']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
