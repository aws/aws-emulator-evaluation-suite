"""service-quota-arn-format-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "service-quota-arn-format-consistency"
GROUP = "representation"
SERVICES = ["service-quotas"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetServiceQuota's QuotaArn equals arn:<partition>:servicequotas:<region>:<account>:vpc/<quota-code>,
    built from the caller's own partition, account and region and a quota code ListServiceQuotas lists."""
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    sq = ctx.client("service-quotas")
    listed = sq.list_service_quotas(ServiceCode="vpc")["Quotas"]
    assert listed, "expected at least one quota for ServiceCode=vpc"
    quota_code = listed[0]["QuotaCode"]

    got = sq.get_service_quota(ServiceCode="vpc", QuotaCode=quota_code)["Quota"]
    expected_arn = f"arn:{partition}:servicequotas:{ctx.region}:{account_id}:vpc/{quota_code}"
    assert got["QuotaArn"] == expected_arn, f"expected {expected_arn!r}, got {got['QuotaArn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
