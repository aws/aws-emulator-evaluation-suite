"""list-service-quotas-filter-by-quota-code."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-service-quotas-filter-by-quota-code"
GROUP = "data-plane"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServiceQuotas with a QuotaCode filter returns exactly that one quota,
    matching ServiceCode/QuotaCode and a regional (non-global) scope."""
    sq = ctx.client("service-quotas")

    resp = sq.list_service_quotas(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)
    quotas = resp["Quotas"]

    assert len(quotas) == 1, f"expected exactly one filtered quota, got {len(quotas)}"
    quota = quotas[0]
    assert quota["ServiceCode"] == _SERVICE_CODE, (
        f"expected ServiceCode {_SERVICE_CODE!r}, got {quota['ServiceCode']!r}"
    )
    assert quota["QuotaCode"] == _QUOTA_CODE, (
        f"expected QuotaCode {_QUOTA_CODE!r}, got {quota['QuotaCode']!r}"
    )
    assert quota["QuotaName"] == "VPCs per Region", (
        f"expected QuotaName 'VPCs per Region', got {quota['QuotaName']!r}"
    )
    assert quota["GlobalQuota"] is False, "VPCs per Region is a regional, not global, quota"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
