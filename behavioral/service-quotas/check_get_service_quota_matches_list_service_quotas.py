"""get-service-quota-matches-list-service-quotas."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-service-quota-matches-list-service-quotas"
GROUP = "representation"
SERVICES = ["service-quotas"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetServiceQuota returns the same ServiceCode, QuotaCode, QuotaName, Value, Adjustable,
    GlobalQuota and Unit as the matching ListServiceQuotas entry: both read paths resolve to one
    record."""
    sq = ctx.client("service-quotas")
    listed = sq.list_service_quotas(ServiceCode="vpc")["Quotas"]
    assert listed, "expected at least one quota for ServiceCode=vpc"
    target = listed[0]

    got = sq.get_service_quota(ServiceCode="vpc", QuotaCode=target["QuotaCode"])["Quota"]

    assert got["ServiceCode"] == target["ServiceCode"] == "vpc", (
        f"ServiceCode mismatch between GetServiceQuota ({got['ServiceCode']!r}) and "
        f"ListServiceQuotas ({target['ServiceCode']!r}), expected both == 'vpc'"
    )
    assert got["QuotaCode"] == target["QuotaCode"], (
        f"QuotaCode mismatch: get={got['QuotaCode']!r} list={target['QuotaCode']!r}"
    )
    assert got["QuotaName"] == target["QuotaName"], (
        f"QuotaName mismatch for {target['QuotaCode']}: "
        f"get={got['QuotaName']!r} list={target['QuotaName']!r}"
    )
    assert got["Value"] == target["Value"], (
        f"Value mismatch for {target['QuotaCode']}: get={got['Value']!r} list={target['Value']!r}"
    )
    assert got["Adjustable"] == target["Adjustable"], (
        f"Adjustable mismatch for {target['QuotaCode']}: "
        f"get={got['Adjustable']!r} list={target['Adjustable']!r}"
    )
    assert got["GlobalQuota"] == target["GlobalQuota"], (
        f"GlobalQuota mismatch for {target['QuotaCode']}: "
        f"get={got['GlobalQuota']!r} list={target['GlobalQuota']!r}"
    )
    assert got.get("Unit") == target.get("Unit"), (
        f"Unit mismatch for {target['QuotaCode']}: get={got.get('Unit')!r} list={target.get('Unit')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
