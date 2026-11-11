"""get-sampling-statistic-summaries-returns-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sampling-statistic-summaries-returns-list"
GROUP = 'sampling-rules'
SERVICES = ['xray']


def _sampling_rule_names(xr, max_pages=25):
    names = set()
    token = None
    for _ in range(max_pages):
        page = xr.get_sampling_rules(**({"NextToken": token} if token else {}))
        for record in page.get("SamplingRuleRecords", []):
            name = (record.get("SamplingRule") or {}).get("RuleName")
            if name:
                names.add(name)
        token = page.get("NextToken")
        if not token:
            break
    return names


def _statistic_summaries(xr, max_pages=25):
    rows = []
    token = None
    for _ in range(max_pages):
        page = xr.get_sampling_statistic_summaries(**({"NextToken": token} if token else {}))
        rows.extend(page.get("SamplingStatisticSummaries", []))
        token = page.get("NextToken")
        if not token:
            break
    return rows


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSamplingStatisticSummaries returns a list of well-formed rows that holds no row for a
    freshly created rule no GetSamplingTargets report has touched."""
    xr = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-xr-ssum-")

    created = xr.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": 9998,
            "FixedRate": 0.05,
            "ReservoirSize": 1,
            "ServiceName": rule_name,
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        }
    )["SamplingRuleRecord"]["SamplingRule"]
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=rule_name))
    assert created["RuleName"] == rule_name, created

    # independent read, at a different operation than the one that created the rule
    rule_names = _sampling_rule_names(xr)
    assert rule_name in rule_names, f"{rule_name} missing from GetSamplingRules: {rule_names}"

    rows = _statistic_summaries(xr)
    assert isinstance(rows, list), f"SamplingStatisticSummaries must be a list, got {type(rows)}: {rows!r}"

    matching = [r for r in rows if r.get("RuleName") == rule_name]
    assert matching == [], (
        f"a rule that has never had a GetSamplingTargets report against it must not appear in "
        f"GetSamplingStatisticSummaries -- {rule_name} was just created with zero reported "
        f"activity, but the endpoint returned {matching!r}"
    )

    for row in rows:
        assert isinstance(row.get("RuleName"), str) and row["RuleName"], row
        assert isinstance(row.get("RequestCount"), int) and row["RequestCount"] >= 0, row
        assert isinstance(row.get("SampledCount"), int) and row["SampledCount"] >= 0, row


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
