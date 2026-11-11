"""sampling-rule-fixed-rate-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "sampling-rule-fixed-rate-precision-preserved"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fractional FixedRate value set on CreateSamplingRule is returned bit-for-bit
    identical by GetSamplingRules, not rounded or truncated to a coarser precision."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    fixed_rate = 0.133713371337
    created = xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": 999,
            "FixedRate": fixed_rate,
            "ReservoirSize": 1,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        }
    )["SamplingRuleRecord"]["SamplingRule"]
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=rule_name))
    xray.tag_resource(ResourceARN=created["RuleARN"], Tags=[{"Key": "sim2real", "Value": "behavioral"}])

    rule = _find_sampling_rule(xray, rule_name)
    assert rule["FixedRate"] == fixed_rate, f"expected {fixed_rate!r}, got {rule['FixedRate']!r}"


def _find_sampling_rule(xray, rule_name: str) -> dict:
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = xray.get_sampling_rules(**kwargs)
        for record in resp["SamplingRuleRecords"]:
            rule = record["SamplingRule"]
            if rule["RuleName"] == rule_name:
                return rule
        token = resp.get("NextToken")
        if not token:
            break
    raise AssertionError(f"sampling rule {rule_name!r} not found in GetSamplingRules")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
