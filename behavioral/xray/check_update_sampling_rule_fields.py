"""update-sampling-rule-fields."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "update-sampling-rule-fields"
GROUP = 'sampling-rules'
SERVICES = ['xray']


def _default_sampling_rule(name, **overrides):
    rule = {
        "RuleName": name,
        "ResourceARN": "*",
        "Priority": random.randint(1, 9999),
        "FixedRate": 0.05,
        "ReservoirSize": 1,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
    }
    rule.update(overrides)
    return rule


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSamplingRule mutates targeted fields (Priority, FixedRate) and preserves others."""
    xr = ctx.client("xray")
    rule = _default_sampling_rule(
        ctx.unique_name("sim2real-behav-r-"), Priority=100, FixedRate=0.05, ReservoirSize=2
    )
    xr.create_sampling_rule(SamplingRule=rule)
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=rule["RuleName"]))

    resp = xr.update_sampling_rule(
        SamplingRuleUpdate={
            "RuleName": rule["RuleName"],
            "Priority": 42,
            "FixedRate": 0.9,
        }
    )
    stored = resp["SamplingRuleRecord"]["SamplingRule"]
    assert stored["Priority"] == 42, stored
    assert stored["FixedRate"] == 0.9, stored
    assert stored["ReservoirSize"] == 2, "untouched field ReservoirSize must be preserved"

    listed = xr.get_sampling_rules()["SamplingRuleRecords"]
    match = next(
        r["SamplingRule"] for r in listed if r["SamplingRule"]["RuleName"] == rule["RuleName"]
    )
    assert match["Priority"] == 42, f"GetSamplingRules shows stale Priority: {match}"
    assert match["FixedRate"] == 0.9, f"GetSamplingRules shows stale FixedRate: {match}"
    assert match["ReservoirSize"] == 2, (
        f"untouched field ReservoirSize did not persist as seen via independent read: {match}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
