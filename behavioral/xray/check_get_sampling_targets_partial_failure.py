"""get-sampling-targets-partial-failure."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags

CHECK = "get-sampling-targets-partial-failure"
GROUP = 'trace-data-plane'
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSamplingTargets returns a target document per known rule and reports unknown rule names
    individually in UnprocessedStatistics rather than failing the whole batch."""
    xr = ctx.client("xray")
    rule = _default_sampling_rule(ctx.unique_name("sim2real-behav-r-"))
    name = rule["RuleName"]
    xr.create_sampling_rule(SamplingRule=rule, Tags=[{"Key": "sim2real", "Value": name}])
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=name))

    bogus_name = ctx.unique_name("sim2real-behav-nx-")
    now = int(time.time())
    resp = xr.get_sampling_targets(
        SamplingStatisticsDocuments=[
            {"RuleName": name, "ClientID": "a" * 24, "Timestamp": now, "RequestCount": 10, "SampledCount": 1},
            {"RuleName": bogus_name, "ClientID": "b" * 24, "Timestamp": now, "RequestCount": 10, "SampledCount": 1},
        ]
    )
    target_rule_names = [t["RuleName"] for t in resp.get("SamplingTargetDocuments", [])]
    unprocessed_names = [u["RuleName"] for u in resp.get("UnprocessedStatistics", [])]
    assert target_rule_names == [name], (
        f"expected exactly one successful target, for the known rule {name}: got {target_rule_names}"
    )
    assert unprocessed_names == [bogus_name], (
        f"expected exactly one UnprocessedStatistics entry, for the unknown rule {bogus_name}: "
        f"got {unprocessed_names}"
    )
    bogus_entry = resp["UnprocessedStatistics"][0]
    assert bogus_entry.get("ErrorCode"), "unprocessed entry must carry an ErrorCode"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
