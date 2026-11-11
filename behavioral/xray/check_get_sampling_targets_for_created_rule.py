"""get-sampling-targets-for-created-rule."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags

CHECK = "get-sampling-targets-for-created-rule"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSamplingTargets answers a report for a freshly created rule with a target document
    echoing its FixedRate 0.2 and, before any allocation cycle, no ReservoirQuota."""
    xr = ctx.client("xray")
    fixed_rate = 0.2
    rule = _default_sampling_rule(ctx.unique_name("sim2real-behav-r-"), ReservoirSize=5, FixedRate=fixed_rate)
    xr.create_sampling_rule(SamplingRule=rule)
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=rule["RuleName"]))

    now = time.time()
    resp = xr.get_sampling_targets(
        SamplingStatisticsDocuments=[
            {
                "RuleName": rule["RuleName"],
                "ClientID": "0" * 24,
                "Timestamp": now,
                "RequestCount": 100,
                "SampledCount": 10,
                "BorrowCount": 0,
            }
        ]
    )
    assert resp.get("UnprocessedStatistics", []) == [], resp
    docs = resp.get("SamplingTargetDocuments", [])
    match = next((d for d in docs if d["RuleName"] == rule["RuleName"]), None)
    assert match is not None, f"no target document for {rule['RuleName']}: {resp}"
    assert match.get("FixedRate") == fixed_rate, (
        f"SamplingTargetDocument must echo the rule's configured FixedRate {fixed_rate}, "
        f"got {match!r}"
    )
    assert "ReservoirQuota" not in match, (
        f"the first report against a freshly created rule precedes the service's first "
        f"allocation cycle for it, so no reservoir can have been granted yet -- an "
        f"implementation that answers with a quota immediately is inventing state it does "
        f"not have: {match!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
