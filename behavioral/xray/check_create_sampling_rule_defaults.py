"""create-sampling-rule-defaults."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "create-sampling-rule-defaults"
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


def _list_all_sampling_rules(xr):
    records = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = xr.get_sampling_rules(**kwargs)
        records.extend(resp["SamplingRuleRecords"])
        next_token = resp.get("NextToken")
        if not next_token:
            return records


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSamplingRule persists all supplied fields and mints RuleARN/CreatedAt/ModifiedAt,
    and GetSamplingRules -- an independent read, not the mutating call's own response --
    reflects the identical values."""
    xr = ctx.client("xray")
    rule = _default_sampling_rule(
        ctx.unique_name("sim2real-behav-r-"), FixedRate=0.1, ReservoirSize=3, Priority=500
    )
    resp = xr.create_sampling_rule(SamplingRule=rule)
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=rule["RuleName"]))
    record = resp["SamplingRuleRecord"]
    stored = record["SamplingRule"]
    assert stored["RuleName"] == rule["RuleName"]
    assert stored["FixedRate"] == 0.1, stored
    assert stored["ReservoirSize"] == 3, stored
    assert stored["Priority"] == 500, stored
    assert stored["RuleARN"], "RuleARN not populated"
    assert record.get("CreatedAt") is not None
    assert record.get("ModifiedAt") is not None

    all_records = _list_all_sampling_rules(xr)
    fetched_records = [r for r in all_records if r["SamplingRule"]["RuleName"] == rule["RuleName"]]
    assert len(fetched_records) == 1, (
        f"expected exactly one GetSamplingRules record for {rule['RuleName']!r}, got {fetched_records}"
    )
    fetched_record = fetched_records[0]
    fetched = fetched_record["SamplingRule"]
    assert fetched["FixedRate"] == 0.1, f"GetSamplingRules FixedRate mismatch: {fetched!r}"
    assert fetched["ReservoirSize"] == 3, f"GetSamplingRules ReservoirSize mismatch: {fetched!r}"
    assert fetched["Priority"] == 500, f"GetSamplingRules Priority mismatch: {fetched!r}"
    assert fetched["RuleARN"] == stored["RuleARN"], (
        f"GetSamplingRules RuleARN {fetched['RuleARN']!r} != CreateSamplingRule RuleARN {stored['RuleARN']!r}"
    )
    assert fetched_record.get("CreatedAt") == record.get("CreatedAt"), (
        f"GetSamplingRules CreatedAt {fetched_record.get('CreatedAt')!r} != "
        f"CreateSamplingRule CreatedAt {record.get('CreatedAt')!r}"
    )
    assert fetched_record.get("ModifiedAt") == record.get("ModifiedAt"), (
        f"GetSamplingRules ModifiedAt {fetched_record.get('ModifiedAt')!r} != "
        f"CreateSamplingRule ModifiedAt {record.get('ModifiedAt')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
