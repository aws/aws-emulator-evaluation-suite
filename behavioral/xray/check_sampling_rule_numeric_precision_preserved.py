"""sampling-rule-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "sampling-rule-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["xray"]


def _find_rule(records: list, rule_name: str) -> dict:
    for record in records:
        rule = record["SamplingRule"]
        if rule["RuleName"] == rule_name:
            return rule
    raise AssertionError(f"rule {rule_name!r} not found in GetSamplingRules")


def _list_all_sampling_rules(xray) -> list:
    records: list = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = xray.get_sampling_rules(**kwargs)
        records.extend(resp["SamplingRuleRecords"])
        token = resp.get("NextToken")
        if not token:
            break
    return records


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FixedRate 0.123456789, SamplingRateBoost MaxRate 0.654321 and CooldownWindowMinutes 7
    come back exact from CreateSamplingRule and GetSamplingRules."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-xray-rule-")
    fixed_rate = 0.123456789
    boost_max_rate = 0.654321
    cooldown_minutes = 7

    sampling_rule = {
        "RuleName": rule_name,
        "ResourceARN": "*",
        "Priority": 9876,
        "FixedRate": fixed_rate,
        "ReservoirSize": 3,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
        "SamplingRateBoost": {
            "MaxRate": boost_max_rate,
            "CooldownWindowMinutes": cooldown_minutes,
        },
    }

    created = xray.create_sampling_rule(
        SamplingRule=sampling_rule,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["SamplingRuleRecord"]["SamplingRule"]
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=rule_name))

    assert created["FixedRate"] == fixed_rate, f"CreateSamplingRule mangled FixedRate: {created['FixedRate']!r}"
    assert created["SamplingRateBoost"]["MaxRate"] == boost_max_rate, (
        f"CreateSamplingRule mangled SamplingRateBoost.MaxRate: {created['SamplingRateBoost']['MaxRate']!r}"
    )
    assert created["SamplingRateBoost"]["CooldownWindowMinutes"] == cooldown_minutes, (
        f"CreateSamplingRule mangled CooldownWindowMinutes: expected {cooldown_minutes!r}, "
        f"got {created['SamplingRateBoost']['CooldownWindowMinutes']!r}"
    )

    records = _list_all_sampling_rules(xray)
    fetched = _find_rule(records, rule_name)
    assert fetched["FixedRate"] == fixed_rate, f"GetSamplingRules mangled FixedRate: {fetched['FixedRate']!r}"
    assert fetched["SamplingRateBoost"]["MaxRate"] == boost_max_rate, (
        f"GetSamplingRules mangled SamplingRateBoost.MaxRate: {fetched['SamplingRateBoost']['MaxRate']!r}"
    )
    assert fetched["SamplingRateBoost"]["CooldownWindowMinutes"] == cooldown_minutes, (
        f"GetSamplingRules mangled CooldownWindowMinutes: expected {cooldown_minutes!r}, "
        f"got {fetched['SamplingRateBoost']['CooldownWindowMinutes']!r}"
    )
    assert fetched["ReservoirSize"] == 3, f"GetSamplingRules mangled ReservoirSize: expected 3, got {fetched['ReservoirSize']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
