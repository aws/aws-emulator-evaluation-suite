"""create-sampling-rule-duplicate-name-fails."""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sampling-rule-duplicate-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to raise ClientError, it succeeded: {result!r}")


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


def _rule_records(xr, name):
    records = xr.get_sampling_rules()["SamplingRuleRecords"]
    return [r["SamplingRule"] for r in records if r["SamplingRule"]["RuleName"] == name]


def _find_rule(xr, name):
    matched = _rule_records(xr, name)
    assert len(matched) == 1, f"expected {name!r} to exist exactly once, got {len(matched)}"
    return matched[0]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateSamplingRule with a used RuleName fails with InvalidRequestException
    "Sampling rule already exists" and leaves the original unchanged; a new name succeeds, and
    so does the rejected call once the name is freed."""
    xr = ctx.client("xray")
    rule = _default_sampling_rule(ctx.unique_name("sim2real-behav-r-"))
    xr.create_sampling_rule(
        SamplingRule=rule, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=rule["RuleName"]))

    created = _find_rule(xr, rule["RuleName"])
    assert created["Priority"] == rule["Priority"], created

    dup = dict(rule)
    dup["Priority"] = rule["Priority"] + 1  # only the name collides
    error = _client_error(lambda: xr.create_sampling_rule(SamplingRule=dup))
    assert (error.get("Code"), error.get("Message")) == (
        "InvalidRequestException", "Sampling rule already exists"
    ), f"expected InvalidRequestException 'Sampling rule already exists', got {error!r}"

    # The effect is absent: the original rule still exists exactly once, unchanged.
    unchanged = _find_rule(xr, rule["RuleName"])
    assert unchanged["Priority"] == rule["Priority"], unchanged

    # Positive control: CreateSamplingRule with a genuinely new name still succeeds in this run.
    control = _default_sampling_rule(ctx.unique_name("sim2real-behav-rc-"))
    xr.create_sampling_rule(
        SamplingRule=control, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=control["RuleName"]))
    found_control = _find_rule(xr, control["RuleName"])
    assert found_control["Priority"] == control["Priority"], found_control

    # Restore: free the name, then the identical call that was rejected now succeeds.
    xr.delete_sampling_rule(RuleName=rule["RuleName"])
    assert _rule_records(xr, rule["RuleName"]) == [], "expected the freed name to be gone"
    xr.create_sampling_rule(SamplingRule=dup)
    restored = _find_rule(xr, rule["RuleName"])
    assert restored["Priority"] == dup["Priority"], restored


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
