"""create-sampling-rule-invalid-fixed-rate-fails."""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sampling-rule-invalid-fixed-rate-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


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


def _rule_names(xr):
    return {
        r["SamplingRule"]["RuleName"]
        for r in xr.get_sampling_rules()["SamplingRuleRecords"]
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSamplingRule refuses FixedRate 1.5 with ValidationException naming the fixedRate
    range and persists no rule, while an in-range FixedRate is accepted."""
    xr = ctx.client("xray")

    good_name = ctx.unique_name("sim2real-behav-rg-")
    good_rule = xr.create_sampling_rule(
        SamplingRule=_default_sampling_rule(good_name),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["SamplingRuleRecord"]["SamplingRule"]
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=good_name))
    assert good_rule["FixedRate"] == 0.05, f"positive control rejected: {good_rule}"
    assert good_name in _rule_names(xr), "positive control rule missing from GetSamplingRules"

    bad_name = ctx.unique_name("sim2real-behav-rb-")
    bad_rule = _default_sampling_rule(bad_name, FixedRate=1.5)
    error = _client_error(lambda: xr.create_sampling_rule(SamplingRule=bad_rule))
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error}"
    assert error.get("Message") == (
        "1 validation error detected: Value '1.5' at 'samplingRule.fixedRate' failed to satisfy "
        "constraint: Member must have value less than or equal to 1"
    ), f"the rejection must name the fixedRate range constraint, got {error!r}"

    # Confirm the rejected rule was not silently persisted.
    assert bad_name not in _rule_names(xr), "invalid rule leaked into GetSamplingRules"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
