"""delete-sampling-rule-lifecycle."""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-sampling-rule-lifecycle"
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


def _rejects(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted sampling rule disappears from GetSamplingRules, a mutation against the dead
    RuleName is rejected rather than resurrecting or silently recreating it, and the freed
    RuleName is reusable by a fresh CreateSamplingRule."""
    xr = ctx.client("xray")
    rule = _default_sampling_rule(ctx.unique_name("sim2real-behav-r-"))
    name = rule["RuleName"]
    xr.create_sampling_rule(SamplingRule=rule)
    ctx.on_cleanup(lambda: xr.delete_sampling_rule(RuleName=name))

    listed = [r["SamplingRule"]["RuleName"] for r in xr.get_sampling_rules()["SamplingRuleRecords"]]
    assert name in listed, f"created rule {name!r} missing from GetSamplingRules: {listed!r}"

    xr.delete_sampling_rule(RuleName=name)

    listed_after = [r["SamplingRule"]["RuleName"] for r in xr.get_sampling_rules()["SamplingRuleRecords"]]
    assert name not in listed_after, "rule still listed after delete"

    # Mutation on the dead id: UpdateSamplingRule against a RuleName that no longer exists must
    # be rejected, not silently resurrect or recreate the rule under that name.
    error = _rejects(lambda: xr.update_sampling_rule(SamplingRuleUpdate={"RuleName": name, "Priority": 42}))
    assert (error.get("Code"), error.get("Message")) == (
        "InvalidRequestException", "Sampling rule does not exist"
    ), f"expected InvalidRequestException 'Sampling rule does not exist' updating a deleted rule, got {error!r}"
    listed_after_update = [
        r["SamplingRule"]["RuleName"] for r in xr.get_sampling_rules()["SamplingRuleRecords"]
    ]
    assert name not in listed_after_update, "rejected UpdateSamplingRule resurrected the deleted rule"

    # The freed RuleName is reusable: a fresh CreateSamplingRule under the same name succeeds.
    recreated = xr.create_sampling_rule(SamplingRule=rule)["SamplingRuleRecord"]["SamplingRule"]
    assert recreated["RuleName"] == name, recreated
    listed_final = [r["SamplingRule"]["RuleName"] for r in xr.get_sampling_rules()["SamplingRuleRecords"]]
    assert name in listed_final, "recreated rule missing from GetSamplingRules"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
