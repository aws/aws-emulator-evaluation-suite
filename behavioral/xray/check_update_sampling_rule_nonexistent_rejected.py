"""update-sampling-rule-nonexistent-rejected."""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-sampling-rule-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSamplingRule on a RuleName that was never created is rejected with
    InvalidRequestException, the phantom rule never materializes, and a real
    sampling rule updated in the same call sequence persists its change.
    """
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-upd-")[:32]
    priority = random.randint(100, 9000)

    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": priority,
            "FixedRate": 0.1,
            "ReservoirSize": 3,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        }
    )
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=rule_name))

    # Positive control half 1: a real update on the real rule succeeds.
    updated = xray.update_sampling_rule(
        SamplingRuleUpdate={"RuleName": rule_name, "Priority": priority, "FixedRate": 0.77}
    )
    fixed_rate = updated["SamplingRuleRecord"]["SamplingRule"]["FixedRate"]
    assert fixed_rate == 0.77, f"expected FixedRate=0.77 after update, got {fixed_rate!r}"

    # Break exactly one thing: update a RuleName that was never created.
    ghost_name = ctx.unique_name("sim2real-ghost-")[:32]
    code, message = _error_code(
        lambda: xray.update_sampling_rule(
            SamplingRuleUpdate={"RuleName": ghost_name, "Priority": priority, "FixedRate": 0.5}
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = "Sampling rule does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the ghost rule never came into existence.
    ghost_record = _find_rule(xray, ghost_name)
    assert ghost_record is None, f"expected no rule named {ghost_name!r}, found {ghost_record!r}"

    # Positive control half 2: the real rule's earlier update is still in effect,
    # proving the rejected call above did not disturb sibling state.
    record = _find_rule(xray, rule_name)
    assert record is not None, f"expected rule {rule_name!r} to still exist, found none"
    persisted_rate = record["SamplingRule"]["FixedRate"]
    assert persisted_rate == 0.77, f"expected sibling FixedRate to still be 0.77, got {persisted_rate!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _find_rule(xray, rule_name: str):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = xray.get_sampling_rules(**kwargs)
        for record in resp.get("SamplingRuleRecords", []):
            if record["SamplingRule"]["RuleName"] == rule_name:
                return record
        next_token = resp.get("NextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
